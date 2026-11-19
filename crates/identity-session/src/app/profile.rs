//! The profile step of a sign-in (TN-151): after every authentication step, a sign-in whose
//! account lacks what the environment asks of every account (a display name, a proven e-mail
//! address) completes only once the person gave it. The address is proven by a code through the
//! address challenge the e-mail change uses; this module keeps the flow's side.

use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};

use super::{
    Auth, FlowRef, Loaded, Notifier, Resume, STEP_NOT_ALLOWED, Step, audit, gone, load, refuse,
    save,
};
use crate::SessionError;
use crate::domain::flow::Purpose;
use crate::ports::{Clock, Random, SessionDb, SessionTx};
use access_identity_account::notify::message::Notice;
use access_identity_account::ports::AccountTx as _;

/// The most characters a display name holds.
pub const NAME_MAX_CHARS: usize = 200;

/// What an account still lacks (TN-151).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each thing an environment asks of every account is one flag"
)]
pub struct ProfileGap {
    /// A display name, which the environment requires.
    pub name: bool,
    /// A proven e-mail address, which the environment signs in with.
    pub email: bool,
    /// A proven phone number, which the environment signs in with (TN-156).
    pub phone: bool,
    /// A national identity number, which the environment requires (TN-158).
    pub national_id: bool,
    /// A birth date, which the environment requires (TN-158).
    pub birthdate: bool,
}

impl ProfileGap {
    /// Whether anything is missing.
    #[must_use]
    pub const fn any(self) -> bool {
        self.name || self.email || self.phone || self.national_id || self.birthdate
    }
}

/// Why the profile step's facts were refused (TN-158).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactsRefusal {
    /// Not a birth date, or a number the scheme refuses.
    Invalid,
    /// Younger than the environment's youngest age.
    TooYoung,
    /// Another account holds the number.
    Taken,
}

/// What the profile step shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileStep {
    /// The account.
    pub subject: [u8; 16],
    /// What it lacks.
    pub gap: ProfileGap,
    /// A code went to the address the step took.
    pub sent: bool,
    /// The address a provider gave without vouching for it, offered for the field.
    pub offered: Option<String>,
}

impl<D, C, R, N, P, S> Auth<'_, D, C, R, N, P, S>
where
    D: SessionDb,
    C: Clock,
    R: Random,
    N: Notifier + Sync,
    P: CredentialRegistry + Sync,
    S: SignalSink + Sync,
{
    /// What `subject` lacks under the environment's policy (TN-151).
    pub(crate) async fn profile_gap(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
    ) -> Result<ProfileGap, SessionError> {
        Ok(ProfileGap {
            name: self.policy.require_name && !tx.has_name(subject).await?,
            email: self.policy.require_email && !tx.has_email(subject).await?,
            phone: self.policy.require_phone && !tx.has_phone(subject).await?,
            national_id: self.policy.require_national_id && !tx.has_national_id(subject).await?,
            birthdate: self.policy.require_birthdate && !tx.has_birthdate(subject).await?,
        })
    }

    async fn profile_flow(
        &self,
        tx: &mut D::Tx,
        flow: &FlowRef<'_>,
        now: u64,
    ) -> Result<Result<(Loaded, [u8; 16], ProfileGap), Step>, SessionError> {
        let l = match load(tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(Err(gone(e))),
        };
        let subject = match l.state.subject {
            Some(s)
                if matches!(l.state.purpose, Purpose::Login)
                    && l.state.first_done()
                    && l.state.pending.is_none() =>
            {
                s
            }
            _ => return Ok(Err(refuse(STEP_NOT_ALLOWED))),
        };
        let gap = self.profile_gap(tx, subject).await?;
        if !gap.any() {
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        }
        Ok(Ok((l, subject, gap)))
    }

    /// The profile step of the flow, when the flow waits for it (TN-151).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn profile_step(
        &self,
        flow: &FlowRef<'_>,
    ) -> Result<Result<ProfileStep, Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let (l, subject, gap) = match self.profile_flow(&mut tx, flow, now).await? {
            Ok(x) => x,
            Err(step) => {
                tx.commit().await?;
                return Ok(Err(step));
            }
        };
        let offered = if gap.email {
            tx.provider_email(subject).await?
        } else {
            None
        };
        tx.commit().await?;
        Ok(Ok(ProfileStep {
            subject,
            gap,
            sent: l.state.address_sent,
            offered,
        }))
    }

    /// Keeps the display name the profile step took (TN-151); what the account still lacks
    /// after it.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn profile_name(
        &self,
        flow: &FlowRef<'_>,
        name: &str,
        correlation: &str,
    ) -> Result<Result<ProfileGap, Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let (_, subject, gap) = match self.profile_flow(&mut tx, flow, now).await? {
            Ok(x) => x,
            Err(step) => {
                tx.commit().await?;
                return Ok(Err(step));
            }
        };
        let name = name.trim();
        if !gap.name {
            tx.commit().await?;
            return Ok(Ok(gap));
        }
        if name.is_empty() || name.chars().count() > NAME_MAX_CHARS {
            tx.commit().await?;
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        }
        tx.set_name(subject, name).await?;
        let target = self.external(subject)?;
        audit(
            &mut tx,
            "account.profile_completed",
            &target,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Ok(ProfileGap { name: false, ..gap }))
    }

    /// Keeps the national identity number (already normalized by its scheme) and the birth date
    /// the profile step took (TN-158); what the account still lacks after them.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn profile_facts(
        &self,
        flow: &FlowRef<'_>,
        national_id: Option<(&str, &str)>,
        birthdate: Option<&str>,
        correlation: &str,
    ) -> Result<Result<Result<ProfileGap, FactsRefusal>, Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let (_, subject, mut gap) = match self.profile_flow(&mut tx, flow, now).await? {
            Ok(x) => x,
            Err(step) => {
                tx.commit().await?;
                return Ok(Err(step));
            }
        };
        if gap.birthdate {
            let Some(raw) = birthdate else {
                tx.commit().await?;
                return Ok(Ok(Err(FactsRefusal::Invalid)));
            };
            let min = u32::from(self.policy.min_age.unwrap_or(0));
            match access_identity_account::domain::birthdate::old_enough(raw, min, now) {
                None => {
                    tx.commit().await?;
                    return Ok(Ok(Err(FactsRefusal::Invalid)));
                }
                Some(false) => {
                    tx.commit().await?;
                    return Ok(Ok(Err(FactsRefusal::TooYoung)));
                }
                Some(true) => {}
            }
            tx.set_birthdate(subject, raw.trim()).await?;
            gap.birthdate = false;
        }
        if gap.national_id {
            let Some((scheme, number)) = national_id else {
                tx.commit().await?;
                return Ok(Ok(Err(FactsRefusal::Invalid)));
            };
            if !tx.keep_national_id(subject, scheme, number).await? {
                // TN-158
                if let Some(holder) = tx.national_id_holder(scheme, number).await?
                    && holder != subject
                {
                    self.account_notice(&mut tx, holder, Notice::NationalIdUsed, now)
                        .await?;
                }
                tx.commit().await?;
                return Ok(Ok(Err(FactsRefusal::Taken)));
            }
            gap.national_id = false;
        }
        let target = self.external(subject)?;
        audit(
            &mut tx,
            "account.profile_completed",
            &target,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Ok(Ok(gap)))
    }

    /// Notes that a code went to the address the profile step took, or that the step takes an
    /// address again (TN-151).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn profile_address_sent(
        &self,
        flow: &FlowRef<'_>,
        sent: bool,
    ) -> Result<Result<(), Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let (mut l, _, _) = match self.profile_flow(&mut tx, flow, now).await? {
            Ok(x) => x,
            Err(step) => {
                tx.commit().await?;
                return Ok(Err(step));
            }
        };
        l.state.address_sent = sent;
        save(&mut tx, &l, "open", Resume::Keep).await?;
        tx.commit().await?;
        Ok(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-151
    #[test]
    fn a_gap_is_anything_missing() {
        assert!(!ProfileGap::default().any());
        assert!(
            ProfileGap {
                name: true,
                ..ProfileGap::default()
            }
            .any()
        );
        assert!(
            ProfileGap {
                phone: true,
                ..ProfileGap::default()
            }
            .any()
        );
    }
}

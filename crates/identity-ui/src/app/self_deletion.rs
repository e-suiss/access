//! The person's own account deletion (OP-159 m.50, TN-145, OP-153 m.3 (bb), TN-78): the
//! environment's sign-in policy allows it (on by default), the session authenticated with two
//! factors in the last five minutes, and the browser's device Instance signs `idp.account.delete`
//! on the person's own account under their self-anchor. The deletion then waits out its
//! cancellation window; the person's sessions stay until it takes effect, so the account's owner
//! can still cancel one they did not ask for.

use access_identity_account::AccountError;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::Actor;
use access_identity_account::app::privacy::{self, DeletionSource};
use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::EnvironmentEntry;
use access_identity_session::app::sessions::SessionStatus;
use access_identity_session::domain::assurance::Aal;
use access_internal_api::idp::IdpAction;
use access_internal_api::support::SupportAuthority;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Capacity;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::json::b64url_encode;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{Id, ResourceRef, Window};
use serde_json::json;

use super::me::{governing, unavailable};
use super::signup::{STEP_UP_MAX_AGE_MS, STEP_UP_REQUIRED};
use super::support::{Signed, parse};
use super::{Browser, Hosted, Reply, signin};
use crate::domain::frontend::rfc3339;
use crate::ports::{Clock, EnvironmentKit, Kits, Messages};

/// The last segment of the person's own account resource under their self-anchor.
pub const ACCOUNT: &str = "account";

/// How long a drafted deletion may be signed.
const DRAFT_MS: u64 = 10 * 60_000;

/// OP-159 m.50: the environment does not let people delete their own account.
pub const CLOSED: Problem = Problem {
    status: 403,
    code: "self-deletion-closed",
    title: "This app doesn't let you delete your account here",
    retry_after_s: None,
};

/// The signed Exercise is not the drafted deletion of the person's own account.
pub const INVALID: Problem = Problem {
    status: 400,
    code: "invalid-request",
    title: "The request is not valid",
    retry_after_s: None,
};

/// Access recorded no deletion: the device's signature or standing did not hold.
pub const NOT_RECORDED: Problem = Problem {
    status: 403,
    code: "self-deletion-not-recorded",
    title: "Access recorded no deletion",
    retry_after_s: None,
};

/// The device has no Party here yet.
pub const NO_PARTY: Problem = Problem {
    status: 409,
    code: "self-deletion-party",
    title: "Add this device first",
    retry_after_s: None,
};

/// The person's own account as a resource under their self-anchor (§7.9.2.3).
#[must_use]
pub fn account_resource(party: &[u8; 16]) -> ResourceRef {
    ResourceRef {
        namespace: String::from(access_identity_account::app::support::RESOURCES),
        path: vec![
            access_identity_account::app::support::hex(party),
            String::from(ACCOUNT),
        ],
        incarnation: 0,
    }
}

/// The intent of the person's own `idp.account.delete` (OP-159 m.50).
#[must_use]
pub fn deletion_intent(party: &[u8; 16], validity: Window) -> IntentEnvelope {
    IntentEnvelope {
        provenance: std::collections::BTreeMap::new(),
        action: IdpAction::AccountDelete.action_ref(),
        resources: vec![account_resource(party)],
        params: std::collections::BTreeMap::new(),
        opaque: std::collections::BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity,
    }
}

/// Whether `intent` is exactly the person's own deletion: the action, their account and nothing
/// else; only its validity is the device's.
#[must_use]
pub fn is_own_deletion(intent: &IntentEnvelope, party: &[u8; 16]) -> bool {
    *intent == deletion_intent(party, intent.validity)
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// The session's subject when it authenticated with two factors in the last five minutes
    /// (OP-159 m.50); `step-up-required` otherwise.
    async fn strong_fresh(&self, kit: &EnvironmentKit, b: &Browser<'_>) -> Result<[u8; 16], Reply> {
        let (subject, _) = self.fresh(kit, b, Some(STEP_UP_MAX_AGE_MS)).await?;
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Err(Reply::problem(STEP_UP_REQUIRED));
        };
        match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) if v.assurance.aal >= Aal::Aal2 => Ok(subject),
            Ok(_) => Err(Reply::problem(STEP_UP_REQUIRED)),
            Err(_) => Err(unavailable()),
        }
    }

    async fn deletion_kit(
        &self,
        entry: &EnvironmentEntry,
    ) -> Result<std::sync::Arc<EnvironmentKit>, Reply> {
        let kit = self.kit(entry).await?;
        if kit.signin.self_deletion {
            Ok(kit)
        } else {
            Err(Reply::problem(CLOSED))
        }
    }

    /// `GET /v1/account/deletion/draft`: the deletion the person's device signs: its intent and
    /// self-anchor basis, the PEP and the date it would take effect.
    pub async fn deletion_draft<A: SupportAuthority>(
        &self,
        authority: &A,
        pep: &str,
        entry: &EnvironmentEntry,
        b: &Browser<'_>,
    ) -> Reply {
        let kit = match self.deletion_kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let Ok(party) = self.party(&kit, subject).await else {
            return Reply::problem(NO_PARTY);
        };
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let Ok(facts) = authority.facts(domain, Id(party), Id(party)).await else {
            return unavailable();
        };
        let Some(anchor) = facts.anchor else {
            return Reply::problem(NO_PARTY);
        };
        let now = self.clock.now_ms();
        let intent = deletion_intent(
            &party,
            Window {
                from: now.saturating_sub(60_000),
                until: now.saturating_add(DRAFT_MS),
            },
        );
        let Ok(bytes) = intent.to_bytes() else {
            return unavailable();
        };
        let window = privacy::cancellation_window_s(facts.ct3_delay_s);
        let effective = now.saturating_add(window.saturating_mul(1_000));
        Reply::json(
            200,
            json!({
                "intent": b64url_encode(&bytes),
                "basis": { "anchor": b64url_encode(&anchor.0) },
                "pep": pep,
                "deleted_on": rfc3339(effective),
            }),
        )
    }

    /// `POST /v1/account/deletion`: the person's signed `idp.account.delete` on their own
    /// account (OP-159 m.50); Access commits it as PEP and schedules the deletion with the
    /// person as its source. An open deletion is answered as it stands.
    pub async fn request_self_deletion<A: SupportAuthority>(
        &self,
        authority: &A,
        pep: &str,
        entry: &EnvironmentEntry,
        b: &Browser<'_>,
        body: &Signed,
    ) -> Reply {
        let kit = match self.deletion_kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.strong_fresh(&kit, b).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let Ok(party) = self.party(&kit, subject).await else {
            return Reply::problem(NO_PARTY);
        };
        let Some(parsed) = parse(body) else {
            return Reply::problem(INVALID);
        };
        if parsed.payload.is_some() || !is_own_deletion(&parsed.intent, &party) {
            return Reply::problem(INVALID);
        }
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let Ok(facts) = authority.facts(domain, Id(party), Id(party)).await else {
            return unavailable();
        };
        if facts
            .anchor
            .is_none_or(|a| parsed.basis != ExerciseBasis::Anchor(a))
        {
            return Reply::problem(INVALID);
        }
        let Ok(committed) =
            Self::commit_signed(authority, pep, (domain, party, Capacity::Own), parsed).await
        else {
            return Reply::problem(NOT_RECORDED);
        };
        let environment = kit.environment();
        let Ok(actor) = environment.external(subject) else {
            return unavailable();
        };
        let who = Actor {
            actor: &actor,
            correlation: b.correlation,
        };
        let db: PgAccounts = self.db(&kit);
        let scheduled = async {
            let mut tx =
                access_identity_account::ports::AccountDb::begin(&db, kit.tenant, kit.environment)
                    .await?;
            let s = privacy::request_deletion(
                &mut tx,
                &environment,
                subject,
                DeletionSource::SelfService,
                Some(&committed.exercise.0),
                facts.ct3_delay_s,
                &who,
            )
            .await?;
            access_identity_account::ports::AccountTx::commit(tx).await?;
            Ok::<_, AccountError>(s)
        };
        match scheduled.await {
            Ok(s) => Reply::json(
                201,
                json!({
                    "scheduled": true,
                    "deleted_on": rfc3339(u64::try_from(s.effective_ms).unwrap_or(0)),
                    "cancellable": true,
                    "statement": s.statement(),
                    "exercise": b64url_encode(&committed.exercise.0),
                }),
            ),
            Err(AccountError::NotFound) => Reply::problem(INVALID),
            Err(_) => unavailable(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-159 m.50, TN-145
    #[test]
    fn only_the_persons_own_drafted_deletion_is_their_deletion() {
        let me = [1; 16];
        let window = Window {
            from: 1_000,
            until: 2_000,
        };
        let mine = deletion_intent(&me, window);
        assert!(is_own_deletion(&mine, &me));
        assert!(is_own_deletion(
            &deletion_intent(&me, Window { from: 5, until: 9 }),
            &me
        ));
        assert!(!is_own_deletion(&mine, &[2; 16]));
        let mut other = mine.clone();
        other.action = IdpAction::AccountSuspend.action_ref();
        assert!(!is_own_deletion(&other, &me));
        let mut more = mine.clone();
        more.resources.push(account_resource(&[2; 16]));
        assert!(!is_own_deletion(&more, &me));
        let mut elsewhere = mine;
        elsewhere.resources[0].path[1] = String::from("artifacts");
        assert!(!is_own_deletion(&elsewhere, &me));
    }
}

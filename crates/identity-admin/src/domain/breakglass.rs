//! `idp.org.member_breakglass{,_clear}` (catalog 7, OP-157 m.3 (a), (h)): marking an
//! organization member's account as a break-glass account. The mark carries no authority, no
//! exemption from recording, audit or requirements (INV-28, SI-22); it narrows how the account
//! signs in and makes every sign-in alarm.

use access_internal_api::idp::IdpAction;
use access_kernel::json::b64url_decode;
use serde_json::Value as Json;
use suiss_crypto::dcbor::Value;

use super::Invalid;

/// A break-glass mark on one member of one organization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BreakglassMark {
    /// The organization's Party.
    pub org: [u8; 16],
    /// The member's account.
    pub member: [u8; 16],
    /// Marked (`idp.org.member_breakglass`, CT2) or cleared (`member_breakglass_clear`, CT1).
    pub on: bool,
}

fn id(v: Option<&Json>) -> Result<[u8; 16], Invalid> {
    v.and_then(Json::as_str)
        .and_then(|s| b64url_decode(s).ok())
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .ok_or(Invalid::Body)
}

impl BreakglassMark {
    /// `markBreakglassAccount` (`{"organization", "member"}`, `on`) or
    /// `clearBreakglassAccount` (`{"organization"}` with the member as key).
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn parse(member: Option<&str>, body: &Json, on: bool) -> Result<Self, Invalid> {
        let m = body.as_object().ok_or(Invalid::Body)?;
        let allowed: &[&str] = if member.is_some() {
            &["organization"]
        } else {
            &["organization", "member"]
        };
        if !m.keys().all(|k| allowed.contains(&k.as_str())) {
            return Err(Invalid::Body);
        }
        let member = match member {
            Some(k) => id(Some(&Json::from(k)))?,
            None => id(m.get("member"))?,
        };
        Ok(Self {
            org: id(m.get("organization"))?,
            member,
            on,
        })
    }

    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        if self.on {
            IdpAction::OrgMemberBreakglass
        } else {
            IdpAction::OrgMemberBreakglassClear
        }
    }

    /// The change's body, which the intent binds (EI-25).
    #[must_use]
    pub fn body(&self) -> Value {
        Value::Map(vec![
            (Value::text("org"), Value::Bytes(self.org.to_vec())),
            (Value::text("member"), Value::Bytes(self.member.to_vec())),
            (Value::text("breakglass"), Value::Bool(self.on)),
        ])
    }
}

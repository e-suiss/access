//! The browser session as the SAML identity provider and WS-Federation see it (OP-155 m.3 (c),
//! IDI-7): access-server keeps the cookies and attests a live session to the SAML gateway; a
//! signed Response is only ever made from such a session. Single logout signs the user out
//! locally with one `session_epoch` step, which always succeeds (§10.6.1 SLO, MD-7).

use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::sessions::{SessionStatus, SessionView};
use access_identity_session::domain::session::{SESSION_COOKIE, clear_cookie};
use access_identity_session::ports::Clock;

use super::{Browser, Hosted, Reply, failed, signin};
use crate::ports::{Kits, Messages};

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// The live session of this browser, if any (G57: a session that is not live vouches for
    /// nothing).
    ///
    /// # Errors
    /// A reply for an unavailable realm or store.
    pub async fn saml_session(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
    ) -> Result<Option<SessionView>, Reply> {
        let kit = self.kit(entry).await?;
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Ok(None);
        };
        match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) => Ok(Some(*v)),
            Ok(_) => Ok(None),
            Err(e) => Err(failed(&e)),
        }
    }

    /// Single logout's local sign-out: one `session_epoch` step ends every session of the
    /// user; the session cookie is cleared either way. Returns the clearing cookie.
    pub async fn saml_sign_out(&self, entry: &RealmEntry, b: &Browser<'_>) -> String {
        let clear = clear_cookie(SESSION_COOKIE);
        let Ok(kit) = self.kit(entry).await else {
            return clear;
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return clear;
        };
        if let Ok(SessionStatus::Valid(me)) = auth.check_session(cookie).await
            && let Ok(actor) = kit.realm().external(me.subject)
        {
            let _ = auth
                .sign_out_everywhere(me.subject, &actor, b.correlation)
                .await;
        }
        clear
    }
}

//! Each client's high-assurance and legacy settings (OP-155 m.3 (k), IDP-12, IDP-24, MD-6,
//! CR-4): one version per `idp.client.*` decision, the newest is the profile; and the realm's
//! front-channel logout opt-in. Nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

/// A `client_secret_jwt` secret sealed under the realm KEK (OP-148 m.16 (l)).
#[derive(Clone, PartialEq, Eq)]
pub struct SealedJwtSecret {
    /// The KEK version that wrapped the data key.
    pub kek_id: String,
    /// The wrapped data key.
    pub wrapped: Vec<u8>,
    /// The AES-GCM nonce.
    pub nonce: Vec<u8>,
    /// The ciphertext with its tag.
    pub ciphertext: Vec<u8>,
}

impl core::fmt::Debug for SealedJwtSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedJwtSecret")
            .field("kek_id", &self.kek_id)
            .finish_non_exhaustive()
    }
}

/// One version of a client's profile.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one decision about the client"
)]
pub struct ClientProfileRow {
    /// Under FAPI 2.0 (`idp.client.profile`).
    pub fapi2: bool,
    /// `client_secret_post` or `client_secret_jwt` (`idp.client.auth_method_legacy`).
    pub legacy_auth: Option<String>,
    /// The sealed `client_secret_jwt` secret.
    pub jwt_secret: Option<SealedJwtSecret>,
    /// `tls_client_auth` or `self_signed_tls_client_auth` (RFC 8705 §2).
    pub tls_auth: Option<String>,
    /// For `tls_client_auth`: which certificate name, and its value.
    pub tls_name: Option<(String, String)>,
    /// For `self_signed_tls_client_auth`: the registered JWKS with `x5c`.
    pub tls_jwks: Option<String>,
    /// RS256 identity assertions opted in (`idp.client.alg_rs256`).
    pub rs256: bool,
    /// `id_token_signed_response_alg`; the realm's algorithm when absent.
    pub id_token_alg: Option<String>,
    /// The JWE key management algorithm.
    pub enc_alg: Option<String>,
    /// The client's encryption JWKS.
    pub enc_jwks: Option<String>,
    /// Encrypt ID tokens.
    pub enc_id_token: bool,
    /// Encrypt userinfo answers.
    pub enc_userinfo: bool,
    /// Encrypt JARM responses.
    pub enc_jarm: bool,
    /// Answer userinfo as a JWT signed by the realm key.
    pub userinfo_signed: bool,
    /// The accepted SAML upstream whose assertions the bearer grant takes.
    pub saml_bearer_upstream: Option<String>,
    /// The legacy bearer exception (`idp.client.legacy_bearer`).
    pub legacy_bearer: bool,
    /// The front-channel logout URI (OIDC Front-Channel Logout §2).
    pub frontchannel_logout_uri: Option<String>,
}

/// Writes the next version of the profile of client `client` under `bound`. Returns the
/// version written.
///
/// # Errors
/// [`StoreError`]; a profile the schema refuses (FAPI 2.0 with a legacy method, RS256 without
/// the opt-in) fails.
pub async fn put_profile(
    t: &mut TenantTx,
    bound: &Bound,
    client: [u8; 16],
    p: &ClientProfileRow,
) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let jwt = p.jwt_secret.as_ref();
    let version = sqlx::query_scalar!(
        r#"INSERT INTO access.oauth_client_profiles (tenant_id, realm_id, client_uuid, version,
                fapi2, legacy_auth, jwt_kek_id, jwt_wrapped, jwt_nonce, jwt_sealed, tls_auth,
                tls_name_kind, tls_name, tls_jwks, rs256, id_token_alg, enc_alg, enc_jwks,
                enc_id_token, enc_userinfo, enc_jarm, userinfo_signed, saml_bearer_upstream,
                legacy_bearer, frontchannel_logout_uri, domain_id, decision_pos)
         SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26
           FROM access.oauth_client_profiles
          WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3
         RETURNING version AS "version!""#,
        tenant,
        realm,
        Uuid::from_bytes(client),
        p.fapi2,
        p.legacy_auth,
        jwt.map(|s| s.kek_id.as_str()),
        jwt.map(|s| s.wrapped.as_slice()),
        jwt.map(|s| s.nonce.as_slice()),
        jwt.map(|s| s.ciphertext.as_slice()),
        p.tls_auth,
        p.tls_name.as_ref().map(|(k, _)| k.as_str()),
        p.tls_name.as_ref().map(|(_, v)| v.as_str()),
        p.tls_jwks,
        p.rs256,
        p.id_token_alg,
        p.enc_alg,
        p.enc_jwks,
        p.enc_id_token,
        p.enc_userinfo,
        p.enc_jarm,
        p.userinfo_signed,
        p.saml_bearer_upstream,
        p.legacy_bearer,
        p.frontchannel_logout_uri,
        bound.domain().as_bytes().as_slice(),
        bound.raw_position(),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    u64::try_from(version).map_err(|_| StoreError::Corrupt)
}

/// The newest profile of client `client`; `None` when no decision ever set one.
///
/// # Errors
/// [`StoreError`].
pub async fn profile(
    t: &mut TenantTx,
    client: [u8; 16],
) -> Result<Option<ClientProfileRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT fapi2, legacy_auth, jwt_kek_id, jwt_wrapped, jwt_nonce, jwt_sealed, tls_auth,
                tls_name_kind, tls_name, tls_jwks, rs256, id_token_alg, enc_alg, enc_jwks,
                enc_id_token, enc_userinfo, enc_jarm, userinfo_signed, saml_bearer_upstream,
                legacy_bearer, frontchannel_logout_uri
           FROM access.oauth_client_profiles
          WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3
          ORDER BY version DESC LIMIT 1",
        tenant,
        realm,
        Uuid::from_bytes(client),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    let Some(r) = row else {
        return Ok(None);
    };
    let jwt_secret = match (r.jwt_kek_id, r.jwt_wrapped, r.jwt_nonce, r.jwt_sealed) {
        (Some(kek_id), Some(wrapped), Some(nonce), Some(ciphertext)) => Some(SealedJwtSecret {
            kek_id,
            wrapped,
            nonce,
            ciphertext,
        }),
        (None, None, None, None) => None,
        _ => return Err(StoreError::Corrupt),
    };
    let tls_name = match (r.tls_name_kind, r.tls_name) {
        (Some(k), Some(v)) => Some((k, v)),
        (None, None) => None,
        _ => return Err(StoreError::Corrupt),
    };
    Ok(Some(ClientProfileRow {
        fapi2: r.fapi2,
        legacy_auth: r.legacy_auth,
        jwt_secret,
        tls_auth: r.tls_auth,
        tls_name,
        tls_jwks: r.tls_jwks,
        rs256: r.rs256,
        id_token_alg: r.id_token_alg,
        enc_alg: r.enc_alg,
        enc_jwks: r.enc_jwks,
        enc_id_token: r.enc_id_token,
        enc_userinfo: r.enc_userinfo,
        enc_jarm: r.enc_jarm,
        userinfo_signed: r.userinfo_signed,
        saml_bearer_upstream: r.saml_bearer_upstream,
        legacy_bearer: r.legacy_bearer,
        frontchannel_logout_uri: r.frontchannel_logout_uri,
    }))
}

/// Records that the realm lets its clients opt in to front-channel logout (IDP-24); a second
/// opt-in changes nothing. Returns whether this call recorded it.
///
/// # Errors
/// [`StoreError`].
pub async fn enable_frontchannel(t: &mut TenantTx, bound: &Bound) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "INSERT INTO access.oauth_realm_frontchannel (tenant_id, realm_id, domain_id, decision_pos)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, realm_id) DO NOTHING",
        tenant,
        realm,
        bound.domain().as_bytes().as_slice(),
        bound.raw_position(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Whether the realm lets its clients opt in to front-channel logout (IDP-24).
///
/// # Errors
/// [`StoreError`].
pub async fn frontchannel_enabled(t: &mut TenantTx) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM access.oauth_realm_frontchannel
                           WHERE tenant_id = $1 AND realm_id = $2) AS "on!""#,
        tenant,
        realm,
    )
    .fetch_one(&mut *t.tx)
    .await?)
}

/// Whether any active client of the realm opted in to a legacy token endpoint method, so the
/// metadata names it (OP-155 m.3 (k)).
///
/// # Errors
/// [`StoreError`].
pub async fn legacy_methods(t: &mut TenantTx) -> Result<Vec<String>, StoreError> {
    let (tenant, realm) = scope(t)?;
    Ok(sqlx::query_scalar!(
        r#"SELECT DISTINCT p.legacy_auth AS "m!"
             FROM access.oauth_client_profiles p
             JOIN access.idp_clients c
               ON c.tenant_id = p.tenant_id AND c.realm_id = p.realm_id
              AND c.client_uuid = p.client_uuid AND c.status = 'active'
            WHERE p.tenant_id = $1 AND p.realm_id = $2 AND p.legacy_auth IS NOT NULL
              AND p.version = (SELECT MAX(n.version) FROM access.oauth_client_profiles n
                                WHERE n.tenant_id = p.tenant_id AND n.realm_id = p.realm_id
                                  AND n.client_uuid = p.client_uuid)
            ORDER BY 1"#,
        tenant,
        realm,
    )
    .fetch_all(&mut *t.tx)
    .await?)
}

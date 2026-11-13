//! A client's high-assurance and legacy profile as the endpoints read it (OP-155 m.3 (k),
//! IDP-12): loaded with the client, checked against its registration, and held against each
//! request; and the identity JWTs made for it, signed with its algorithm and encrypted when it
//! asked (CR-2, CR-4, MD-3).

use super::{Env, OAuth, Realm};
use crate::domain::client::{Client, ClientAuth};
use crate::domain::fapi::{ClientProfile, IdAlg, TlsAuth, check};
use crate::domain::jwe::{NESTED_CTY, encryption_key};
use crate::domain::jwt::parse_jwks;
use crate::domain::request::Params;
use crate::domain::request::jar::{self, JarError, JarRules};
use crate::ports::Unavailable;
use crate::ports::oauth::ClientKeys;
use crate::ports::oauth::{OAuthDb, OAuthTx, TokenSigner};

impl<E: Env> OAuth<E> {
    /// The client with its newest profile; `None` when the stored profile does not fit the
    /// model or the client's registration (fail closed: the client is not used).
    pub(crate) async fn profiled(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        mut client: Client,
    ) -> Result<Option<Client>, Unavailable> {
        let Some(row) = tx.client_profile(client.uuid).await? else {
            return Ok(Some(client));
        };
        let Some(profile) = ClientProfile::from_row(row) else {
            tracing::warn!("client profile does not fit the model");
            return Ok(None);
        };
        if let Err(r) = check(&client.auth, &profile) {
            tracing::warn!(reason = r.code(), "client profile refused");
            return Ok(None);
        }
        client.profile = profile;
        Ok(Some(client))
    }

    /// RFC 9101, IDI-6, OP-155 m.3 (k): the authorization request a pushed request object
    /// `object` carries. An encrypted one opens with the realm's `jwe-enc` key first; the
    /// signature verifies against the client's keys with an algorithm from its allowlist.
    pub(crate) async fn request_object(
        &self,
        realm: &Realm,
        client: &Client,
        outer: &Params,
        object: &str,
        now: u64,
    ) -> Result<Result<Params, JarError>, Unavailable> {
        if !jar::outer_ok(outer) {
            return Ok(Err(JarError::Claims));
        }
        let opened;
        let signed = if object.split('.').count() == 5 {
            let Some(plain) = self.env.request_keys().decrypt(realm.realm, object).await? else {
                return Ok(Err(JarError::Encryption));
            };
            let Ok(text) = String::from_utf8(plain) else {
                return Ok(Err(JarError::Encryption));
            };
            opened = text;
            opened.as_str()
        } else {
            object
        };
        let doc = match (&client.auth, &client.profile.tls) {
            (ClientAuth::PrivateKeyJwt { jwks_uri }, _) => {
                self.env.client_keys().fetch(jwks_uri).await?
            }
            (ClientAuth::PrivateKeyJwtKey { jwks }, _)
            | (_, Some(TlsAuth::SelfSigned { jwks })) => jwks.clone().into_bytes(),
            _ => return Ok(Err(JarError::Signature)),
        };
        let Ok(keys) = parse_jwks(&doc) else {
            return Ok(Err(JarError::Signature));
        };
        let rules = JarRules {
            client_id: &client.id,
            issuer: realm.issuer.as_str(),
            now_ms: now,
            rs256: client.rs256 && !client.profile.fapi2,
        };
        Ok(jar::verify(signed, &keys, &rules))
    }

    /// A JWS of `typ` over `claims` with `alg`, absent the realm's algorithm: the realm's own,
    /// or ML-DSA with the realm's post-quantum key set while its signing profile holds that
    /// parameter set and the token fits the header budget. Anything else refuses the token and
    /// nothing is signed in its place (CR-41, CR-43, MD-8, OP-159 m.3 (o), (p), m.21 (b)).
    pub(crate) async fn sign_as(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        alg: Option<IdAlg>,
        typ: &str,
        claims: &[u8],
        now: u64,
    ) -> Result<String, Unavailable> {
        let realm_alg = tx.jose_alg().await?;
        let signer = self.env.signer();
        match alg {
            None => signer.sign(realm.realm, realm_alg, typ, claims, now).await,
            Some(a) if a.name() == realm_alg.name() => {
                signer.sign(realm.realm, realm_alg, typ, claims, now).await
            }
            // CR-41, OP-159 m.3 (o)
            Some(a) if a.ml_dsa().is_some() => {
                let profile = tx.signing_profile().await?;
                match a.ml_dsa() {
                    Some(pq) if profile == Some(pq) => {
                        let token = signer.sign_pq(realm.realm, pq, typ, claims, now).await?;
                        // CR-43, OP-159 m.3 (p)
                        if access_crypto::budget::Carrier::Header
                            .check(token.len())
                            .is_err()
                        {
                            tracing::warn!("post-quantum token over the header budget");
                            return Err(Unavailable);
                        }
                        Ok(token)
                    }
                    _ => {
                        tracing::warn!("ML-DSA algorithm is not the realm's profile");
                        Err(Unavailable)
                    }
                }
            }
            Some(_) => {
                tracing::warn!("signing algorithm is not served by the realm");
                Err(Unavailable)
            }
        }
    }

    /// An identity JWT of `typ` over `claims` for `client`: signed with its
    /// `id_token_signed_response_alg` (the realm's algorithm, or RS256 with the realm's
    /// `rsa-id` key after its opt-in), then, when `encrypt`, a nested JWE to its encryption key.
    /// A setting the realm cannot serve refuses the token (MD-8).
    #[expect(clippy::too_many_arguments, reason = "the facts of one identity JWT")]
    pub(crate) async fn client_jwt(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        typ: &str,
        claims: &[u8],
        encrypt: bool,
        now: u64,
    ) -> Result<String, Unavailable> {
        let jws = match client.profile.id_alg {
            // CR-2, MD-3, MD-6
            Some(IdAlg::Rs256) if client.profile.rs256 && !client.profile.fapi2 => {
                self.env
                    .signer()
                    .sign_rs256(realm.realm, typ, claims, now)
                    .await?
            }
            alg => self.sign_as(tx, realm, alg, typ, claims, now).await?,
        };
        if !encrypt {
            return Ok(jws);
        }
        // CR-4
        let Some(enc) = &client.profile.encryption else {
            return Err(Unavailable);
        };
        let Some((key, kid)) = encryption_key(enc.jwks.as_bytes(), enc.alg) else {
            tracing::warn!("client encryption key unusable");
            return Err(Unavailable);
        };
        access_crypto::jwe::encrypt(&key, kid.as_deref(), Some(NESTED_CTY), jws.as_bytes()).map_err(
            |e| {
                tracing::warn!(reason = e.code(), "client encryption failed");
                Unavailable
            },
        )
    }
}

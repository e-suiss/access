//! The verifier's pure core (OP-63): DCQL, the credential formats, issuer trust, status, DID
//! resolution, the response encryption, the request object and the Claims. No I/O, clock or
//! randomness: the use cases in [`crate::app`] bring those through ports.

pub mod b64;
pub mod cbor;
pub mod claims;
pub mod dcql;
pub mod did;
pub mod jwe;
pub mod mdoc;
pub mod presentation;
pub mod request;
pub mod sd_jwt_vc;
pub mod status;
pub mod time;
pub mod trust;
pub mod w3c;
pub mod x509;

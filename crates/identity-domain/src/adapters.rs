//! Adapters of the custom domain ports: HTTPS to the ACME directory's origin, and certificate
//! keys sealed under the realm KEK (OP-156 m.3 (i), CR-32).

pub mod https;
pub mod seal;

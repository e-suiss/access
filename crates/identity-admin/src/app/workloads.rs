//! The Acceptances a realm's governing domain is born with for workloads and attestation
//! (OP-154 m.3 (d), (r), (s), AG-30, AG-31, U20), and the trust domain Acceptance its root
//! establishes.
//!
//! - The realm issuer's `identity_binding_workload` Claim is accepted for actor binding: it is
//!   what a workload's self-signed `instance_create` stands on (the platform issuer of m.3 (d)).
//! - Its `attestation_runtime` Claim is accepted as predicate input: a runtime attestation
//!   requirement is met by it, bound to the attested Instance (§5.9).
//! - A SPIFFE or WIMSE trust domain is accepted only by the domain root's own actor-binding
//!   Acceptance of the trust domain's issuer id; it is never an `AuthorityDomain`.
//!
//! A workload client's registration (its SPIFFE ID selector, Bundle Endpoint and agent) is
//! written with its `idp.client.register` or `idp.client.update`.

use access_identity_attest::domain::workload::{Scheme, trust_domain_issuer};
use access_kernel::claim::body::{BindingKind, Class};
use access_kernel::codec::Canonical as _;
use access_kernel::model::{Id, SubjectSelector};
use suiss_crypto::dcbor::Value;

fn acceptance(issuer: Id, use_: &str, class: Class) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (Value::text("use"), Value::text(use_)),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text(&class.name())]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

/// OP-154 m.3 (d): the realm issuer's `identity_binding_workload` Claim for actor binding.
#[must_use]
pub fn workload_binding(issuer: Id) -> Value {
    acceptance(
        issuer,
        access_kernel::claim::ACTOR_BINDING,
        Class::IdentityBinding(BindingKind::Workload),
    )
}

/// OP-154 m.3 (s), §5.9: the realm issuer's `attestation_runtime` Claim as predicate input.
#[must_use]
pub fn runtime_attestation(issuer: Id) -> Value {
    acceptance(
        issuer,
        access_kernel::claim::PREDICATE_INPUT,
        Class::AttestationRuntime,
    )
}

/// OP-154 m.3 (r): the domain root's actor-binding Acceptance of a trust domain, the content
/// of its `acceptance_establish`.
#[must_use]
pub fn trust_domain(scheme: Scheme, trust_domain: &str) -> Value {
    acceptance(
        Id(trust_domain_issuer(scheme, trust_domain)),
        access_kernel::claim::ACTOR_BINDING,
        Class::IdentityBinding(BindingKind::Workload),
    )
}

/// OP-154 m.3 (d), (r): writes a workload client's registration under `bound`; its agent must be
/// a live agent of the realm.
///
/// # Errors
/// [`AdminError`]; [`Invalid::NoAgent`] for an agent the realm does not have or retired.
pub(crate) async fn register(
    t: &mut access_store::identity::TenantTx,
    bound: &access_store::idp::Bound,
    client_uuid: [u8; 16],
    w: &crate::domain::SpiffeAuth,
) -> Result<(), crate::AdminError> {
    if t.agent(w.agent)
        .await?
        .is_none_or(|a| a.status == super::agents::RETIRED)
    {
        return Err(crate::domain::Invalid::NoAgent.into());
    }
    access_store::workloads::put_client_workload(
        t,
        bound,
        &access_store::workloads::ClientWorkload {
            client_uuid,
            spiffe_id: w.spiffe_id.clone(),
            bundle_endpoint: w.bundle_endpoint.clone(),
            agent: w.agent,
        },
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use access_kernel::claim::Gate;

    use super::*;

    // OP-154 m.3 (d), (r), (s), L0-META-5
    #[test]
    fn the_workload_acceptances_are_acceptance_contents() {
        let issuer = Id([7; 16]);
        let w = Gate::of(&workload_binding(issuer)).unwrap();
        assert_eq!(w.use_, access_kernel::claim::ACTOR_BINDING);
        assert_eq!(w.classes, vec![String::from("identity_binding_workload")]);
        let r = Gate::of(&runtime_attestation(issuer)).unwrap();
        assert_eq!(r.use_, access_kernel::claim::PREDICATE_INPUT);
        assert_eq!(r.classes, vec![String::from("attestation_runtime")]);
        let td = Gate::of(&trust_domain(Scheme::Spiffe, "acme.example")).unwrap();
        assert_eq!(
            td.issuer,
            Some(Id(trust_domain_issuer(Scheme::Spiffe, "acme.example")))
        );
    }
}

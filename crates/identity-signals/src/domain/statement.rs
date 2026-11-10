//! How a posture statement reads on the console and the approval surface (§8.10, §8.17.8.2):
//! Access shows whose statement it is and never states compliance in its own name.

use access_internal_api::signals::PostureMdm;

/// "Compliant per *provider* (statement)", "Not compliant per …" or "Not managed by …";
/// `provider` is the source's display name.
#[must_use]
pub fn posture_line(p: &PostureMdm, provider: &str) -> String {
    let verdict = match (p.managed, p.compliant) {
        (false, _) => format!("Not managed by {provider}"),
        (true, true) => format!("Compliant per {provider}"),
        (true, false) => format!("Not compliant per {provider}"),
    };
    format!("{verdict} ({})", p.statement)
}

#[cfg(test)]
mod tests {
    use super::*;

    // §8.10, §8.17.8.2
    #[test]
    fn a_posture_is_the_providers_statement() {
        let p = |managed, compliant| PostureMdm {
            managed,
            compliant,
            provider: String::from("acme-mdm"),
            statement: String::from("Disk encrypted, OS current"),
        };
        assert_eq!(
            posture_line(&p(true, true), "Acme MDM"),
            "Compliant per Acme MDM (Disk encrypted, OS current)"
        );
        assert!(
            posture_line(&p(true, false), "Acme MDM").starts_with("Not compliant per Acme MDM")
        );
        assert!(posture_line(&p(false, true), "Acme MDM").starts_with("Not managed by Acme MDM"));
    }
}

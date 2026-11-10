# Compatibility

Which systems Access is tested against, at which version, and how. CI runs every row nightly and on every release tag; a failing row fails the run.

This file is generated from [`lab.toml`](lab.toml) by `cargo xtask interop-table`; do not edit it by hand. An oracle is a reference whose answer the differential tests compare against; every other row is a counterpart Access must work with.

## OpenID Connect and OAuth

| System | Role | Version tested | How | Profile | Oracle | Tests | CI job |
|---|---|---|---|---|---|---|---|
| OpenID Foundation conformance suite | certification suite | release-v5.3.3 | container `registry.gitlab.com/openid/conformance-suite` (`sha256:377ab51f011d`) | none | yes | 9 | `oidf-conformance` |
| oidc-provider | reference authorization server | 9.13.3 on Node.js 24.22.0 | container `node` (`sha256:a61553844466`) | none | yes | 7 | `differential` |
| openid-client | relying party library | 6.8.8 on Node.js 24.22.0 | container `node` (`sha256:a61553844466`) | none | no | 1 | `differential` |

## SAML 2.0

| System | Role | Version tested | How | Profile | Oracle | Tests | CI job |
|---|---|---|---|---|---|---|---|
| xmlsec1 | XML signature verifier | Debian 13.2 package | container `debian` (`sha256:4bcb9db66237`) | none | yes | 1 | `differential` |
| SimpleSAMLphp | service provider | simplesamlphp/saml2-legacy 4.20.3, the SAML library of SimpleSAMLphp 2.5 | container `composer` (`sha256:5248900ab8b5`) | none | no | 1 | `differential` |
| Shibboleth SP | service provider | 3, Debian 13.2 package behind Apache | container `debian` (`sha256:4bcb9db66237`) | none | no | 1 | `differential` |
| Salesforce | service provider | request shape of the vendor's SAML guide | recorded or documented requests | `saml.salesforce` | no | 3 | `interop-lab` |
| ServiceNow | service provider | request shape of the vendor's SAML guide | recorded or documented requests | `saml.servicenow` | no | 3 | `interop-lab` |
| Workday | service provider | request shape of the vendor's SAML guide | recorded or documented requests | `saml.workday` | no | 3 | `interop-lab` |
| AWS IAM Identity Center | service provider | request shape of the vendor's SAML guide | recorded or documented requests | `saml.aws_identity_center` | no | 3 | `interop-lab` |
| Google Workspace | service provider | request shape of the vendor's SAML guide | recorded or documented requests | `saml.google_workspace` | no | 3 | `interop-lab` |
| Slack | service provider | request shape of the vendor's SAML guide | recorded or documented requests | `saml.slack` | no | 3 | `interop-lab` |
| Zoom | service provider | request shape of the vendor's SAML guide | recorded or documented requests | `saml.zoom` | no | 3 | `interop-lab` |
| Atlassian Cloud | service provider | request shape of the vendor's SAML guide | recorded or documented requests | `saml.atlassian` | no | 3 | `interop-lab` |
| ADFS | service provider | request shape of the vendor's SAML guide | recorded or documented requests | none | no | 2 | `interop-lab` |
| Amazon Web Services console federation | service provider (IdP-initiated) | response profile of the AWS IAM guide | recorded or documented requests | `saml.aws` | no | 2 | `interop-lab` |
| Microsoft Entra ID / Microsoft 365 | service provider | response profile of the Microsoft guide | recorded or documented requests | `saml.entra` | no | 1 | `interop-lab` |

## SCIM 2.0

| System | Role | Version tested | How | Profile | Oracle | Tests | CI job |
|---|---|---|---|---|---|---|---|
| scim2-tester | compliance checker | 0.6.4 | container `python` (`sha256:d98cc29d3266`) | none | yes | 1 | `differential` |
| Microsoft Entra ID | provisioning client | recorded requests, scrubbed of tenant names and secrets | recorded or documented requests | `scim.entra` | no | 4 | `interop-lab` |
| Okta | provisioning client | recorded requests, scrubbed of tenant names and secrets | recorded or documented requests | `scim.okta` | no | 4 | `interop-lab` |
| Google Workspace | provisioning client | recorded requests, scrubbed of tenant names and secrets | recorded or documented requests | `scim.google_workspace` | no | 2 | `interop-lab` |
| OneLogin | provisioning client | recorded requests, scrubbed of tenant names and secrets | recorded or documented requests | `scim.onelogin` | no | 3 | `interop-lab` |
| JumpCloud | provisioning client | recorded requests, scrubbed of tenant names and secrets | recorded or documented requests | `scim.jumpcloud` | no | 3 | `interop-lab` |

## LDAP

| System | Role | Version tested | How | Profile | Oracle | Tests | CI job |
|---|---|---|---|---|---|---|---|
| OpenLDAP command-line clients | LDAP client | ldap-utils of Ubuntu 24.04 | distribution package on the CI runner | none | no | 1 | `edge-interop` |
| OpenLDAP | directory (AD sync source) | osixia/openldap 1.5.0 | container `osixia/openldap` (`sha256:18742e9c449c`) | none | no | 1 | `edge-interop` |

## Kerberos

| System | Role | Version tested | How | Profile | Oracle | Tests | CI job |
|---|---|---|---|---|---|---|---|
| MIT Kerberos KDC | key distribution center | krb5-kdc of Debian 13.2 | container `debian` (`sha256:4bcb9db66237`) | none | no | 1 | `kerberos` |

## RADIUS

| System | Role | Version tested | How | Profile | Oracle | Tests | CI job |
|---|---|---|---|---|---|---|---|
| FreeRADIUS radclient | RADIUS client | 3.2.8 | container `freeradius/freeradius-server` (`sha256:bbb399476d80`) | none | no | 1 | `edge-interop` |

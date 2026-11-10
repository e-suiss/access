# access-identity-x509

X.509 client certificates for the Access identity plane: path validation, OCSP and CRL
revocation, and what a certificate says for sign-in. Revocation fails closed: a certificate whose
status cannot be established is refused.

## Path validation

The presented chain (leaf first, at most 8 certificates of at most 8 KB each) must lead to one of
the realm's accepted CAs with [rustls-webpki](https://github.com/rustls/webpki). Every certificate
must be valid now, and a leaf with an extended key usage must name `id-kp-clientAuth`.

## Revocation

Every certificate below the CA is checked.

| Step | Rule |
|---|---|
| OCSP first | `POST` of a DER request naming the certificate by a SHA-1 `CertID` (RFC 5019), no nonce; the answer (at most 8 KB) must be a successful basic response signed by the issuing CA or by a responder certificate the CA issued for `id-kp-OCSPSigning` |
| Freshness | `thisUpdate` at most 5 minutes ahead; current until `nextUpdate`, or 5 minutes after `thisUpdate` without one |
| `revoked` | refuses at once |
| CRL fallback | when any certificate lacks a current `good` answer, the CRLs of every certificate (at most 1 MB each) are fetched and webpki checks the whole path: revoked, uncovered or expired refuses |
| Cache | answers and CRLs are kept until their `nextUpdate`, at most 24 hours, never past it |

Unknown, unreachable, unreadable and stale all refuse. OCSP and CRL URLs may be `http` because the
documents are signed; the fetch still goes through the SSRF-guarded outbound client.

## Sign-in

| | Rule |
|---|---|
| Identifier | the realm's rule maps exactly one subjectAltName `rfc822Name` (`san_email`) or user principal name (`san_upn`) to the account |
| Assurance | an issuer policy OID the realm mapped as hardware-bound PIV makes the certificate a device-bound key with the card's PIN (AAL3, CT3); any other certificate is a software key and never reaches CT3 |
| CA trust | a CA is trusted only through the governing domain's actor-binding Acceptance of its issuer id, derived from its subject and public key |
| Thumbprint | SHA-256 of the leaf (`x5t#S256`) |

## Testing

The `testing` feature makes certificate authorities, client certificates, CRLs and OCSP responses
at test time, so no certificate or key is committed.

## License

[Apache License 2.0](../../LICENSE).

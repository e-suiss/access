# Privileged access and secret custody

How a PAM product and a secret store connect to Access. Both are separate products: Access decides who may use a privileged session or a secret, on which condition and for how long; the product keeps the session, its recording, the vault and the secret. Neither is built into Access, and Suiss does not build one.

| Concern | Owner |
|---|---|
| Who may open this session or release this secret, on which condition (just-in-time, approval, time box) | Access: a Grant with its requirements and validity |
| The session, its brokering and recording; the account vault; the secret and its versions | The PAM product or the secret store |
| The record that the use was allowed | Access: the Exercise, which the product stores with the session or the release |

## The contract

- **The product is a PEP.** It asks Access before each session or release, with the requesting user's own signed statement, over the public AuthZEN evaluation endpoint (`POST /access/v1/evaluation`). It never acts with its own identity, and it never writes a Grant.
- **No Exercise, no effect.** A session opens and a secret leaves only for an ALLOW the product verified (`esuiss-access-sdk` `authorize::Pep::authorize`). A DENY, `REQUIRE_ACTION`, an Access that does not answer, or an answer for another intent is a refusal.
- **An Exercise releases once.** A secret store hands a secret out through `resource::release::Releases::release`, which checks that the ALLOW is for exactly this secret, inside the intent's validity, and never used before.
- **Just in time.** Standing access is not needed: the Grant is time boxed, can require an approval, and ends on revocation. The next session asks again.
- **SSH.** The short-lived SSH certificate comes from the realm's Access SSH CA (`access ssh login`); the PAM keeps the session it opens.

## Files

- `pam.toml` and `secret.toml` are the seam schemas: `pam.session.open` on `pam.host:[cluster, host]` and `secret.release` on `secret:[mount, path…]`.
- `teleport.toml` and `cyberark.toml` map each product's request to an Access intent and its answer back: which fields name the resource and the user, and where the decision and its Exercise are written.
- `recorded/` holds one scrubbed request of each product. The seam tests map each recording with its mapping file, ask Access with a user's statement signed at test time, and check that the product opens nothing without the Exercise.

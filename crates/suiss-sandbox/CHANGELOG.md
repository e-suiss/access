# Changelog

## 0.2.4

### Changed

- The lockdown sets `RLIMIT_CORE` to zero; a failure reports `Step::CoreLimit`.
- The signer profile allows filesystem writes and `renameat`, kept inside its key vault by Landlock.

## 0.2.3

No changes; released with `esuiss-crypto`.

## 0.2.2

First release on crates.io.

## 0.2.1

First release as a shared crate. It was `access-sandbox`; the library is now `suiss_sandbox`.

# Changelog

## 0.3.0

No changes; released with `esuiss-access-kernel` 0.3.0.

## 0.2.6

No changes; released with `esuiss-access-kernel` and published from CI with trusted publishing.

## 0.2.5

No changes; released with `esuiss-retention`.

## 0.2.4

No changes; released with `esuiss-crypto`.

## 0.2.3

No changes; released with `esuiss-crypto`.

## 0.2.2

No changes; released with `esuiss-sandbox`.

## 0.2.1

### Changed

- `Limits` fields are private. Start from `Limits::default()` and lower one value at a time with `Limits::narrowed(Narrow::…)`; asking for a wider value is `WiderLimit`.
- `CompileError` is `#[non_exhaustive]` and has a stable `code()`.

## 0.1.1

First release.

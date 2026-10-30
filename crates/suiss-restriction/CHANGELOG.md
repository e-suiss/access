# Changelog

## 0.2.2

No changes; released with `esuiss-sandbox`.

## 0.2.1

### Changed

- `Limits` fields are private. Start from `Limits::default()` and lower one value at a time with `Limits::narrowed(Narrow::…)`; asking for a wider value is `WiderLimit`.
- `CompileError` is `#[non_exhaustive]` and has a stable `code()`.

## 0.1.1

First release.

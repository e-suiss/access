# Changelog

## 0.2.0

### Changed

- `Limits` fields are private. Start from `Limits::default()` and lower one value at a time with `Limits::narrowed(Narrow::…)`; asking for a wider value is `WiderLimit`.
- `CompileError` is `#[non_exhaustive]` and has a stable `code()`.

## 0.1.1

First release.

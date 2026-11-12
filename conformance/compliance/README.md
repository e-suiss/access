# Compliance mappings

One file per framework, `<framework>.toml`, maps each control to the guarantee rows and tests
that already back it. A mapping adds no claim of its own: every row it cites is in
[`catalog/`](../catalog), every test it names exists, and a control marked `met` names at least
one test. Statutory conformity is not guaranteed by any mapping.

| Field | Meaning |
|---|---|
| `control` | the framework's control identifier |
| `status` | `met`, `partial`, `not-claimed` or `n/a` |
| `rules` | catalog rows that back it |
| `tests` | tests that exercise it |
| `note` | the scope of the mapping, in the catalog's words |

The shape is [`compliance-map.schema.json`](../schemas/compliance-map.schema.json).
`cargo xtask check` (`compliance-map`) checks every file here.

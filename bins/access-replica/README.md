# access-replica

A replica of an Access domain's record outside the provider: it follows the mirror stream, checks every checkpoint, keeps its own append-only copy and acknowledges what it holds.

```text
access-replica follow <config>
access-replica apply-redactions <config>
access-replica --replay <config>
```

The command is a placeholder in this release: `--help` prints the usage and every other
command exits with status 2.

# access-witness

A witness for Access domains: it checks that each new checkpoint extends the one it cosigned before, cosigns it, and compares cosigns with the other witnesses to catch a log that shows different histories to different readers.

```text
access-witness serve <config>
access-witness monitor <config>
```

The command is a placeholder in this release: `--help` prints the usage and every other
command exits with status 2.

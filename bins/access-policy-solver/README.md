# access-policy-solver

The restriction analysis solver as a sibling process of the server: it runs the pinned cvc5 in
its own sandbox and answers the server's analysis requests over a Unix socket, so the server
itself never starts a process. When the solver cannot be reached or times out, the server
classifies the change at the higher tier.

```text
access-policy-solver serve <config>
```

The command is a placeholder in this release: `--help` prints the usage and every other
command exits with status 2.

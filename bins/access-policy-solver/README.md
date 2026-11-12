# access-policy-solver

The restriction analysis solver as a sibling process of the server: it runs the pinned cvc5 in
its own sandbox and answers the server's analysis requests over a Unix socket, so the server
itself never starts a process. When the solver cannot be reached, gives no answer or times out,
the server classifies the change at the higher tier.

```text
access-policy-solver serve <config>
```

The configuration names the socket, the cvc5 executable and the socket mode:

```text
socket = "/run/access-solver/solver.sock"
cvc5 = "/opt/cvc5/bin/cvc5"
mode = "0660"
```

At start the solver refuses a socket directory that others can write. The server is pointed at
the socket with `[policy] solver` (and `solver_owner` when the solver runs under another uid);
it checks the socket's owner and mode at start and before every request.

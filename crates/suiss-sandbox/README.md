# esuiss-sandbox

Process lockdown for Suiss services on Linux. A process calls it once at start-up, after it has opened the files and sockets it needs, and from then on it cannot reach anything else. If any step cannot be applied the call fails and the process must exit: there is no "run without the sandbox" mode.

What it applies, in order:

- `PR_SET_DUMPABLE=0` and `no_new_privs`;
- a switch away from root to the identity you give, and an empty capability set;
- Landlock (ABI V4 or newer): only the paths you declare are readable, writable or executable, and with V4 only the TCP ports you declare can be bound or connected to;
- seccomp in two phases: a start-up allowlist, then a narrower one installed on every thread once the runtime is up; `io_uring` is never allowed, and no profile can create processes;
- `memfd_secret` memory for key material, where the kernel supports it.

## Profiles

| Profile | For | Unlisted syscalls |
|---|---|---|
| `Server` | Network-facing services | fail with `EPERM` |
| `Signer` | Signing processes: Unix sockets only, no network | kill the process |
| `ParserWorker` | Workers that parse untrusted input: no sockets at all | kill the process |
| `Solver` | An external solver started through `Lockdown::confine` | kill the process |

## Use

```toml
[dependencies]
esuiss-sandbox = "=0.2.0"
```

```rust
use suiss_sandbox::{LandlockAbi, Lockdown, Profile};

let locked = Lockdown::new(Profile::Server, LandlockAbi::REQUIRED)
    .allow_read("/etc/my-service")
    .allow_tcp_connect(5432)
    .apply()?;
// start the async runtime, then:
let report = locked.narrow()?;
```

On other operating systems every call returns an error, so a service that requires the lockdown does not start there. Run it in a Linux container instead.

## Versions

Until 1.0, a breaking change raises the minor version. Pin an exact version. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache License 2.0](../../LICENSE).

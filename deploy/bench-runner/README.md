# Benchmark runner

The nightly wall-clock benchmarks (OP-72) run on one dedicated, always-on Linux
machine registered as a GitHub Actions self-hosted runner (OP-84). Instruction-count
benchmarks do not need it: they run on GitHub-hosted runners on every pull request.

Only the `bench-wallclock` job of the `Nightly` workflow runs here, and only for
scheduled or manually started runs of `main`. Pull requests never run on this machine:
the repository is public, and a pull request could otherwise execute arbitrary code on it.

## What the setup does

`setup.sh` (run as root) installs:

- the GitHub Actions runner, pinned by version and SHA-256, owned by an unprivileged
  `gh-bench` user with no sudo and no login shell;
- `rustup` for that user; the workflow installs the toolchain pinned in `rust-toolchain.toml`;
- a `systemd` unit `actions-runner-bench.service` with sandboxing (`NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, writable paths limited to the runner's own dirs)
  and optional CPU pinning;
- a `systemd` oneshot `bench-cpu-tuning.service` that sets the `performance` governor and
  switches off turbo/boost at every boot.

The registration token is typed in when the script asks for it. It is passed to the
runner's `config.sh` and never written anywhere. The runner keeps only its own
credentials, under `/opt/actions-runner`.

## One-time setup

1. **Scope**: the runner registers on the `e-suiss/access` repository only (repository-level
   runner; the organization's free plan has no custom runner groups). Other repositories
   cannot use it.
2. **Repository setting** (Settings → Actions → General): require approval for workflow runs
   from all outside collaborators. A pull request cannot run on this machine until a
   maintainer approves it.
3. **Machine** (optional, recommended): isolate two cores from the scheduler and pin the
   runner to them. Add to the kernel command line and reboot:

   ```
   isolcpus=2,3 nohz_full=2,3 rcu_nocbs=2,3
   ```

   Disabling SMT (`echo off > /sys/devices/system/cpu/smt/control`) removes another noise
   source. Keep the machine otherwise idle: no desktop session, no other services that wake up
   at night.
4. **Install and register**:

   ```sh
   sudo BENCH_CPUS=2-3 ./setup.sh
   ```

   Create the token with `gh api -X POST repos/e-suiss/access/actions/runners/registration-token --jq .token`
   (valid for one hour) and paste it when asked. Leave `BENCH_CPUS` unset if no cores are isolated.

## Operation

- Status: `systemctl status actions-runner-bench` and the repository's runner list.
- Logs: `journalctl -u actions-runner-bench`.
- Each night uploads an artifact named `bench-wallclock-<run id>` containing the commit,
  date, kernel and governor, followed by the benchmark table.
- If the machine is off, that night has no measurement. The gap stays in the series and
  is never filled in afterwards (OP-84).
- The runner updates itself when GitHub releases a new version. To move to a new pinned
  version for a fresh install, change `RUNNER_VERSION` and both checksums in `setup.sh`
  after the 7-day cooldown (F-2).

## Removing the runner

```sh
sudo systemctl disable --now actions-runner-bench
sudo -u gh-bench /opt/actions-runner/config.sh remove --token <removal token>
```

The removal token comes from `gh api -X POST repos/e-suiss/access/actions/runners/remove-token --jq .token`.

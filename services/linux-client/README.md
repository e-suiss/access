# access-linux-client

Sign in to a Linux computer with Access. The `access-linuxd` daemon answers user and group lookups and console sign-ins for the NSS and PAM modules, which talk to it over a local socket. A console sign-in is approved in the browser or on a phone; `sudo` asks for a security key every time. When Access cannot be reached, a short-lived cache keeps console sign-in working within limits the administrator sets, and `sudo` is never allowed offline.

## How it works

- **Who exists on the computer.** An administrator registers the computer with its server group and the fingerprint of its client certificate. The computer resolves exactly the people whose `ssh.login` access names that server group, under the Linux names the access lists. User and group ids are handed out once per name and never reused. Nothing else about the person reaches the computer.
- **Console sign-in.** The PAM module shows a code and a link; the person opens it, signs in and approves. Access then checks that their access names this user on this computer. Access that only `sshd` can enforce (a forced command, a source address) opens no console.
- **`sudo`.** Every `sudo` is a fresh step-up: a sign-in in the last five minutes with a phishing-resistant, user-verifying authenticator (CT2), or also device-bound (CT3) when the computer asks for it. A push or a password alone never opens `sudo`.
- **Offline.** The daemon keeps the user list for at most 12 hours and reuses a console sign-in for at most 8 hours, both never past the computer's horizon, and the offline sign-in still needs one of the person's security keys. `sudo` is never answered offline. A clock that goes back stops every offline answer.
- **Emergency access.** With break-glass allowed for the computer, the reserved break-glass proof issued in advance lets one person in once, checked offline; the proof is marked spent on the computer.
- **Fail-closed.** When the daemon does not answer, the NSS module resolves nobody and the PAM module answers `PAM_AUTHINFO_UNAVAIL`.

## Install

The `-linux-client` image is the package root: copy its files onto the computer.

| File | Place |
| --- | --- |
| `access-linuxd` | `/usr/sbin/access-linuxd` |
| `libnss_access.so.2` | `/usr/lib/x86_64-linux-gnu/` |
| `pam_access.so` | `/usr/lib/access/` (its own directory: Linux-PAM ships a module of the same name) |
| `access-linuxd.service` | `/usr/lib/systemd/system/` |

Then:

1. Put the realm's CA, the computer's client certificate and key under `/etc/access-linuxd/` (root, mode 0600) and fill in `/etc/access-linuxd/access-linuxd.env` from `deploy/linux-client/access-linuxd.env`.
2. Add `access` after `files` for `passwd` and `group` in `/etc/nsswitch.conf` (`deploy/linux-client/nsswitch.conf`).
3. Add `auth required /usr/lib/access/pam_access.so` to `/etc/pam.d/login` and `/etc/pam.d/sudo` (`deploy/linux-client/pam.d/`).
4. `systemctl enable --now access-linuxd`.

## Crates

- `access-linux-client`: the daemon, on public crates only.
- `access-linux-module`: the socket messages (`conformance/cddl/linux-client.cddl`) and the modules' safe code.
- `access-linux-nss`, `access-linux-pam`: the C ABI shells, Linux only.

## License

Apache-2.0.

# access-linux-client

Sign in to a Linux computer with Access. The `access-linuxd` daemon answers user and group lookups and console sign-ins for the NSS and PAM modules, which talk to it over a local socket. A console sign-in is approved in the browser or on a phone, or with a local security key; `sudo` asks for a security key every time. When Access cannot be reached, a short-lived cache keeps console sign-in working within limits the administrator sets, and `sudo` is never allowed offline.

## License

Apache-2.0.

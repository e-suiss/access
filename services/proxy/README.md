# access-proxy

Access Proxy puts sign-in and an authorization decision in front of any web application. One TOML file describes the application; `access-proxy` renders it as Envoy, Caddy or Traefik configuration, and the engine asks Access before every request. When Access cannot be reached, the request is refused.

It uses public crates only, holds no authority, and never implements the proxy engine itself.

## License

Apache-2.0.

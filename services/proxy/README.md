# access-proxy

Access Proxy puts sign-in and an authorization decision in front of any web application, without changing the application. You write one TOML file. `access-proxy` turns it into Envoy, Caddy or Traefik configuration, and before every request the engine asks Access. When Access cannot be reached, the request is refused.

The proxy engine is never written here. Envoy and Caddy are packaged as images; Traefik is configuration output only; Nginx has a documented `auth_request` example. Switching engines never changes the TOML file.

## The file

```toml
[access]
url = "https://access.example.com:8443"         # Access's mTLS listener
ca = "/etc/access-proxy/access-ca.pem"          # roots of Access's certificate
certificate = "/etc/access-proxy/proxy.pem"     # Access names the proxy by this certificate
key = "/etc/access-proxy/proxy-key.pem"

[listen]
address = "0.0.0.0:8443"
certificate = "/etc/access-proxy/tls/apps.pem"  # optional for Caddy, which can obtain its own
key = "/etc/access-proxy/tls/apps-key.pem"

[[app]]
policy = "wiki"                                 # the proxy registration in Access
host = "wiki.example.com"
upstream = "http://127.0.0.1:8080"
plain_headers = false
```

Who may reach what is decided in Access, not in this file. Register the proxy in Access with `idp.proxy.register`, naming the application host, the client certificate's thumbprint, the action every request asks and the path patterns.

The application receives `Access-Identity`, a short-lived token signed by Access for that application. `X-Access-User` and `X-Access-Email` are passed only when both the file and Access turn them on, and the tool refuses them unless the upstream is a loopback address that only the proxy can reach. Identity headers sent by the client never reach the application.

## Commands

```text
access-proxy check  [--config FILE]
access-proxy render --engine envoy|caddy|traefik [--config FILE] [--out FILE]
access-proxy run    --engine envoy|caddy [--config FILE] [--dir DIR]
```

`run` renders the configuration and starts the engine on it; it is the entry point of the images.

## Packages

- `ghcr.io/e-suiss/access-proxy-envoy`: the official Envoy image, pinned by digest, with `access-proxy`.
- `ghcr.io/e-suiss/access-proxy-caddy`: the official Caddy image, pinned by digest, with `access-proxy`.
- `deploy/proxy/k8s/`: a kustomize template.
- `deploy/proxy/nginx/access-proxy.conf.template`: the Nginx `auth_request` example.

Each image's SBOM names its engine and version. The engines pass the same behaviour cases (`tests/behaviour/`) in CI.

## License

Apache-2.0.

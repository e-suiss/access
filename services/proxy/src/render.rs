//! The one file as each engine's configuration (IDP-30 (2), OP-156 m.3 (m), m.15 (f)). Every
//! engine asks Access's `/proxy/v1/check/{engine}` before each request with the proxy's client
//! certificate, passes only the identity headers the answer sets, and refuses when Access does not
//! answer. Traefik is configuration output only; Envoy and Caddy are also packaged.

use std::fmt::Write as _;
use std::net::IpAddr;

use crate::config::{App, Config, ConfigError, Origin, Scheme};
use crate::yaml::{Y, map, s, to_yaml};

/// The application token header (OP-156 m.3 (l)).
pub const IDENTITY_HEADER: &str = "Access-Identity";

/// The plain identity headers, sent only under `idp.proxy.plain_headers` (OP-156 m.3 (l)).
pub const PLAIN_HEADERS: [&str; 2] = ["X-Access-User", "X-Access-Email"];

/// The headers of a refusal or a sign-in that go back to the browser.
pub const CLIENT_HEADERS: [&str; 5] = [
    "Location",
    "Set-Cookie",
    "Cache-Control",
    "Retry-After",
    "Content-Type",
];

/// An engine `access-proxy` renders for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Envoy, packaged as `-proxy-envoy`.
    Envoy,
    /// Caddy, packaged as `-proxy-caddy`.
    Caddy,
    /// Traefik dynamic configuration, not packaged.
    Traefik,
}

/// Every target.
pub const TARGETS: [Target; 3] = [Target::Envoy, Target::Caddy, Target::Traefik];

impl Target {
    /// The target `word` names.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        TARGETS.into_iter().find(|t| t.word() == word)
    }

    /// Its name, which is also its forward-auth path word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Envoy => "envoy",
            Self::Caddy => "caddy",
            Self::Traefik => "traefik",
        }
    }

    /// The configuration file name.
    #[must_use]
    pub const fn file(self) -> &'static str {
        match self {
            Self::Envoy => "envoy.yaml",
            Self::Caddy => "Caddyfile",
            Self::Traefik => "traefik.yaml",
        }
    }
}

/// The forward-auth check path of `target` (OP-156 m.3 (l)).
#[must_use]
pub fn check_path(target: Target) -> String {
    format!("/proxy/v1/check/{}", target.word())
}

/// The identity headers an allowed request of `app` carries: always the token, the plain ones
/// only when the file turns them on.
#[must_use]
pub fn passed(app: &App) -> Vec<&'static str> {
    let mut h = vec![IDENTITY_HEADER];
    if app.plain_headers {
        h.extend(PLAIN_HEADERS);
    }
    h
}

/// `config` for `target`.
///
/// # Errors
/// [`ConfigError::Needs`] when the target needs a value the file leaves out.
pub fn render(config: &Config, target: Target) -> Result<String, ConfigError> {
    match target {
        Target::Envoy => envoy(config),
        Target::Caddy => Ok(caddy(config)),
        Target::Traefik => traefik(config),
    }
}

/// `ms` as a protobuf JSON duration.
fn seconds(ms: u64) -> String {
    format!("{}.{:03}s", ms / 1000, ms % 1000)
}

fn exact(names: &[&str]) -> Y {
    map([(
        "patterns",
        Y::List(
            names
                .iter()
                .map(|n| map([("exact", s(n.to_ascii_lowercase()))]))
                .collect(),
        ),
    )])
}

fn address(host: &str, port: u16) -> Y {
    map([(
        "socket_address",
        map([
            ("address", s(host)),
            ("port_value", Y::Int(u64::from(port))),
        ]),
    )])
}

fn cluster(name: &str, o: &Origin, tls: Option<Y>, timeout_ms: u64) -> Y {
    let mut c = vec![
        (String::from("name"), s(name)),
        (String::from("type"), s("STRICT_DNS")),
        (String::from("dns_lookup_family"), s("V4_PREFERRED")),
        (String::from("connect_timeout"), s(seconds(timeout_ms))),
        (
            String::from("load_assignment"),
            map([
                ("cluster_name", s(name)),
                (
                    "endpoints",
                    Y::List(vec![map([(
                        "lb_endpoints",
                        Y::List(vec![map([(
                            "endpoint",
                            map([("address", address(&o.host, o.port))]),
                        )])]),
                    )])]),
                ),
            ]),
        ),
    ];
    if let Some(t) = tls {
        c.push((String::from("transport_socket"), t));
    }
    Y::Map(c)
}

fn san(o: &Origin) -> Y {
    let kind = if o.ip().is_some() {
        "IP_ADDRESS"
    } else {
        "DNS"
    };
    Y::List(vec![map([
        ("san_type", s(kind)),
        ("matcher", map([("exact", s(o.host.clone()))])),
    ])])
}

fn upstream_tls(o: &Origin, ca: &str, client: Option<(&str, &str)>, tls13: bool) -> Y {
    let mut common = Vec::new();
    if tls13 {
        common.push((
            String::from("tls_params"),
            map([
                ("tls_minimum_protocol_version", s("TLSv1_3")),
                ("tls_maximum_protocol_version", s("TLSv1_3")),
            ]),
        ));
    }
    if let Some((cert, key)) = client {
        common.push((
            String::from("tls_certificates"),
            Y::List(vec![map([
                ("certificate_chain", map([("filename", s(cert))])),
                ("private_key", map([("filename", s(key))])),
            ])]),
        ));
    }
    common.push((
        String::from("validation_context"),
        map([
            ("trusted_ca", map([("filename", s(ca))])),
            ("match_typed_subject_alt_names", san(o)),
        ]),
    ));
    let mut ctx = vec![(String::from("common_tls_context"), Y::Map(common))];
    if o.ip().is_none() {
        ctx.push((String::from("sni"), s(o.host.clone())));
    }
    map([
        ("name", s("envoy.transport_sockets.tls")),
        (
            "typed_config",
            Y::Map(
                [(
                    String::from("@type"),
                    s("type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext"),
                )]
                .into_iter()
                .chain(ctx)
                .collect(),
            ),
        ),
    ])
}

fn app_cluster(app: &App) -> String {
    format!("app-{}", app.policy)
}

#[allow(
    clippy::too_many_lines,
    reason = "one Envoy bootstrap document, written top to bottom as Envoy reads it"
)]
fn envoy(c: &Config) -> Result<String, ConfigError> {
    let (cert, key) = c.listen.tls.as_ref().ok_or(ConfigError::Needs {
        engine: "envoy",
        field: "listen.certificate",
    })?;
    let a = &c.access;
    let mut hosts: Vec<Y> = c
        .apps
        .iter()
        .map(|app| {
            map([
                ("name", s(app.policy.clone())),
                (
                    "domains",
                    Y::List(vec![s(app.hostname()), s(format!("{}:*", app.hostname()))]),
                ),
                (
                    "routes",
                    Y::List(vec![Y::Map(
                        [
                            (String::from("match"), map([("prefix", s("/"))])),
                            (
                                String::from("route"),
                                map([("cluster", s(app_cluster(app))), ("timeout", s("60s"))]),
                            ),
                        ]
                        .into_iter()
                        .chain((!app.plain_headers).then(|| {
                            (
                                String::from("request_headers_to_remove"),
                                Y::List(
                                    PLAIN_HEADERS
                                        .iter()
                                        .map(|h| s(h.to_ascii_lowercase()))
                                        .collect(),
                                ),
                            )
                        }))
                        .collect(),
                    )]),
                ),
            ])
        })
        .collect();
    hosts.push(map([
        ("name", s("unknown-host")),
        ("domains", Y::List(vec![s("*")])),
        (
            "routes",
            Y::List(vec![map([
                ("match", map([("prefix", s("/"))])),
                ("direct_response", map([("status", Y::Int(404))])),
            ])]),
        ),
    ]));
    let mut upstream_headers = vec![IDENTITY_HEADER];
    if c.apps.iter().any(|a| a.plain_headers) {
        upstream_headers.extend(PLAIN_HEADERS);
    }
    let strip: Vec<Y> = upstream_headers
        .iter()
        .copied()
        .chain(PLAIN_HEADERS)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|h| s(h.to_ascii_lowercase()))
        .collect();
    let ext_authz = map([
        ("name", s("envoy.filters.http.ext_authz")),
        (
            "typed_config",
            map([
                (
                    "@type",
                    s("type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz"),
                ),
                ("transport_api_version", s("V3")),
                ("failure_mode_allow", Y::Bool(false)),
                ("status_on_error", map([("code", s("ServiceUnavailable"))])),
                ("allowed_headers", exact(&["cookie"])),
                (
                    "http_service",
                    map([
                        (
                            "server_uri",
                            map([
                                ("uri", s(a.origin.url())),
                                ("cluster", s("access")),
                                ("timeout", s(seconds(a.timeout_ms))),
                            ]),
                        ),
                        ("path_prefix", s(check_path(Target::Envoy))),
                        (
                            "authorization_response",
                            map([
                                ("allowed_upstream_headers", exact(&upstream_headers)),
                                ("allowed_client_headers", exact(&CLIENT_HEADERS)),
                            ]),
                        ),
                    ]),
                ),
            ]),
        ),
    ]);
    let hcm = map([
        ("name", s("envoy.filters.network.http_connection_manager")),
        (
            "typed_config",
            map([
                (
                    "@type",
                    s(
                        "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                    ),
                ),
                ("stat_prefix", s("access_proxy")),
                ("codec_type", s("AUTO")),
                ("path_with_escaped_slashes_action", s("REJECT_REQUEST")),
                (
                    "route_config",
                    map([("name", s("apps")), ("virtual_hosts", Y::List(hosts))]),
                ),
                (
                    "http_filters",
                    Y::List(vec![
                        map([
                            ("name", s("envoy.filters.http.header_mutation")),
                            (
                                "typed_config",
                                map([
                                    (
                                        "@type",
                                        s(
                                            "type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation",
                                        ),
                                    ),
                                    (
                                        "mutations",
                                        map([(
                                            "request_mutations",
                                            Y::List(
                                                strip
                                                    .into_iter()
                                                    .map(|h| map([("remove", h)]))
                                                    .collect(),
                                            ),
                                        )]),
                                    ),
                                ]),
                            ),
                        ]),
                        ext_authz,
                        map([
                            ("name", s("envoy.filters.http.router")),
                            (
                                "typed_config",
                                map([(
                                    "@type",
                                    s(
                                        "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
                                    ),
                                )]),
                            ),
                        ]),
                    ]),
                ),
            ]),
        ),
    ]);
    let listener_tls = map([
        ("name", s("envoy.transport_sockets.tls")),
        (
            "typed_config",
            map([
                (
                    "@type",
                    s(
                        "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                    ),
                ),
                (
                    "common_tls_context",
                    map([
                        (
                            "tls_params",
                            map([("tls_minimum_protocol_version", s("TLSv1_2"))]),
                        ),
                        (
                            "tls_certificates",
                            Y::List(vec![map([
                                ("certificate_chain", map([("filename", s(cert.clone()))])),
                                ("private_key", map([("filename", s(key.clone()))])),
                            ])]),
                        ),
                        ("alpn_protocols", Y::List(vec![s("h2"), s("http/1.1")])),
                    ]),
                ),
            ]),
        ),
    ]);
    let mut clusters = vec![cluster(
        "access",
        &a.origin,
        Some(upstream_tls(
            &a.origin,
            &a.ca,
            Some((&a.certificate, &a.key)),
            true,
        )),
        a.timeout_ms,
    )];
    for app in &c.apps {
        let tls = match (&app.upstream.scheme, &app.upstream_ca) {
            (Scheme::Https, Some(ca)) => Some(upstream_tls(&app.upstream, ca, None, false)),
            _ => None,
        };
        clusters.push(cluster(&app_cluster(app), &app.upstream, tls, 5000));
    }
    let doc = map([(
        "static_resources",
        map([
            (
                "listeners",
                Y::List(vec![map([
                    ("name", s("apps")),
                    ("address", address(&c.listen.ip.to_string(), c.listen.port)),
                    (
                        "filter_chains",
                        Y::List(vec![map([
                            ("filters", Y::List(vec![hcm])),
                            ("transport_socket", listener_tls),
                        ])]),
                    ),
                ])]),
            ),
            ("clusters", Y::List(clusters)),
        ]),
    )]);
    let mut out = String::from(
        "# Rendered by access-proxy from access-proxy.toml; edit that file instead.\n",
    );
    out.push_str(&to_yaml(&doc));
    Ok(out)
}

fn caddy_bind(ip: IpAddr) -> Option<String> {
    (!ip.is_unspecified()).then(|| ip.to_string())
}

fn caddy(c: &Config) -> String {
    let a = &c.access;
    let mut out = String::from(
        "# Rendered by access-proxy from access-proxy.toml; edit that file instead.\n{\n\tadmin off\n",
    );
    if c.listen.tls.is_some() {
        out.push_str("\tauto_https disable_redirects\n");
    }
    if c.listen.port != 443 {
        let _ = writeln!(out, "\thttps_port {}", c.listen.port);
    }
    if let Some(b) = caddy_bind(c.listen.ip) {
        let _ = writeln!(out, "\tdefault_bind {b}");
    }
    out.push_str("}\n");
    for app in &c.apps {
        let site = if c.listen.port == 443 {
            String::from(app.hostname())
        } else {
            format!("{}:{}", app.hostname(), c.listen.port)
        };
        let _ = writeln!(out, "\n{site} {{");
        if let Some((cert, key)) = &c.listen.tls {
            let _ = writeln!(out, "\ttls {cert} {key}");
        }
        out.push_str("\troute {\n");
        for h in std::iter::once(IDENTITY_HEADER).chain(PLAIN_HEADERS) {
            let _ = writeln!(out, "\t\trequest_header -{h}");
        }
        let _ = writeln!(out, "\t\tforward_auth {} {{", a.origin.url());
        let _ = writeln!(out, "\t\t\turi {}", check_path(Target::Caddy));
        let _ = writeln!(out, "\t\t\tcopy_headers {}", passed(app).join(" "));
        out.push_str("\t\t\ttransport http {\n");
        let _ = writeln!(out, "\t\t\t\ttls_client_auth {} {}", a.certificate, a.key);
        let _ = writeln!(out, "\t\t\t\ttls_trust_pool file {}", a.ca);
        let _ = writeln!(out, "\t\t\t\ttls_server_name {}", a.origin.host);
        let _ = writeln!(out, "\t\t\t\tdial_timeout {}ms", a.timeout_ms);
        let _ = writeln!(out, "\t\t\t\tresponse_header_timeout {}ms", a.timeout_ms);
        out.push_str("\t\t\t}\n\t\t}\n");
        match &app.upstream_ca {
            Some(ca) => {
                let _ = writeln!(out, "\t\treverse_proxy {} {{", app.upstream.url());
                out.push_str("\t\t\ttransport http {\n");
                let _ = writeln!(out, "\t\t\t\ttls_trust_pool file {ca}");
                let _ = writeln!(out, "\t\t\t\ttls_server_name {}", app.upstream.host);
                out.push_str("\t\t\t}\n\t\t}\n");
            }
            None => {
                let _ = writeln!(out, "\t\treverse_proxy {}", app.upstream.url());
            }
        }
        out.push_str("\t}\n}\n");
    }
    out
}

#[allow(
    clippy::too_many_lines,
    reason = "one Traefik dynamic document, written top to bottom as Traefik reads it"
)]
fn traefik(c: &Config) -> Result<String, ConfigError> {
    let a = &c.access;
    let mut routers = Vec::new();
    let mut middlewares = Vec::new();
    let mut services = Vec::new();
    let mut transports = Vec::new();
    for app in &c.apps {
        let strip = format!("{}-strip", app.policy);
        let auth = format!("{}-access", app.policy);
        routers.push((
            app.policy.clone(),
            map([
                ("rule", s(format!("Host(`{}`)", app.hostname()))),
                ("service", s(app.policy.clone())),
                (
                    "middlewares",
                    Y::List(vec![s(strip.clone()), s(auth.clone())]),
                ),
                ("tls", map([])),
            ]),
        ));
        middlewares.push((
            strip,
            map([(
                "headers",
                map([(
                    "customRequestHeaders",
                    Y::Map(
                        std::iter::once(IDENTITY_HEADER)
                            .chain(PLAIN_HEADERS)
                            .map(|h| (String::from(h), s("")))
                            .collect(),
                    ),
                )]),
            )]),
        ));
        middlewares.push((
            auth,
            map([(
                "forwardAuth",
                map([
                    (
                        "address",
                        s(format!("{}{}", a.origin.url(), check_path(Target::Traefik))),
                    ),
                    ("trustForwardHeader", Y::Bool(false)),
                    (
                        "authResponseHeaders",
                        Y::List(passed(app).into_iter().map(s).collect()),
                    ),
                    (
                        "tls",
                        map([
                            ("ca", s(a.ca.clone())),
                            ("cert", s(a.certificate.clone())),
                            ("key", s(a.key.clone())),
                        ]),
                    ),
                ]),
            )]),
        ));
        let mut lb = vec![
            (
                String::from("servers"),
                Y::List(vec![map([("url", s(app.upstream.url()))])]),
            ),
            (String::from("passHostHeader"), Y::Bool(true)),
        ];
        if let Some(ca) = &app.upstream_ca {
            let name = format!("{}-upstream", app.policy);
            lb.push((String::from("serversTransport"), s(name.clone())));
            transports.push((
                name,
                map([
                    ("serverName", s(app.upstream.host.clone())),
                    ("rootCAs", Y::List(vec![s(ca.clone())])),
                ]),
            ));
        }
        services.push((app.policy.clone(), map([("loadBalancer", Y::Map(lb))])));
    }
    let mut http = vec![
        (String::from("routers"), Y::Map(routers)),
        (String::from("middlewares"), Y::Map(middlewares)),
        (String::from("services"), Y::Map(services)),
    ];
    if !transports.is_empty() {
        http.push((String::from("serversTransports"), Y::Map(transports)));
    }
    let (cert, key) = c.listen.tls.as_ref().ok_or(ConfigError::Needs {
        engine: "traefik",
        field: "listen.certificate",
    })?;
    let doc = map([
        ("http", Y::Map(http)),
        (
            "tls",
            map([(
                "certificates",
                Y::List(vec![map([
                    ("certFile", s(cert.clone())),
                    ("keyFile", s(key.clone())),
                ])]),
            )]),
        ),
    ]);
    let mut out = String::from(
        "# Rendered by access-proxy from access-proxy.toml; edit that file instead.\n",
    );
    out.push_str(&to_yaml(&doc));
    Ok(out)
}

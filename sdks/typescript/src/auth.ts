// T41, OP-151 m.3 (g): the identity side for browsers and Node. RFC 6749, RFC 7636, RFC 8414,
// RFC 9207, RFC 9449, RFC 9700. Every check fails closed; nothing here signs in on an unknown
// answer.

/** The only PKCE method; `plain` is never offered (RFC 9700 §2.1.1). */
export const PKCE_METHOD = "S256";

/** Longest read or access token lifetime the management surface accepts (TN-130). */
export const MAX_MANAGEMENT_TOKEN_SECONDS = 3600;

/** A refusal with a stable `code`; for an OAuth error answer, its class (P15). */
export class AuthError extends Error {
  readonly code: string;
  readonly oauthClass: OAuthClass | undefined;

  constructor(code: string, oauthClass?: OAuthClass) {
    super(code);
    this.name = "AuthError";
    this.code = code;
    this.oauthClass = oauthClass;
  }
}

/** OAuth error classes; an `error` code the SDK does not know is `refused`, its parent (P15). */
export type OAuthClass =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "access_denied"
  | "interaction_required"
  | "invalid_dpop_proof"
  | "use_dpop_nonce"
  | "unavailable"
  | "refused";

const OAUTH_CLASSES: Readonly<Record<string, OAuthClass>> = {
  invalid_request: "invalid_request",
  invalid_request_uri: "invalid_request",
  invalid_request_object: "invalid_request",
  invalid_client: "invalid_client",
  invalid_grant: "invalid_grant",
  unauthorized_client: "unauthorized_client",
  unsupported_grant_type: "unsupported_grant_type",
  unsupported_response_type: "unsupported_grant_type",
  invalid_scope: "invalid_scope",
  access_denied: "access_denied",
  login_required: "interaction_required",
  interaction_required: "interaction_required",
  consent_required: "interaction_required",
  account_selection_required: "interaction_required",
  invalid_dpop_proof: "invalid_dpop_proof",
  use_dpop_nonce: "use_dpop_nonce",
  server_error: "unavailable",
  temporarily_unavailable: "unavailable",
};

export function oauthClass(code: string): OAuthClass {
  return Object.hasOwn(OAUTH_CLASSES, code) ? (OAUTH_CLASSES[code] ?? "refused") : "refused";
}

/** What an app shows when the access token expired and the refresh failed (§8.13). */
export const SIGN_IN_AGAIN = "Please sign in again to continue.";

/**
 * The text an app shows for a failed refresh: the one sign-in-again line, never a cause the app
 * cannot verify (§8.13); `undefined` for a refusal the person cannot fix by signing in.
 */
export function refreshFailedText(e: AuthError): string | undefined {
  switch (e.oauthClass) {
    case "invalid_grant":
    case "interaction_required":
    case "invalid_client":
    case "unauthorized_client":
      return SIGN_IN_AGAIN;
    default:
      return undefined;
  }
}

export function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** `n` random bytes from the platform CSPRNG, base64url. */
export function randomText(n = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(n)));
}

async function sha256(text: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

/** `BASE64URL(SHA256(ASCII(verifier)))` (RFC 7636 §4.2). */
export async function pkceChallenge(verifier: string): Promise<string> {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) throw new AuthError("pkce-verifier");
  return base64url(await sha256(verifier));
}

export interface Metadata {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly parEndpoint?: string;
  readonly endSessionEndpoint?: string;
  readonly issParameter: boolean;
  readonly dpopAlgs: readonly string[];
}

/** The discovery URL of `issuer` (OIDC Discovery §4). */
export function wellKnown(issuer: string): string {
  return `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
}

export function isHttps(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "https:" && u.username === "" && u.password === "" && u.hash === "";
  } catch {
    return false;
  }
}

function strings(v: unknown): string[] | undefined {
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? v : undefined;
}

/**
 * Reads authorization server metadata for the configured `issuer` (RFC 8414 §3.3): the issuer
 * is that exact string, every endpoint is `https`, and `S256` is offered.
 */
export function parseMetadata(doc: unknown, issuer: string): Metadata {
  if (typeof doc !== "object" || doc === null) throw new AuthError("discovery-malformed");
  const d = doc as Record<string, unknown>;
  if (d["issuer"] !== issuer || !isHttps(issuer)) throw new AuthError("discovery-issuer");
  if (!strings(d["code_challenge_methods_supported"])?.includes(PKCE_METHOD)) {
    throw new AuthError("discovery-pkce");
  }
  const endpoint = (name: string): string => {
    const v = d[name];
    if (typeof v !== "string" || !isHttps(v)) throw new AuthError(`discovery-endpoint:${name}`);
    return v;
  };
  const optional = (name: string): string | undefined =>
    d[name] === undefined ? undefined : endpoint(name);
  const par = optional("pushed_authorization_request_endpoint");
  const endSession = optional("end_session_endpoint");
  return {
    issuer,
    authorizationEndpoint: endpoint("authorization_endpoint"),
    tokenEndpoint: endpoint("token_endpoint"),
    jwksUri: endpoint("jwks_uri"),
    ...(par === undefined ? {} : { parEndpoint: par }),
    ...(endSession === undefined ? {} : { endSessionEndpoint: endSession }),
    issParameter: d["authorization_response_iss_parameter_supported"] === true,
    dpopAlgs: strings(d["dpop_signing_alg_values_supported"]) ?? [],
  };
}

export interface Client {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scope: string;
}

/** What the client keeps between the request and the callback; store it, never log it. */
export interface Pending {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly issParameter: boolean;
  readonly state: string;
  readonly nonce: string;
  readonly verifier: string;
}

/** The authorization request: fresh `state`, `nonce` and verifier; `dpop_jkt` when given. */
export async function authorizationRequest(
  meta: Metadata,
  client: Client,
  dpopJkt?: string,
): Promise<{ url: string; pending: Pending }> {
  const pending: Pending = {
    issuer: meta.issuer,
    clientId: client.clientId,
    redirectUri: client.redirectUri,
    issParameter: meta.issParameter,
    state: randomText(),
    nonce: randomText(),
    verifier: randomText(),
  };
  const scopes = client.scope.split(" ").filter((s) => s !== "");
  if (!scopes.includes("openid")) scopes.unshift("openid");
  const url = new URL(meta.authorizationEndpoint);
  const q = url.searchParams;
  q.set("response_type", "code");
  q.set("client_id", client.clientId);
  q.set("redirect_uri", client.redirectUri);
  q.set("scope", scopes.join(" "));
  q.set("state", pending.state);
  q.set("nonce", pending.nonce);
  q.set("code_challenge", await pkceChallenge(pending.verifier));
  q.set("code_challenge_method", PKCE_METHOD);
  if (dpopJkt !== undefined) q.set("dpop_jkt", dpopJkt);
  return { url: url.href, pending };
}

function same(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * The code of a callback (RFC 9700 §4.7, RFC 9207): this request's `state`, the same issuer,
 * no `error`, and a `code`. Anything else throws.
 */
export function callbackCode(pending: Pending, query: string | URLSearchParams): string {
  const q = typeof query === "string" ? new URLSearchParams(query) : query;
  for (const name of new Set(q.keys())) {
    if (q.getAll(name).length > 1) throw new AuthError("callback-malformed");
  }
  const state = q.get("state");
  if (state === null || !same(state, pending.state)) throw new AuthError("callback-state");
  const iss = q.get("iss");
  if ((iss === null && pending.issParameter) || (iss !== null && iss !== pending.issuer)) {
    throw new AuthError("callback-issuer");
  }
  const error = q.get("error");
  if (error !== null) throw new AuthError("callback-refused", oauthClass(error));
  const code = q.get("code");
  if (code === null || code === "") throw new AuthError("callback-code");
  return code;
}

/** The token request body for `code` (RFC 6749 §4.1.3, RFC 7636 §4.5). */
export function tokenRequestBody(pending: Pending, code: string): URLSearchParams {
  return new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: pending.redirectUri,
    client_id: pending.clientId,
    code_verifier: pending.verifier,
  });
}

/** The refresh request body (RFC 6749 §6). */
export function refreshRequestBody(clientId: string, refreshToken: string): URLSearchParams {
  return new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: clientId,
  });
}

export interface Tokens {
  readonly accessToken: string;
  readonly tokenType: "DPoP" | "Bearer";
  readonly expiresIn: number;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly scope?: string;
}

/** Reads a token endpoint answer; with `expectDpop` a `Bearer` token is refused (RFC 9449 §5). */
export function parseTokenResponse(status: number, body: unknown, expectDpop: boolean): Tokens {
  const b = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
  if (status !== 200) {
    const e = b["error"];
    const c = typeof e === "string" ? oauthClass(e) : status >= 500 ? "unavailable" : "refused";
    throw new AuthError("token-refused", c);
  }
  const at = b["access_token"];
  const tt = b["token_type"];
  const exp = b["expires_in"];
  if (typeof at !== "string" || at === "" || typeof tt !== "string") {
    throw new AuthError("token-malformed");
  }
  if (typeof exp !== "number" || !Number.isSafeInteger(exp) || exp < 0) {
    throw new AuthError("token-malformed");
  }
  const lower = tt.toLowerCase();
  if (lower !== "dpop" && lower !== "bearer") throw new AuthError("token-malformed");
  const tokenType = lower === "dpop" ? "DPoP" : "Bearer";
  if (expectDpop && tokenType !== "DPoP") throw new AuthError("token-unbound");
  const text = (n: string): string | undefined => {
    const v = b[n];
    return typeof v === "string" ? v : undefined;
  };
  const refreshToken = text("refresh_token");
  const idToken = text("id_token");
  const scope = text("scope");
  return {
    accessToken: at,
    tokenType,
    expiresIn: exp,
    ...(refreshToken === undefined ? {} : { refreshToken }),
    ...(idToken === undefined ? {} : { idToken }),
    ...(scope === undefined ? {} : { scope }),
  };
}

// ---------------------------------------------------------------- DPoP (RFC 9449)

/** A DPoP key: its private half cannot leave WebCrypto (`extractable: false`). */
export interface DpopKey {
  readonly privateKey: CryptoKey;
  readonly publicJwk: {
    readonly kty: "EC";
    readonly crv: "P-256";
    readonly x: string;
    readonly y: string;
  };
  /** RFC 7638 thumbprint: `dpop_jkt` and `cnf.jkt`. */
  readonly jkt: string;
}

/** RFC 7638 thumbprint of a P-256 public JWK. */
export async function jwkThumbprint(jwk: {
  crv: string;
  kty: string;
  x: string;
  y: string;
}): Promise<string> {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return base64url(await sha256(canonical));
}

/** A fresh ES256 DPoP key with a non-extractable private key. */
export async function generateDpopKey(): Promise<DpopKey> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  if (typeof pub.x !== "string" || typeof pub.y !== "string") throw new AuthError("dpop-key");
  const publicJwk = { kty: "EC", crv: "P-256", x: pub.x, y: pub.y } as const;
  return { privateKey: pair.privateKey, publicJwk, jkt: await jwkThumbprint(publicJwk) };
}

/** `htu`: the URL without query and fragment, normalised by the URL parser (RFC 9449 §4.2). */
export function htu(url: string): string {
  const u = new URL(url);
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new AuthError("dpop-uri");
  u.search = "";
  u.hash = "";
  return u.href;
}

export interface ProofFor {
  readonly method: string;
  readonly url: string;
  readonly accessToken?: string;
  readonly nonce?: string;
  /** Unix seconds; the platform clock when absent. */
  readonly now?: number;
}

function b64json(v: unknown): string {
  return base64url(new TextEncoder().encode(JSON.stringify(v)));
}

/** A DPoP proof for one request, signed with `key`. */
export async function dpopProof(key: DpopKey, request: ProofFor): Promise<string> {
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: key.publicJwk };
  const claims: Record<string, string | number> = {
    jti: randomText(16),
    htm: request.method,
    htu: htu(request.url),
    iat: request.now ?? Math.floor(Date.now() / 1000),
  };
  if (request.accessToken !== undefined) {
    claims["ath"] = base64url(await sha256(request.accessToken));
  }
  if (request.nonce !== undefined) claims["nonce"] = request.nonce;
  const input = `${b64json(header)}.${b64json(claims)}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key.privateKey,
    new TextEncoder().encode(input),
  );
  return `${input}.${base64url(new Uint8Array(signature))}`;
}

// ---------------------------------------------------------------- storage and refresh

export interface StoredTokens {
  readonly tokens: Tokens;
  /** Unix milliseconds the access token stops being used. */
  readonly expiresAt: number;
}

/** Where tokens live. The default keeps them in memory only; a browser should not put them in `localStorage`. */
export interface TokenStore {
  get(): Promise<StoredTokens | undefined>;
  set(value: StoredTokens): Promise<void>;
  clear(): Promise<void>;
}

export class MemoryTokenStore implements TokenStore {
  #value: StoredTokens | undefined;

  get(): Promise<StoredTokens | undefined> {
    return Promise.resolve(this.#value);
  }

  set(value: StoredTokens): Promise<void> {
    this.#value = value;
    return Promise.resolve();
  }

  clear(): Promise<void> {
    this.#value = undefined;
    return Promise.resolve();
  }
}

/**
 * Refresh single-flight (P50, §9.9.3 k.6): refresh tokens rotate and a reused one ends the
 * family, so concurrent callers share one refresh. The first call starts it; calls while it runs
 * get the same promise; the next call after it settles starts a new one.
 */
export class Refresher<T> {
  #flight: Promise<T> | undefined;

  get inFlight(): boolean {
    return this.#flight !== undefined;
  }

  refresh(start: () => Promise<T>): Promise<T> {
    if (this.#flight !== undefined) return this.#flight;
    const flight: Promise<T> = Promise.resolve()
      .then(start)
      .finally(() => {
        if (this.#flight === flight) this.#flight = undefined;
      });
    this.#flight = flight;
    return flight;
  }
}

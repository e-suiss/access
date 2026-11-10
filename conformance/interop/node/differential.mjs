// T42, IDP-40, OP-155 m.3 (q), Ek B 5064, 5100
//
// The OAuth and OpenID Connect differential tests.
//
// 1. openid-client, a widely used relying party library, signs in against Access with PAR,
//    PKCE S256, DPoP and private_key_jwt, redeems the code, refreshes and reads userinfo.
// 2. Every request of the corpus below goes to Access and to oidc-provider, the reference
//    authorization server, configured with the same client. The two must refuse alike (same
//    `error`, as a 4xx answer or an error redirect). A difference fails the run unless expected.json lists it with its reason.
//    oidc-provider is the oracle here; Keycloak never is (§14.8).
//
//   node differential.mjs <issuer> <conformance/oidf dir> <expected.json> [--release]
//
// The issuer's TLS certificate comes from NODE_EXTRA_CA_CERTS; ACCESS_RESOLVE=<host>:<ip> pins
// the issuer host to an address when no DNS entry exists.

import dns from 'node:dns';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { webcrypto as crypto } from 'node:crypto';
import * as client from 'openid-client';
import Provider from 'oidc-provider';

const [issuer, oidfDir, expectedPath] = process.argv.slice(2);
const release = process.argv.includes('--release');
if (!issuer || !oidfDir || !expectedPath) {
  console.error('usage: node differential.mjs <issuer> <conformance/oidf dir> <expected.json> [--release]');
  process.exit(2);
}

if (process.env.ACCESS_RESOLVE) {
  const [host, ip] = process.env.ACCESS_RESOLVE.split(':');
  const lookup = dns.lookup;
  dns.lookup = (name, options, callback) => lookup.call(dns, name === host ? ip : name, options, callback);
}

const enc = new TextEncoder();
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const json64 = (value) => b64u(enc.encode(JSON.stringify(value)));
const now = () => Math.floor(Date.now() / 1000);
const jti = () => b64u(crypto.getRandomValues(new Uint8Array(16)));

const fapi = JSON.parse(readFileSync(`${oidfDir}/access-fapi2.json`, 'utf8'));
const plans = JSON.parse(readFileSync(`${oidfDir}/plans.json`, 'utf8'));
const redirectUri = plans.plans.find((p) => p.config === 'access-fapi2.json').redirect_uri;
const clientId = fapi.client.client_id;
const jwk = fapi.client.jwks.keys[0];
const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, kid: jwk.kid, alg: 'ES256', use: 'sig' };
const ES256 = { name: 'ECDSA', namedCurve: 'P-256' };
const signingKey = await crypto.subtle.importKey('jwk', { ...publicJwk, d: jwk.d }, ES256, false, ['sign']);
const otherKey = (await crypto.subtle.generateKey(ES256, true, ['sign', 'verify'])).privateKey;

async function jws(header, payload, key) {
  const input = `${json64(header)}.${json64(payload)}`;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(input));
  return `${input}.${b64u(new Uint8Array(sig))}`;
}

async function assertion(aud, { key = signingKey, exp = now() + 60, id = jti() } = {}) {
  return jws(
    { alg: 'ES256', kid: publicJwk.kid, typ: 'JWT' },
    { iss: clientId, sub: clientId, aud, iat: now(), exp, jti: id },
    key,
  );
}

const dpopPair = await crypto.subtle.generateKey(ES256, true, ['sign', 'verify']);
const dpopPublic = await crypto.subtle.exportKey('jwk', dpopPair.publicKey);

async function dpopProof(htm, htu, nonce) {
  return jws(
    { typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: 'EC', crv: 'P-256', x: dpopPublic.x, y: dpopPublic.y } },
    { htm, htu, iat: now(), jti: jti(), ...(nonce ? { nonce } : {}) },
    dpopPair.privateKey,
  );
}

// 1. openid-client against Access
async function relyingParty() {
  const config = await client.discovery(
    new URL(issuer),
    clientId,
    undefined,
    client.PrivateKeyJwt(signingKey, { kid: publicJwk.kid }),
  );
  const dpop = client.getDPoPHandle(config, await client.randomDPoPKeyPair('ES256'));
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const url = await client.buildAuthorizationUrlWithPAR(
    config,
    {
      redirect_uri: redirectUri,
      scope: 'openid',
      code_challenge: await client.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
      state,
    },
    { DPoP: dpop },
  );
  const jar = new Map();
  let next = url.href;
  for (let hop = 0; hop < 10 && !next.startsWith(redirectUri); hop += 1) {
    const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const r = await fetch(next, { redirect: 'manual', headers: cookie ? { cookie } : {} });
    for (const set of r.headers.getSetCookie()) {
      const [pair] = set.split(';');
      const at = pair.indexOf('=');
      jar.set(pair.slice(0, at), pair.slice(at + 1));
    }
    const location = r.headers.get('location');
    if (!location) {
      throw new Error(`the sign-in stopped at ${next} with ${r.status}: ${(await r.text()).slice(0, 300)}`);
    }
    next = new URL(location, next).href;
  }
  if (!next.startsWith(redirectUri)) {
    throw new Error(`no redirect to the client after the sign-in (${next})`);
  }
  const tokens = await client.authorizationCodeGrant(
    config,
    new URL(next),
    { pkceCodeVerifier: verifier, expectedState: state },
    undefined,
    { DPoP: dpop },
  );
  if (tokens.token_type?.toLowerCase() !== 'dpop') {
    throw new Error(`token_type ${tokens.token_type}, expected DPoP`);
  }
  const claims = tokens.claims();
  const info = await client.fetchUserInfo(config, tokens.access_token, claims.sub, { DPoP: dpop });
  if (info.sub !== claims.sub) {
    throw new Error('userinfo names another subject');
  }
  if (tokens.refresh_token) {
    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token, undefined, { DPoP: dpop });
    if (!refreshed.access_token) {
      throw new Error('the refresh gave no access token');
    }
  }
  return `signed in as ${claims.sub}, userinfo read${tokens.refresh_token ? ', refreshed' : ''}`;
}

// 2. the reference authorization server
async function reference() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const provider = new Provider(base, {
    clients: [
      {
        client_id: clientId,
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [publicJwk] },
        redirect_uris: [redirectUri],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        dpop_bound_access_tokens: true,
        require_pushed_authorization_requests: true,
      },
    ],
    clientAuthMethods: ['private_key_jwt'],
    features: {
      devInteractions: { enabled: false },
      dPoP: { enabled: true },
      pushedAuthorizationRequests: { enabled: true, requirePushedAuthorizationRequests: true },
    },
    pkce: { required: () => true },
    enabledJWA: {
      clientAuthSigningAlgValues: ['ES256'],
      dPoPSigningAlgValues: ['ES256'],
    },
  });
  provider.proxy = false;
  server.on('request', provider.callback());
  return { base, server };
}

async function discover(base) {
  const r = await fetch(`${base}/.well-known/openid-configuration`);
  if (!r.ok) {
    throw new Error(`discovery of ${base}: ${r.status}`);
  }
  return r.json();
}

function form(fields) {
  const body = new URLSearchParams();
  for (const [k, v] of fields) {
    body.append(k, v);
  }
  return body;
}

async function send(method, url, fields, headers = {}) {
  const init = { method, redirect: 'manual', headers: { ...headers } };
  if (fields) {
    init.body = form(fields);
    init.headers['content-type'] = 'application/x-www-form-urlencoded';
  }
  const r = await fetch(url, init);
  const nonce = r.headers.get('dpop-nonce');
  let error = null;
  const location = r.headers.get('location');
  if (location) {
    error = new URL(location, url).searchParams.get('error');
  } else {
    const text = await r.text();
    try {
      error = JSON.parse(text).error ?? null;
    } catch {
      error = null;
    }
  }
  return { status: r.status, error, nonce };
}

// RFC 9449 §8: a server may ask for its nonce; the request is made again with it, once, with
// fields built anew (a client assertion is single use).
async function sendDpop(method, url, fields) {
  const build = typeof fields === 'function' ? fields : async () => fields;
  const first = await send(method, url, await build(), { dpop: await dpopProof(method, url) });
  if (first.error !== 'use_dpop_nonce' || !first.nonce) {
    return first;
  }
  return send(method, url, await build(), { dpop: await dpopProof(method, url, first.nonce) });
}

const challenge = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode('x'.repeat(43)))));
const authz = (extra = []) => [
  ['client_id', clientId],
  ['response_type', 'code'],
  ['redirect_uri', redirectUri],
  ['scope', 'openid'],
  ['state', 's1'],
  ['code_challenge', challenge],
  ['code_challenge_method', 'S256'],
  ...extra,
];
const auth = async (aud, options) => [
  ['client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'],
  ['client_assertion', await assertion(aud, options)],
];
const without = (fields, name) => fields.filter(([k]) => k !== name);
const replace = (fields, name, value) => fields.map(([k, v]) => [k, k === name ? value : v]);

// The corpus: each case builds one request for an authorization server's metadata.
const CASES = {
  'par-without-client-authentication': async (m) => ['POST', m.pushed_authorization_request_endpoint, authz()],
  'par-assertion-signed-by-another-key': async (m) => [
    'POST', m.pushed_authorization_request_endpoint, [...authz(), ...(await auth(m.issuer, { key: otherKey }))],
  ],
  'par-assertion-for-another-audience': async (m) => [
    'POST', m.pushed_authorization_request_endpoint, [...authz(), ...(await auth('https://elsewhere.example'))],
  ],
  'par-assertion-expired': async (m) => [
    'POST', m.pushed_authorization_request_endpoint, [...authz(), ...(await auth(m.issuer, { exp: now() - 600 }))],
  ],
  'par-without-pkce': async (m) => [
    'POST', m.pushed_authorization_request_endpoint,
    [...without(without(authz(), 'code_challenge'), 'code_challenge_method'), ...(await auth(m.issuer))],
  ],
  'par-pkce-plain': async (m) => [
    'POST', m.pushed_authorization_request_endpoint,
    [...replace(authz(), 'code_challenge_method', 'plain'), ...(await auth(m.issuer))],
  ],
  'par-unregistered-redirect-uri': async (m) => [
    'POST', m.pushed_authorization_request_endpoint,
    [...replace(authz(), 'redirect_uri', 'https://attacker.example/cb'), ...(await auth(m.issuer))],
  ],
  'par-response-type-token': async (m) => [
    'POST', m.pushed_authorization_request_endpoint,
    [...replace(authz(), 'response_type', 'token'), ...(await auth(m.issuer))],
  ],
  'par-with-request-uri': async (m) => [
    'POST', m.pushed_authorization_request_endpoint,
    [...authz([['request_uri', 'urn:ietf:params:oauth:request_uri:x']]), ...(await auth(m.issuer))],
  ],
  'par-duplicate-parameter': async (m) => [
    'POST', m.pushed_authorization_request_endpoint,
    [...authz([['scope', 'openid']]), ...(await auth(m.issuer))],
  ],
  'authorize-without-par': async (m) => ['GET', `${m.authorization_endpoint}?${form(authz())}`, null],
  'token-unknown-grant-type': async (m) => [
    'POST', m.token_endpoint, [['grant_type', 'urn:example:unknown'], ...(await auth(m.issuer))],
  ],
  'token-without-grant-type': async (m) => ['POST', m.token_endpoint, [...(await auth(m.issuer))]],
  'token-unknown-code': async (m) => [
    'POST', m.token_endpoint,
    async () => [
      ['grant_type', 'authorization_code'],
      ['code', 'not-a-code'],
      ['redirect_uri', redirectUri],
      ['code_verifier', 'x'.repeat(43)],
      ...(await auth(m.issuer)),
    ],
    { dpop: true },
  ],
  'token-assertion-replayed': async (m) => {
    const replayed = await assertion(m.issuer, { id: 'replayed-jti' });
    const fields = [
      ['grant_type', 'authorization_code'],
      ['code', 'not-a-code'],
      ['redirect_uri', redirectUri],
      ['code_verifier', 'x'.repeat(43)],
      ['client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'],
      ['client_assertion', replayed],
    ];
    await sendDpop('POST', m.token_endpoint, fields);
    return ['POST', m.token_endpoint, fields, { dpop: true }];
  },
};

async function run(metadata, name) {
  const [method, url, fields, options] = await CASES[name](metadata);
  return options?.dpop ? sendDpop(method, url, fields) : send(method, url, fields);
}

const expected = JSON.parse(readFileSync(expectedPath, 'utf8'));
const recorded = expected.recorded === true;
const known = expected.differences ?? {};
let failed = false;

try {
  console.log(`ok    openid-client: ${await relyingParty()}`);
} catch (e) {
  failed = true;
  console.log(`FAIL  openid-client: ${e.stack ?? e}`);
}

const { base, server } = await reference();
const access = await discover(issuer);
const oracle = await discover(base);
const candidate = {};
const bad = [];
for (const name of Object.keys(CASES)) {
  const a = await run(access, name);
  const o = await run(oracle, name);
  const refused = (r) => r.status >= 400 || r.error !== null;
  const same = a.error === o.error && refused(a) && refused(o);
  const line = `Access ${a.status} ${a.error ?? '-'}, oidc-provider ${o.status} ${o.error ?? '-'}`;
  if (same) {
    console.log(`ok    ${name}: ${line}`);
    if (known[name]) {
      console.log(`::warning::${name} no longer differs; remove it from expected.json`);
    }
    continue;
  }
  candidate[name] = known[name] ?? `first run: ${line}`;
  if (!refused(a)) {
    bad.push(`${name}: Access accepted what the reference refuses (${line})`);
  } else if (known[name]) {
    console.log(`known ${name}: ${line} (${known[name]})`);
  } else if (recorded) {
    bad.push(`${name}: ${line}`);
  } else {
    console.log(`::warning::${name}: first run, ${line}`);
  }
}
server.close();

if (!recorded) {
  console.log('expected.json is not recorded yet; record this list after review:');
  console.log(JSON.stringify({ recorded: true, differences: candidate }, null, 2));
  if (release) {
    bad.push('a release needs a recorded expected.json (OP-155 m.3 (q))');
  }
}
for (const line of bad) {
  console.log(`::error::${line}`);
}
console.log(`${Object.keys(CASES).length - bad.length} of ${Object.keys(CASES).length} cases agree or differ as expected`);
process.exit(failed || bad.length > 0 ? 1 : 0);

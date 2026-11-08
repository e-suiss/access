// T41, OP-151 m.3 (g)
import { describe, expect, it } from "vitest";

import {
  AuthError,
  MemoryTokenStore,
  Refresher,
  authorizationRequest,
  callbackCode,
  dpopProof,
  generateDpopKey,
  htu,
  jwkThumbprint,
  oauthClass,
  parseMetadata,
  parseTokenResponse,
  pkceChallenge,
  refreshFailedText,
  SIGN_IN_AGAIN,
  tokenRequestBody,
} from "./auth.js";
import { reason, reasons } from "./reason.js";

const ISSUER = "https://login.example/realms/acme";
const META = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  jwks_uri: `${ISSUER}/jwks`,
  code_challenge_methods_supported: ["S256"],
  authorization_response_iss_parameter_supported: true,
};

function code(f: () => unknown): string | undefined {
  try {
    f();
    return undefined;
  } catch (e) {
    return e instanceof AuthError ? e.code : String(e);
  }
}

function b64urlJson(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
}

describe("auth", () => {
  // RFC 7636 Appendix B
  it("computes the S256 challenge", async () => {
    expect(await pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
    await expect(pkceChallenge("short")).rejects.toThrow("pkce-verifier");
  });

  // RFC 8414 §3.3, RFC 9700 §2.1.1
  it("refuses another issuer, no S256 and non-https endpoints", () => {
    expect(parseMetadata(META, ISSUER).tokenEndpoint).toBe(`${ISSUER}/token`);
    expect(code(() => parseMetadata(META, "https://evil.example"))).toBe("discovery-issuer");
    expect(
      code(() => parseMetadata({ ...META, code_challenge_methods_supported: ["plain"] }, ISSUER)),
    ).toBe("discovery-pkce");
    expect(
      code(() => parseMetadata({ ...META, token_endpoint: "http://login.example/token" }, ISSUER)),
    ).toBe("discovery-endpoint:token_endpoint");
  });

  // RFC 9700 §4.7, RFC 9207, P15
  it("accepts a callback only with this state, this issuer and a code", async () => {
    const meta = parseMetadata(META, ISSUER);
    const { url, pending } = await authorizationRequest(
      meta,
      { clientId: "c-1", redirectUri: "https://app.example/cb", scope: "profile" },
      "jkt-1",
    );
    const q = new URL(url).searchParams;
    expect(q.get("code_challenge_method")).toBe("S256");
    expect(q.get("scope")).toBe("openid profile");
    expect(q.get("dpop_jkt")).toBe("jkt-1");
    expect(q.get("code_challenge")).toBe(await pkceChallenge(pending.verifier));
    const ok = new URLSearchParams({ code: "c", state: pending.state, iss: ISSUER });
    expect(callbackCode(pending, ok)).toBe("c");
    expect(code(() => callbackCode(pending, `code=c&state=x&iss=${ISSUER}`))).toBe(
      "callback-state",
    );
    expect(code(() => callbackCode(pending, `code=c&state=${pending.state}`))).toBe(
      "callback-issuer",
    );
    const refused = new URLSearchParams({ error: "new_kind", state: pending.state, iss: ISSUER });
    try {
      callbackCode(pending, refused);
    } catch (e) {
      expect((e as AuthError).oauthClass).toBe("refused");
    }
    expect(tokenRequestBody(pending, "c").get("code_verifier")).toBe(pending.verifier);
  });

  // RFC 9449 §5, P15
  it("refuses an unbound token where DPoP was asked and classes unknown errors as refused", () => {
    const ok = { access_token: "at", token_type: "DPoP", expires_in: 300 };
    expect(parseTokenResponse(200, ok, true).tokenType).toBe("DPoP");
    expect(code(() => parseTokenResponse(200, { ...ok, token_type: "Bearer" }, true))).toBe(
      "token-unbound",
    );
    for (const [status, body, want] of [
      [400, { error: "invalid_grant" }, "invalid_grant"],
      [400, { error: "brand_new" }, "refused"],
      [503, "<html>", "unavailable"],
    ] as const) {
      try {
        parseTokenResponse(status, body, true);
        expect.unreachable();
      } catch (e) {
        expect((e as AuthError).oauthClass).toBe(want);
      }
    }
    expect(oauthClass("__proto__")).toBe("refused");
  });

  // RFC 9449 §4.2, §4.3
  it("builds a DPoP proof that verifies with the public key", async () => {
    const key = await generateDpopKey();
    expect(key.privateKey.extractable).toBe(false);
    expect(key.jkt).toBe(await jwkThumbprint(key.publicJwk));
    const proof = await dpopProof(key, {
      method: "GET",
      url: "https://RS.example:443/doors/1?x=1#f",
      accessToken: "at",
      nonce: "n-1",
      now: 1_800_000_000,
    });
    const [h, p, s] = proof.split(".");
    if (h === undefined || p === undefined || s === undefined) throw new Error("shape");
    expect(b64urlJson(h)).toMatchObject({ typ: "dpop+jwt", alg: "ES256" });
    const claims = b64urlJson(p);
    expect(claims).toMatchObject({ htm: "GET", htu: "https://rs.example/doors/1", nonce: "n-1" });
    expect(typeof claims["ath"]).toBe("string");
    const pub = await crypto.subtle.importKey(
      "jwk",
      key.publicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pub,
      Buffer.from(s, "base64url"),
      new TextEncoder().encode(`${h}.${p}`),
    );
    expect(valid).toBe(true);
    expect(code(() => htu("ftp://x.example/"))).toBe("dpop-uri");
  });

  it("keeps tokens in memory by default", async () => {
    const store = new MemoryTokenStore();
    expect(await store.get()).toBeUndefined();
    await store.set({
      tokens: parseTokenResponse(
        200,
        { access_token: "a", token_type: "DPoP", expires_in: 1 },
        true,
      ),
      expiresAt: 1,
    });
    expect((await store.get())?.tokens.accessToken).toBe("a");
    await store.clear();
    expect(await store.get()).toBeUndefined();
  });

  // P50, §9.9.3 k.6: N concurrent callers make one network call and get one result
  it("runs one refresh for concurrent callers", async () => {
    const r = new Refresher<string>();
    let calls = 0;
    let open: (v: string) => void = () => undefined;
    const gate = new Promise<string>((resolve) => {
      open = resolve;
    });
    const start = (): Promise<string> => {
      calls += 1;
      return gate;
    };
    const all = Array.from({ length: 16 }, () => r.refresh(start));
    expect(r.inFlight).toBe(true);
    open("rotated-1");
    expect(await Promise.all(all)).toEqual(Array(16).fill("rotated-1"));
    expect(calls).toBe(1);
    expect(r.inFlight).toBe(false);
    expect(await r.refresh(() => Promise.resolve("rotated-2"))).toBe("rotated-2");
  });

  // P50: a failed refresh fails every waiter and the next call starts again
  it("fails every waiter of a failed refresh, even one that throws at once", async () => {
    const r = new Refresher<string>();
    const a = r.refresh(() => {
      throw new AuthError("token-refused", "invalid_grant");
    });
    const b = r.refresh(() => Promise.resolve("not-run"));
    await expect(a).rejects.toThrow("token-refused");
    await expect(b).rejects.toThrow("token-refused");
    expect(await r.refresh(() => Promise.resolve("fresh"))).toBe("fresh");
  });

  // P15: unknown subcode → parent class; no unknown class
  it("reads an unknown subcode as its parent class", () => {
    expect(reason("ended", "ended/revoked")).toEqual({ class: "ended", subcode: "ended/revoked" });
    expect(reason("ended", "ended/new-in-v9")).toEqual({ class: "ended" });
    expect(reason("restricted", "ended/revoked")).toEqual({ class: "restricted" });
    expect(reason("restricted", "restricted/policy:p-1").subcode).toBe("restricted/policy:p-1");
    expect(() => reason("new-class")).toThrow("unknown-class");
    expect(
      reasons({
        context: { blockers: [{ class: "budget-exhausted", subcode: "budget-exhausted/x" }] },
      }),
    ).toEqual([{ class: "budget-exhausted" }]);
  });
});

// §8.13
describe("a failed refresh", () => {
  it("says only to sign in again", () => {
    const expired = new AuthError("invalid_grant", oauthClass("invalid_grant"));
    expect(refreshFailedText(expired)).toBe("Please sign in again to continue.");
    expect(refreshFailedText(new AuthError("login_required", oauthClass("login_required")))).toBe(
      SIGN_IN_AGAIN,
    );
    expect(refreshFailedText(new AuthError("temporarily_unavailable", "unavailable"))).toBe(
      undefined,
    );
  });
});

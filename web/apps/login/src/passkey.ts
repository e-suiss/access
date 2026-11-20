import * as v from "valibot";

import type { PasskeyOptions, PasskeySignal } from "./contract.js";

type Json = Record<string, unknown>;

// OP-159 m.46 (f)
const TRANSPORTS: ReadonlySet<string> = new Set(["ble", "hybrid", "internal", "nfc", "usb"]);

function isTransport(t: string): t is AuthenticatorTransport {
  return TRANSPORTS.has(t);
}

const optional = <S extends v.GenericSchema>(s: S) => v.fallback(v.optional(s), undefined);

const Descriptor = v.looseObject({
  id: v.string(),
  transports: optional(v.array(v.string())),
});

const Verification = v.picklist(["required", "preferred", "discouraged"]);

const RequestJson = v.looseObject({
  challenge: v.string(),
  rpId: optional(v.string()),
  allowCredentials: v.optional(v.unknown()),
  userVerification: optional(Verification),
  timeout: optional(v.number()),
});

const CreationJson = v.looseObject({
  rp: v.looseObject({ name: v.string(), id: optional(v.string()) }),
  user: v.looseObject({ id: v.string(), name: v.string(), displayName: v.string() }),
  challenge: v.string(),
  pubKeyCredParams: v.fallback(
    v.array(v.looseObject({ type: v.literal("public-key"), alg: v.number() })),
    [],
  ),
  excludeCredentials: v.optional(v.unknown()),
  authenticatorSelection: optional(
    v.looseObject({
      authenticatorAttachment: optional(v.picklist(["platform", "cross-platform"])),
      residentKey: optional(v.picklist(["discouraged", "preferred", "required"])),
      requireResidentKey: optional(v.boolean()),
      userVerification: optional(Verification),
    }),
  ),
  extensions: optional(v.record(v.string(), v.unknown())),
  timeout: optional(v.number()),
});

export function fromBase64url(text: string): ArrayBuffer {
  const b64 = text.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "="));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function toBase64url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] {
  if (!Array.isArray(list)) return [];
  return list.flatMap((item: unknown) => {
    const d = v.safeParse(Descriptor, item);
    if (!d.success) return [];
    const transports = d.output.transports?.filter(isTransport);
    return [
      {
        type: "public-key" as const,
        id: fromBase64url(d.output.id),
        ...(transports === undefined ? {} : { transports }),
      },
    ];
  });
}

/** Platform authenticator first; cross-device QR (hybrid) only as the last resort (TN-99). */
async function hints(options: PasskeyOptions): Promise<string[]> {
  const given = options["hints"];
  if (Array.isArray(given) && given.length > 0) return given.map(String);
  const platform = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(
    () => false,
  );
  return platform ? ["client-device", "security-key", "hybrid"] : ["security-key", "hybrid"];
}

async function requestOptions(options: PasskeyOptions): Promise<PublicKeyCredentialRequestOptions> {
  const json = {
    ...options,
    hints: await hints(options),
  } as unknown as PublicKeyCredentialRequestOptionsJSON;
  if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
    return PublicKeyCredential.parseRequestOptionsFromJSON(json);
  }
  const o = v.parse(RequestJson, options);
  return {
    challenge: fromBase64url(o.challenge),
    ...(o.rpId === undefined ? {} : { rpId: o.rpId }),
    allowCredentials: descriptors(o.allowCredentials),
    ...(o.userVerification === undefined ? {} : { userVerification: o.userVerification }),
    ...(o.timeout === undefined ? {} : { timeout: o.timeout }),
  };
}

async function creationOptions(
  options: PasskeyOptions,
): Promise<PublicKeyCredentialCreationOptions> {
  const json = {
    ...options,
    hints: await hints(options),
  } as unknown as PublicKeyCredentialCreationOptionsJSON;
  if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
    return PublicKeyCredential.parseCreationOptionsFromJSON(json);
  }
  const o = v.parse(CreationJson, options);
  const selection = o.authenticatorSelection;
  return {
    rp: { name: o.rp.name, ...(o.rp.id === undefined ? {} : { id: o.rp.id }) },
    user: { id: fromBase64url(o.user.id), name: o.user.name, displayName: o.user.displayName },
    challenge: fromBase64url(o.challenge),
    pubKeyCredParams: o.pubKeyCredParams,
    excludeCredentials: descriptors(o.excludeCredentials),
    ...(selection === undefined
      ? {}
      : {
          authenticatorSelection: {
            ...(selection.authenticatorAttachment === undefined
              ? {}
              : { authenticatorAttachment: selection.authenticatorAttachment }),
            ...(selection.residentKey === undefined ? {} : { residentKey: selection.residentKey }),
            ...(selection.requireResidentKey === undefined
              ? {}
              : { requireResidentKey: selection.requireResidentKey }),
            ...(selection.userVerification === undefined
              ? {}
              : { userVerification: selection.userVerification }),
          },
        }),
    attestation: "none",
    ...(o.extensions === undefined ? {} : { extensions: o.extensions }),
    ...(o.timeout === undefined ? {} : { timeout: o.timeout }),
  };
}

function credentialJson(credential: PublicKeyCredential): string {
  if (typeof credential.toJSON === "function") return JSON.stringify(credential.toJSON());
  const r = credential.response;
  const response: Json = { clientDataJSON: toBase64url(r.clientDataJSON) };
  if (r instanceof AuthenticatorAssertionResponse) {
    response["authenticatorData"] = toBase64url(r.authenticatorData);
    response["signature"] = toBase64url(r.signature);
    if (r.userHandle !== null) response["userHandle"] = toBase64url(r.userHandle);
  } else if (r instanceof AuthenticatorAttestationResponse) {
    response["attestationObject"] = toBase64url(r.attestationObject);
    response["transports"] = r.getTransports();
  }
  return JSON.stringify({
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response,
    clientExtensionResults: credential.getClientExtensionResults(),
  });
}

/** TN-164: whether this browser can use passkeys at all. */
export function passkeysSupported(): boolean {
  return (
    typeof window.PublicKeyCredential === "function" &&
    typeof navigator.credentials?.get === "function"
  );
}

/**
 * TN-164: a passkey ceremony's end. Browsers report a dismissed prompt and a timed-out one alike
 * (`NotAllowedError`), so both are `cancelled`; anything else is `failed`.
 */
export type PasskeyResult =
  | { readonly kind: "credential"; readonly json: string }
  | { readonly kind: "cancelled" }
  | { readonly kind: "failed" };

const CANCELLED: ReadonlySet<string> = new Set(["NotAllowedError", "AbortError"]);

/** `navigator.credentials.get`, telling a cancelled ceremony from a failed one (TN-164). */
export async function askPasskey(
  options: PasskeyOptions,
  mediation: "conditional" | undefined,
  signal: AbortSignal,
): Promise<PasskeyResult> {
  try {
    const credential = await navigator.credentials.get({
      publicKey: await requestOptions(options),
      signal,
      ...(mediation === undefined ? {} : { mediation }),
    });
    return credential instanceof PublicKeyCredential
      ? { kind: "credential", json: credentialJson(credential) }
      : { kind: "cancelled" };
  } catch (e) {
    if (signal.aborted) return { kind: "cancelled" };
    return e instanceof DOMException && CANCELLED.has(e.name)
      ? { kind: "cancelled" }
      : { kind: "failed" };
  }
}

/** `navigator.credentials.get`; `null` when the user cancelled or the ceremony was aborted. */
export async function getPasskey(
  options: PasskeyOptions,
  mediation: "conditional" | undefined,
  signal: AbortSignal,
): Promise<string | null> {
  const result = await askPasskey(options, mediation, signal);
  return result.kind === "credential" ? result.json : null;
}

/** `navigator.credentials.create`; `null` when declined or unavailable. */
export async function createPasskey(
  options: PasskeyOptions,
  mediation: "conditional" | undefined,
  signal: AbortSignal,
): Promise<string | null> {
  try {
    const credential = await navigator.credentials.create({
      publicKey: await creationOptions(options),
      signal,
      ...(mediation === undefined
        ? {}
        : { mediation: mediation as CredentialMediationRequirement }),
    });
    return credential instanceof PublicKeyCredential ? credentialJson(credential) : null;
  } catch {
    return null;
  }
}

export async function conditionalGetAvailable(): Promise<boolean> {
  try {
    return (
      typeof PublicKeyCredential === "function" &&
      typeof PublicKeyCredential.isConditionalMediationAvailable === "function" &&
      (await PublicKeyCredential.isConditionalMediationAvailable())
    );
  } catch {
    return false;
  }
}

export async function conditionalCreateAvailable(): Promise<boolean> {
  try {
    if (typeof PublicKeyCredential.getClientCapabilities !== "function") return false;
    const capabilities = await PublicKeyCredential.getClientCapabilities();
    return capabilities["conditionalCreate"] === true;
  } catch {
    return false;
  }
}

interface SignalApi {
  signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void>;
  signalAllAcceptedCredentials?: (o: {
    rpId: string;
    userId: string;
    allAcceptedCredentialIds: readonly string[];
  }) => Promise<void>;
  signalCurrentUserDetails?: (o: {
    rpId: string;
    userId: string;
    name: string;
    displayName: string;
  }) => Promise<void>;
}

/** Makes a Signal API call where the browser has it (TN-97, §10.2.4). */
export async function sendSignal(signal: PasskeySignal): Promise<void> {
  if (typeof PublicKeyCredential !== "function") return;
  const api = PublicKeyCredential as unknown as SignalApi;
  try {
    switch (signal.kind) {
      case "unknown_credential":
        await api.signalUnknownCredential?.({
          rpId: signal.rp_id,
          credentialId: signal.credential_id,
        });
        break;
      case "all_accepted_credentials":
        await api.signalAllAcceptedCredentials?.({
          rpId: signal.rp_id,
          userId: signal.user_id,
          allAcceptedCredentialIds: signal.all_accepted_credential_ids,
        });
        break;
      case "current_user_details":
        await api.signalCurrentUserDetails?.({
          rpId: signal.rp_id,
          userId: signal.user_id,
          name: signal.name,
          displayName: signal.display_name,
        });
        break;
    }
  } catch {
    return;
  }
}

import type { PasskeyOptions, PasskeySignal } from "./contract.js";

type Json = Record<string, unknown>;

function isRecord(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

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
  return list.filter(isRecord).map((d) => ({
    type: "public-key",
    id: fromBase64url(String(d["id"])),
    ...(Array.isArray(d["transports"])
      ? { transports: d["transports"] as AuthenticatorTransport[] }
      : {}),
  }));
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
  const o = options as Json;
  return {
    challenge: fromBase64url(String(o["challenge"])),
    ...(typeof o["rpId"] === "string" ? { rpId: o["rpId"] } : {}),
    allowCredentials: descriptors(o["allowCredentials"]),
    ...(typeof o["userVerification"] === "string"
      ? { userVerification: o["userVerification"] as UserVerificationRequirement }
      : {}),
    ...(typeof o["timeout"] === "number" ? { timeout: o["timeout"] } : {}),
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
  const o = options as Json;
  const rp = isRecord(o["rp"]) ? o["rp"] : {};
  const user = isRecord(o["user"]) ? o["user"] : {};
  return {
    rp: { name: String(rp["name"]), ...(typeof rp["id"] === "string" ? { id: rp["id"] } : {}) },
    user: {
      id: fromBase64url(String(user["id"])),
      name: String(user["name"]),
      displayName: String(user["displayName"]),
    },
    challenge: fromBase64url(String(o["challenge"])),
    pubKeyCredParams: Array.isArray(o["pubKeyCredParams"])
      ? (o["pubKeyCredParams"] as PublicKeyCredentialParameters[])
      : [],
    excludeCredentials: descriptors(o["excludeCredentials"]),
    ...(isRecord(o["authenticatorSelection"])
      ? { authenticatorSelection: o["authenticatorSelection"] }
      : {}),
    attestation: "none",
    ...(isRecord(o["extensions"]) ? { extensions: o["extensions"] } : {}),
    ...(typeof o["timeout"] === "number" ? { timeout: o["timeout"] } : {}),
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

/** `navigator.credentials.get`; `null` when the user cancelled or the ceremony was aborted. */
export async function getPasskey(
  options: PasskeyOptions,
  mediation: "conditional" | undefined,
  signal: AbortSignal,
): Promise<string | null> {
  try {
    const credential = await navigator.credentials.get({
      publicKey: await requestOptions(options),
      signal,
      ...(mediation === undefined ? {} : { mediation }),
    });
    return credential instanceof PublicKeyCredential ? credentialJson(credential) : null;
  } catch {
    return null;
  }
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

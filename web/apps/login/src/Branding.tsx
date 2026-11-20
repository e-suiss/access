// TN-106, OP-153 m.3 (t), §14.3: branding is data; the logo is an image from an origin the
// environment's CSP allows, drawn with <img> only, so an SVG cannot run anything; no upload exists.
// OP-159 m.47 (b), TN-138: the branding also says the environment's kind; a primary environment
// names its tenant, whose administrators sign in there.
import { useEffect, useState } from "react";
import * as v from "valibot";

import { under } from "./base.js";
import { getJson } from "./http.js";

// OP-159 m.46 (f)
/** `GET /v1/login/branding`. */
const BrandingData = v.looseObject({
  display_name: v.nullish(v.string(), null),
  logo_uri: v.nullish(v.string(), null),
  environment: v.exactOptional(
    v.looseObject({
      kind: v.picklist(["standard", "primary"]),
      tenant_name: v.nullish(v.string()),
      display_name: v.nullish(v.string()),
    }),
  ),
  // TN-168
  sign_in: v.exactOptional(
    v.looseObject({
      identifier: v.picklist([
        "email",
        "username",
        "email_or_username",
        "phone",
        "email_or_phone",
        "username_or_phone",
        "any",
      ]),
      secret: v.picklist(["password", "pin"]),
      email_code: v.boolean(),
    }),
  ),
});

export type BrandingData = Readonly<v.InferOutput<typeof BrandingData>>;

export const brandingPath = "/v1/login/branding";

let read: Promise<BrandingData | null> | undefined;

/** The environment's branding, read once for the page. */
function branding(): Promise<BrandingData | null> {
  read ??= getJson(brandingPath, BrandingData).then((a) => (a.ok ? a.body : null));
  return read;
}

/** The environment's branding once it is read; `null` before, or when there is none. */
export function useBranding(): BrandingData | null {
  const [brand, setBrand] = useState<BrandingData | null>(null);
  useEffect(() => {
    let live = true;
    void branding().then((b) => {
      if (live) setBrand(b);
    });
    return () => {
      live = false;
    };
  }, []);
  return brand;
}

/** The environment's theme sheet: CSS custom properties the server writes from validated colours. */
export function linkTheme(): void {
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = under("/login/theme.css");
  document.head.append(link);
}

function httpsUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

export function Branding() {
  const brand = useBranding();
  if (brand === null) return null;
  const name = typeof brand.display_name === "string" ? brand.display_name : null;
  const logo = httpsUrl(brand.logo_uri) ? brand.logo_uri : null;
  if (name === null && logo === null) return null;
  return (
    <header className="flex items-center gap-2 text-lg font-semibold" data-testid="brand">
      {logo !== null && (
        <img
          src={logo}
          alt=""
          className="brand-logo max-h-10 max-w-40"
          referrerPolicy="no-referrer"
        />
      )}
      {name !== null && <span>{name}</span>}
    </header>
  );
}

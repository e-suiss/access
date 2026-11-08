// TN-106, OP-153 m.3 (t), §14.3: branding is data; the logo is an image from an origin the
// realm's CSP allows, drawn with <img> only, so an SVG cannot run anything; no upload exists.
import { useEffect, useState } from "react";

import { under } from "./base.js";
import { getJson } from "./http.js";

/** `GET /v1/login/branding`. */
export interface BrandingData {
  readonly display_name: string | null;
  readonly logo_uri: string | null;
}

export const brandingPath = "/v1/login/branding";

/** The realm's theme sheet: CSS custom properties the server writes from validated colours. */
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
  const [brand, setBrand] = useState<BrandingData | null>(null);
  useEffect(() => {
    void getJson<BrandingData>(brandingPath).then((a) => {
      if (a.ok) setBrand(a.body);
    });
  }, []);
  if (brand === null) return null;
  const name = typeof brand.display_name === "string" ? brand.display_name : null;
  const logo = httpsUrl(brand.logo_uri) ? brand.logo_uri : null;
  if (name === null && logo === null) return null;
  return (
    <header className="brand" data-testid="brand">
      {logo !== null && (
        <img src={logo} alt="" className="brand-logo" referrerPolicy="no-referrer" />
      )}
      {name !== null && <span className="brand-name">{name}</span>}
    </header>
  );
}

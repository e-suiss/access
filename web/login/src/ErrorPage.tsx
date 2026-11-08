// X-L8, X41, §8.10, §8.15.2, OP-153 m.3 (jj): an error names whose it is and carries a short
// reference; the raw error code is never shown.
import { useEffect, useRef } from "react";

import { t } from "./i18n.js";

export type Owner = "app" | "upstream" | "access";

/** The reference: the first 30 bits of the request id in Crockford base32, `XXXX-XX`. */
export function reference(value: string | null): string | null {
  if (value === null) return null;
  const v = value.toUpperCase();
  return /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{2}$/.test(v) ? v : null;
}

/** The text id an error shows: the person's own choice, else its owner's line. */
export function errorText(error: string | null, owner: string | null): string {
  if (error === "access_denied") return "page.access_denied";
  if (error === "temporarily_unavailable") return "error.access_owner";
  switch (owner) {
    case "app":
      return "error.app_owner";
    case "upstream":
      return "error.upstream_owner";
    default:
      return "error.access_owner";
  }
}

export function ErrorPage() {
  const params = new URL(window.location.href).searchParams;
  const id = errorText(params.get("error"), params.get("owner"));
  const ref = reference(params.get("ref"));
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    title.current?.focus();
  }, []);
  return (
    <div className="card">
      <section aria-labelledby="error-heading" data-kind="error">
        <h1 id="error-heading" ref={title} tabIndex={-1}>
          {id === "page.access_denied" ? t("page.not_continued_title") : t("page.error_title")}
        </h1>
        <p role="alert" data-message-id={id}>
          {t(id)}
        </p>
        {ref !== null && (
          <p className="reference" data-testid="reference">
            {t("error.reference")}: <span dir="ltr">{ref}</span>
          </p>
        )}
      </section>
    </div>
  );
}

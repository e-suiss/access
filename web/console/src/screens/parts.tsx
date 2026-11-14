// §8.13, E25, TN-131: what every section screen shares. A read that fails shows that it failed
// and nothing else; nothing is ever guessed or shown as allowed. Strings render as text nodes.
import { useCallback, useEffect, useRef, useState, type ReactElement, type ReactNode } from "react";

import { Badge } from "@suiss/access-ui/components/ui/badge";
import { Card, CardContent, CardHeader } from "@suiss/access-ui/components/ui/card";
import {
  Field as FieldRoot,
  FieldDescription,
  FieldLabel,
} from "@suiss/access-ui/components/ui/field";
import { Input } from "@suiss/access-ui/components/ui/input";

import { t, type Key } from "../i18n/index.js";
import { Problem, type SessionInfo } from "../lib/api.js";
import type { Confirm, Instance } from "../lib/instance.js";
import { NotSigned } from "../lib/instance.js";
import type { Screen } from "../lib/sections.js";
import { BULLETS, Busy, Failure, HINT, MONO } from "../ui.js";

/** What a section screen works with. */
export interface Ctx {
  readonly session: SessionInfo;
  readonly instance: Instance;
  readonly confirm: Confirm;
  readonly screens: ReadonlySet<Screen>;
}

export type Loaded<T> =
  | { readonly status: "idle" }
  | { readonly status: "busy" }
  | { readonly status: "done"; readonly value: T }
  | { readonly status: "failed"; readonly key: Key };

/** The text for a failed read or change: refused by authority, not signed, or no answer. */
export function failureKey(e: unknown): Key {
  if (e instanceof NotSigned) return e.message === "mismatch" ? "signatureMismatch" : "notChanged";
  if (e instanceof Problem && (e.status === 401 || e.status === 403)) return "readRefused";
  return "readFailed";
}

/** Runs `f` on demand; the last call wins. */
export function useRun<T>(): readonly [Loaded<T>, (f: () => Promise<T>) => void] {
  const [state, setState] = useState<Loaded<T>>({ status: "idle" });
  const seq = useRef(0);
  const run = useCallback((f: () => Promise<T>) => {
    seq.current += 1;
    const mine = seq.current;
    setState({ status: "busy" });
    f().then(
      (value) => {
        if (seq.current === mine) setState({ status: "done", value });
      },
      (e: unknown) => {
        if (seq.current === mine) setState({ status: "failed", key: failureKey(e) });
      },
    );
  }, []);
  return [state, run] as const;
}

/** Runs `f` once on mount. */
export function useLoad<T>(f: () => Promise<T>): Loaded<T> {
  const [state, run] = useRun<T>();
  const first = useRef(f);
  useEffect(() => {
    run(first.current);
  }, [run]);
  return state;
}

/** The busy, failed and done states of `l`; `children` renders the value. */
export function Show<T>({
  l,
  children,
}: {
  readonly l: Loaded<T>;
  readonly children: (value: T) => ReactNode;
}): ReactElement | null {
  if (l.status === "idle") return null;
  if (l.status === "busy") return <Busy />;
  if (l.status === "failed") return <Failure>{t(l.key)}</Failure>;
  return <>{children(l.value)}</>;
}

export function Panel({
  id,
  title,
  children,
}: {
  readonly id: string;
  readonly title: string;
  readonly children: ReactNode;
}): ReactElement {
  return (
    <section aria-labelledby={`${id}-title`}>
      <Card className="gap-4">
        <CardHeader>
          <h3 id={`${id}-title`} className="text-base font-semibold">
            {title}
          </h3>
        </CardHeader>
        <CardContent className="flex min-w-0 flex-col gap-4">{children}</CardContent>
      </Card>
    </section>
  );
}

/** E-2, §8.17.10.4: every advisory answer says so. */
export function Advisory(): ReactElement {
  return (
    <Badge variant="outline" className="self-start" data-testid="advisory">
      {t("advisory")}
    </Badge>
  );
}

export function Field({
  id,
  label,
  value,
  onChange,
  hint,
  type = "text",
}: {
  readonly id: string;
  readonly label: string;
  readonly value: string;
  readonly onChange: (v: string) => void;
  readonly hint?: string;
  readonly type?: "text" | "number";
}): ReactElement {
  return (
    <FieldRoot className="max-w-xl gap-2">
      <FieldLabel htmlFor={id} className="text-sm">
        {label}
      </FieldLabel>
      <Input
        id={id}
        type={type}
        size="md"
        value={value}
        aria-describedby={hint === undefined ? undefined : `${id}-hint`}
        onChange={(e) => {
          onChange(e.target.value);
        }}
      />
      {hint !== undefined && <FieldDescription id={`${id}-hint`}>{hint}</FieldDescription>}
    </FieldRoot>
  );
}

/** A time from Unix milliseconds, or the text as given. */
export function at(ms: number | string | null | undefined): string {
  if (ms === null || ms === undefined) return "";
  const n = typeof ms === "number" ? ms : Date.parse(ms);
  return Number.isFinite(n) ? new Date(n).toISOString() : String(ms);
}

/** The disclosure-aware count line of a search page (OP-151 m.8 (g)). */
export function PageCount({
  page,
  shown,
}: {
  readonly page: { readonly total?: number; readonly has_more?: boolean };
  readonly shown: number;
}): ReactElement {
  if (page.total !== undefined) {
    return (
      <p data-testid="result-count" className={HINT}>
        {page.total === 0 ? t("resultsNone") : t("resultsTotal", { n: String(page.total) })}
      </p>
    );
  }
  if (page.has_more === true)
    return (
      <p data-testid="result-count" className={HINT}>
        {t("resultsMore")}
      </p>
    );
  return (
    <p data-testid="result-count" className={HINT}>
      {shown === 0 ? t("resultsNone") : t("resultsTotal", { n: String(shown) })}
    </p>
  );
}

export function List({ items }: { readonly items: readonly string[] }): ReactElement {
  if (items.length === 0) return <p className={HINT}>{t("none")}</p>;
  return (
    <ul className={BULLETS}>
      {items.map((i) => (
        <li key={i} className={MONO}>
          {i}
        </li>
      ))}
    </ul>
  );
}

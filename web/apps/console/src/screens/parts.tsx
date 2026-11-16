// §8.13, E25, TN-131: what every section screen shares. A read that fails shows that it failed
// and nothing else; nothing is ever guessed or shown as allowed. Strings render as text nodes.
import {
  type QueryKey,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryResult,
} from "@tanstack/react-query";
import type { ReactElement, ReactNode } from "react";

import { Badge } from "@access/ui/components/badge";
import { Card, CardContent, CardHeader } from "@access/ui/components/card";
import { Field as FieldRoot, FieldDescription, FieldLabel } from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";

import { t, type Key } from "../i18n/index.js";
import type { SearchAnswer } from "../lib/adp.js";
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

const IDLE = { status: "idle" } as const;
const BUSY = { status: "busy" } as const;

// OP-159 m.46 (d)
/** The key of a read of the viewer's environment: what a write that changes it invalidates. */
export function readKey(ctx: Ctx, ...parts: readonly unknown[]): QueryKey {
  return ["read", ctx.session.environment, ctx.instance.id, ...parts];
}

/**
 * Runs `f` on demand; the last call wins. A change is never retried and nothing is shown before
 * its answer (no optimistic update); once it succeeds, the reads under `invalidates` are read
 * again.
 */
export function useRun<T>(
  invalidates: readonly QueryKey[] = [],
): readonly [Loaded<T>, (f: () => Promise<T>) => void] {
  const client = useQueryClient();
  const m = useMutation({
    mutationFn: (f: () => Promise<T>) => f(),
    retry: false,
    onSuccess: () => {
      for (const queryKey of invalidates) void client.invalidateQueries({ queryKey });
    },
  });
  let state: Loaded<T>;
  if (m.status === "idle") state = IDLE;
  else if (m.status === "pending") state = BUSY;
  else if (m.status === "error") state = { status: "failed", key: failureKey(m.error) };
  else state = { status: "done", value: m.data };
  return [state, m.mutate] as const;
}

/** A query's state as a screen shows it; a read that is not asked for is idle. */
export function loaded<T>(q: UseQueryResult<T>): Loaded<T> {
  if (q.status === "error") return { status: "failed", key: failureKey(q.error) };
  if (q.status === "pending") return q.fetchStatus === "idle" ? IDLE : BUSY;
  return { status: "done", value: q.data };
}

/** Reads `f` under `key`: kept while the key stays, read again when it changes or is invalidated. */
export function useLoad<T>(key: QueryKey, f: () => Promise<T>): Loaded<T> {
  const q = useQuery({ queryKey: key, queryFn: async () => ({ value: await f() }) });
  const l = loaded(q);
  return l.status === "done" ? { status: "done", value: l.value.value } : l;
}

/** A paged search read: every page read so far, and the next one while there is one. */
export function usePages<T>(
  key: QueryKey,
  page: (token: string | undefined) => Promise<SearchAnswer<T>>,
): { readonly l: Loaded<readonly T[]>; readonly more: (() => void) | undefined } {
  const q = useInfiniteQuery({
    queryKey: key,
    queryFn: ({ pageParam }) => page(pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) =>
      last.page.next_token === undefined || last.page.next_token === ""
        ? undefined
        : last.page.next_token,
  });
  const more = q.hasNextPage
    ? () => {
        void q.fetchNextPage();
      }
    : undefined;
  if (q.isPending) return { l: BUSY, more: undefined };
  if (q.isError) return { l: { status: "failed", key: failureKey(q.error) }, more: undefined };
  return { l: { status: "done", value: q.data.pages.flatMap((a) => a.results) }, more };
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

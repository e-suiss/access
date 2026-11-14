// OP-159 m.31
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
} from "@suiss/access-ui/components/ui/card";
import { Empty, EmptyDescription } from "@suiss/access-ui/components/ui/empty";
import { Item } from "@suiss/access-ui/components/ui/item";
import { Skeleton } from "@suiss/access-ui/components/ui/skeleton";
import { cn } from "@suiss/access-ui/lib/utils";
import type { ComponentProps, ReactElement, ReactNode } from "react";

import { t } from "./i18n.js";

/** A settings card: a titled `<section>` holding one part of a page. */
export function Panel({
  title,
  titleId,
  description,
  level = 3,
  children,
  ...props
}: Omit<ComponentProps<"section">, "title"> & {
  readonly title: ReactNode;
  readonly titleId?: string;
  readonly description?: ReactNode;
  readonly level?: 2 | 3;
}): ReactElement {
  const Heading = level === 2 ? "h2" : "h3";
  return (
    <section {...props}>
      <Card>
        <CardHeader>
          <Heading id={titleId} className="text-base font-semibold">
            {title}
          </Heading>
          {description !== undefined && <CardDescription>{description}</CardDescription>}
        </CardHeader>
        <CardContent className="flex flex-col gap-4">{children}</CardContent>
      </Card>
    </section>
  );
}

/** A part of a card, set apart from the one before it by a rule. */
export function Part({ className, ...props }: ComponentProps<"section">): ReactElement {
  return (
    <section
      className={cn("flex flex-col gap-3 border-t pt-4 first:border-t-0 first:pt-0", className)}
      {...props}
    />
  );
}

/** A page's title. */
export function PageTitle({ className, ...props }: ComponentProps<"h2">): ReactElement {
  return <h2 className={cn("text-xl font-semibold tracking-tight", className)} {...props} />;
}

/** A list of rows. */
export function Rows({ className, ...props }: ComponentProps<"ul">): ReactElement {
  return <ul className={cn("flex flex-col gap-2", className)} {...props} />;
}

/** One row of a list, as a suiss/ui item. */
export function RowItem({
  className,
  variant = "outline",
  ...props
}: ComponentProps<"div"> & { readonly variant?: "outline" | "muted" }): ReactElement {
  return (
    <Item
      variant={variant}
      size="sm"
      className={cn("items-start", className)}
      render={(p) => <li {...p} />}
      {...props}
    />
  );
}

/** The quiet line under a row's title. */
export function Meta({ className, ...props }: ComponentProps<"p">): ReactElement {
  return <p className={cn("text-sm text-muted-foreground", className)} {...props} />;
}

/** A row's buttons. */
export function Actions({ className, ...props }: ComponentProps<"div">): ReactElement {
  return <div className={cn("flex flex-wrap items-center gap-2", className)} {...props} />;
}

/** What a list says when it has nothing. */
export function Nothing({ children }: { readonly children: ReactNode }): ReactElement {
  return (
    <Empty className="border p-6">
      <EmptyDescription>{children}</EmptyDescription>
    </Empty>
  );
}

/** A placeholder while a part loads; the loading text is for screen readers. */
export function Loading({
  status = false,
  rows = 2,
}: {
  readonly status?: boolean;
  readonly rows?: number;
}): ReactElement {
  return (
    <div className="flex flex-col gap-2">
      <p className="sr-only" {...(status ? { role: "status" } : {})}>
        {t("shell.loading")}
      </p>
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} aria-hidden="true" className="h-12 w-full" />
      ))}
    </div>
  );
}

/** A native checkbox in the suiss/ui colours; tests and assistive tools reach the input itself. */
export function Check({
  className,
  ...props
}: Omit<ComponentProps<"input">, "type">): ReactElement {
  return (
    <input
      type="checkbox"
      className={cn(
        "size-4 shrink-0 cursor-pointer rounded-sm accent-primary outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
        className,
      )}
      {...props}
    />
  );
}

/** Monospaced text that wraps anywhere, for keys and identifiers. */
export const MONO = "font-mono text-sm wrap-anywhere";

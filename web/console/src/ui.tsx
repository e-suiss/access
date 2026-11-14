// TN-131: the console's layout pieces on suiss/ui; every string renders as a text node.
import type { ComponentProps, ReactElement, ReactNode } from "react";

import { Alert } from "@suiss/access-ui/components/ui/alert";
import { Skeleton } from "@suiss/access-ui/components/ui/skeleton";
import { cn } from "@suiss/access-ui/lib/utils";

import { t } from "./i18n/index.js";

/** An identifier, a key or any other machine text. */
export const MONO = "font-mono text-[0.9em] wrap-anywhere";

/** A sentence that explains the control or value next to it. */
export const HINT = "text-sm text-muted-foreground";

/** A list of label and value pairs. */
export const FACTS =
  "grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-[minmax(8rem,max-content)_minmax(0,1fr)] [&>dd]:mb-2 sm:[&>dd]:mb-0 [&>dt]:font-medium [&>dt]:text-muted-foreground";

export const BULLETS = "flex list-disc flex-col gap-1 ps-5";

export const NUMBERED = "flex list-decimal flex-col gap-2 ps-5";

/** The buttons that end a form or a panel. */
export const ACTIONS = "flex flex-wrap items-center gap-3";

/** A form of fields and their actions. */
export const FORM = "flex max-w-xl flex-col gap-4";

/** A radio or check box, the browser's own control in the theme's colour. */
export const CHOICE = "size-4 shrink-0 accent-primary";

/** A radio or check box with its label. */
export const CHOICE_LABEL = "flex min-h-6 items-center gap-2 text-sm";

export const H4 = "text-sm font-semibold";

/** One result inside a panel: an answer, a report, an entry. */
export const REPORT = "flex flex-col gap-3 border-t pt-4";

/** A page's landmark and heading. */
export function Page({
  title,
  intro,
  children,
  className,
  ...props
}: Omit<ComponentProps<"main">, "title"> & {
  readonly title: ReactNode;
  readonly intro?: ReactNode;
}): ReactElement {
  return (
    <main
      id="main"
      tabIndex={-1}
      className={cn(
        "mx-auto flex w-full max-w-5xl flex-col gap-6 px-4 py-6 outline-none md:px-8 md:py-8",
        className,
      )}
      {...props}
    >
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {intro !== undefined && <p className="text-muted-foreground">{intro}</p>}
      </header>
      {children}
    </main>
  );
}

/** A notice: information, a warning, or a failure. It has a role only when the caller gives one. */
export function Notice({
  tone = "info",
  role,
  className,
  ...props
}: ComponentProps<typeof Alert> & {
  readonly tone?: "info" | "warning" | "danger";
}): ReactElement {
  return (
    <Alert
      data-tone={tone}
      role={role}
      className={cn(
        "rounded-xl p-3 text-sm",
        tone === "warning" &&
          "bg-amber-50 text-amber-950 ring-1 ring-amber-600/30 dark:bg-amber-950/40 dark:text-amber-50",
        tone === "danger" &&
          "bg-red-50 text-red-900 ring-1 ring-red-700/25 dark:bg-red-950/40 dark:text-red-50",
        className,
      )}
      {...props}
    />
  );
}

/** A read or change that failed: the failure and nothing else. */
export function Failure({
  children,
  className,
}: {
  readonly children: ReactNode;
  readonly className?: string;
}): ReactElement {
  return (
    <Notice tone="danger" role="alert" {...(className === undefined ? {} : { className })}>
      {children}
    </Notice>
  );
}

/** A read in flight. */
export function Busy({ className }: { readonly className?: string }): ReactElement {
  return (
    <div aria-busy="true" className={cn("flex flex-col gap-2 py-1", className)}>
      <span className="sr-only">{t("loading")}</span>
      <Skeleton className="h-4 w-3/4" />
      <Skeleton className="h-4 w-1/2" />
    </div>
  );
}

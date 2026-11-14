// TN-106, TN-107, TN-108
import type { ComponentProps } from "react";

import { buttonVariants } from "@suiss/access-ui/components/ui/button";
import { Card, CardContent } from "@suiss/access-ui/components/ui/card";
import { cn } from "@suiss/access-ui/lib/utils";

/** The one card a page is drawn on. */
export function Panel({ className, children, ...props }: ComponentProps<"div">) {
  return (
    <Card className={cn("w-full max-w-sm", className)} {...props}>
      <CardContent className="flex flex-col gap-4">{children}</CardContent>
    </Card>
  );
}

/** A page's content, one block under the other. */
export const stack = "flex flex-col gap-4";

/** The page heading; a new step moves focus to it. */
export function Title({ className, ...props }: ComponentProps<"h1">) {
  return (
    <h1
      tabIndex={-1}
      className={cn(
        "rounded-sm text-2xl font-semibold tracking-tight outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
        className,
      )}
      {...props}
    />
  );
}

/** A refusal or failure the page shows. */
export const problem =
  "rounded-lg border-s-4 border-destructive bg-destructive/10 px-4 py-3 text-sm text-foreground";

/** Something the person should weigh before going on. */
export const warning =
  "rounded-lg border-s-4 border-chart-4 bg-chart-4/10 px-4 py-3 text-sm text-foreground";

/** A quieter line of explanation. */
export const note = "text-sm text-muted-foreground";

/** An outcome the page reports. */
export const outcome = "rounded-lg bg-muted px-4 py-3 text-sm text-foreground";

/** A link on its own line. */
export const link =
  "inline-flex min-h-6 items-center rounded-sm text-sm font-medium text-(color:--link) underline-offset-4 outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50";

/** A link inside a sentence. */
export const inlineLink =
  "rounded-sm font-medium text-(color:--link) underline underline-offset-4 outline-none focus-visible:ring-3 focus-visible:ring-ring/50";

/** The main action of a page. */
export const primary = { block: true, size: "lg" } as const;

/** The quieter action beside it. */
export const quiet = {
  block: true,
  size: "lg",
  variant: "plain",
  className: "text-(color:--link)",
} as const;

/** Another way to go on. */
export const other = {
  block: true,
  size: "lg",
  variant: "outline",
  className: "bg-card",
} as const;

/** A full-page navigation drawn as a button. */
export const otherLink = cn(buttonVariants(other));

/** A label/value list. */
export const facts = "grid gap-1 [&_dd]:text-muted-foreground [&_dt]:font-medium";

/** A checkbox's or radio's own input covers its 40×32 target, so a press lands on the input. */
export const pressable = cn(
  "[&>span:first-child]:inset-0! [&>span:first-child]:m-0! [&>span:first-child]:size-full! [&>span:first-child]:overflow-visible! [&>span:first-child]:[clip:auto]! [&>span:first-child]:[clip-path:none]! [&>span:first-child]:z-10",
  "[&_input]:absolute [&_input]:-inset-s-3 [&_input]:-top-2 [&_input]:m-0 [&_input]:h-[calc(100%+1rem)] [&_input]:w-[calc(100%+1.5rem)] [&_input]:cursor-pointer [&_input]:opacity-0",
);

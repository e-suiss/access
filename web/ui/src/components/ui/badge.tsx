import { cva, type VariantProps } from "class-variance-authority";
import type * as React from "react";
import { cn } from "@suiss/access-ui/lib/utils";

const badgeVariants = cva(
  "focus-visible:border-ring aria-invalid:border-destructive h-5 gap-1 rounded-full border border-transparent text-xs font-semibold transition-colors focus-visible:ring-3 focus-visible:ring-ring/50 inline-flex w-fit shrink-0 items-center justify-center overflow-hidden whitespace-nowrap [&>svg]:pointer-events-none group/badge [&>svg]:size-3!",
  {
    variants: {
      variant: {
        default: "text-primary [a]:hover:underline",
        secondary: "text-muted-foreground [a]:hover:underline",
        destructive:
          "text-destructive focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 [a]:hover:underline",
        outline:
          "border-border px-2 text-foreground has-data-[icon=inline-end]:pe-1.5 has-data-[icon=inline-start]:ps-1.5 [a]:hover:bg-accent [a]:hover:text-accent-foreground",
        ghost:
          "px-2 has-data-[icon=inline-end]:pe-1.5 has-data-[icon=inline-start]:ps-1.5 [a]:hover:bg-accent [a]:hover:text-muted-foreground",
        link: "text-primary hover:underline",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

function Badge({
  className,
  variant = "default",
  render,
  ...props
}: React.ComponentProps<"span"> & {
  render?: (props: React.HTMLAttributes<HTMLElement>) => React.ReactNode;
} & VariantProps<typeof badgeVariants>) {
  const merged = {
    "data-slot": "badge",
    "data-variant": variant,
    className: cn(badgeVariants({ variant }), className),
    ...props,
  };
  if (render) return render(merged as React.HTMLAttributes<HTMLElement>);
  return <span {...merged} />;
}

export { Badge };

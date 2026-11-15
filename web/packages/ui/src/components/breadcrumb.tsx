import { mergeProps } from "@base-ui/react/merge-props";
import { useRender } from "@base-ui/react/use-render";
import type * as React from "react";
import { CaretRightIcon, DotsThreeIcon } from "@phosphor-icons/react";
import { cn } from "@access/ui/lib/utils";

function Breadcrumb({ className, ...props }: React.ComponentProps<"nav">) {
  return <nav aria-label="breadcrumb" data-slot="breadcrumb" className={className} {...props} />;
}

function BreadcrumbList({ className, ...props }: React.ComponentProps<"ol">) {
  return (
    <ol
      data-slot="breadcrumb-list"
      className={cn(
        "gap-3 text-sm text-muted-foreground flex flex-wrap items-center wrap-break-word",
        className,
      )}
      {...props}
    />
  );
}

function BreadcrumbItem({ className, ...props }: React.ComponentProps<"li">) {
  return (
    <li
      data-slot="breadcrumb-item"
      className={cn("gap-1.5 inline-flex items-center", className)}
      {...props}
    />
  );
}

function BreadcrumbLink({ className, render, ...props }: useRender.ComponentProps<"a">) {
  return useRender({
    defaultTagName: "a",
    props: mergeProps<"a">(
      {
        className: cn(
          "rounded-xs outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50 [&_svg:not([class*='size-'])]:size-4.5",
          className,
        ),
      },
      props,
    ),
    render,
    state: {
      slot: "breadcrumb-link",
    },
  });
}

function BreadcrumbPage({ className, ...props }: React.ComponentProps<"span">) {
  return (
    <span
      data-slot="breadcrumb-page"
      aria-current="page"
      className={cn("text-foreground", className)}
      {...props}
    />
  );
}

function BreadcrumbSeparator({ children, className, ...props }: React.ComponentProps<"li">) {
  return (
    <li
      data-slot="breadcrumb-separator"
      role="presentation"
      aria-hidden="true"
      className={cn("[&>svg]:size-3", className)}
      {...props}
    >
      {children ?? <CaretRightIcon className="rtl:rotate-180" />}
    </li>
  );
}

function BreadcrumbEllipsis({ className, children, ...props }: React.ComponentProps<"span">) {
  return (
    <span
      data-slot="breadcrumb-ellipsis"
      className={cn("size-5 flex items-center justify-center [&>svg]:size-4", className)}
      {...props}
    >
      <DotsThreeIcon aria-hidden="true" />
      <span className="sr-only">{children ?? "More"}</span>
    </span>
  );
}

export {
  Breadcrumb,
  BreadcrumbEllipsis,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
};

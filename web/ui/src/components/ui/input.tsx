import type * as React from "react";
import { Input as InputPrimitive } from "react-aria-components";
import { cn, defined } from "@suiss/access-ui/lib/utils";

function Input({
  className,
  type,
  size = "default",
  ...props
}: Omit<React.ComponentProps<"input">, "size"> & {
  size?: "sm" | "md" | "default";
}) {
  return (
    <InputPrimitive
      type={type}
      data-slot="input"
      data-size={size}
      className={cn(
        "h-11 rounded-lg border border-transparent bg-secondary px-3 py-1 text-base transition-[color,box-shadow,background-color] file:h-7 file:border-0 file:bg-transparent file:text-sm caret-primary focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 data-[size=md]:h-9 data-[size=md]:text-sm data-[size=sm]:h-8 data-[size=sm]:rounded-md data-[size=sm]:px-2.5 data-[size=sm]:text-sm aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:bg-destructive/5 dark:aria-invalid:bg-destructive/10 w-full min-w-0 outline-none file:inline-flex file:text-foreground placeholder:text-muted-foreground disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...defined(props)}
    />
  );
}

export { Input };

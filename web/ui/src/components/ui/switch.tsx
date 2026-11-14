import type * as React from "react";
import { SwitchButton, SwitchField, type SwitchFieldProps } from "react-aria-components";
import { cn } from "@suiss/access-ui/lib/utils";

function Switch({
  className,
  size = "default",
  children,
  ...props
}: Omit<SwitchFieldProps, "className" | "children"> & {
  className?: string;
  children?: React.ReactNode;
  size?: "sm" | "default";
}) {
  return (
    <SwitchField className="contents" {...props}>
      <SwitchButton
        data-slot="switch"
        data-size={size}
        className={cn(
          "shrink-0 rounded-full border-2 transition-colors group-has-focus-visible/field-label:ring-0 data-focus-visible:border-ring data-focus-visible:ring-3 data-focus-visible:ring-ring/50 data-invalid:border-destructive data-invalid:ring-3 data-invalid:ring-destructive/20 dark:data-invalid:ring-destructive/40 data-[size=default]:h-6 data-[size=default]:w-13 data-[size=sm]:h-5 data-[size=sm]:w-11 data-selected:border-primary data-selected:bg-primary group-has-focus-visible/field-label:data-selected:border-primary not-data-selected:border-transparent not-data-selected:bg-input dark:not-data-selected:bg-input/80 group-has-focus-visible/field-label:not-data-selected:border-transparent data-disabled:data-selected:border-transparent peer group/switch relative inline-flex items-center outline-none after:absolute after:-inset-x-3 after:-inset-y-2 data-disabled:cursor-not-allowed data-disabled:opacity-50",
          className,
        )}
      >
        {({ isSelected }) => (
          <>
            <span
              data-slot="switch-thumb"
              data-checked={isSelected || undefined}
              data-unchecked={!isSelected || undefined}
              className="rounded-full bg-background shadow-sm transition-[translate,width] duration-200 ease-[cubic-bezier(0.32,0.72,0,1)] not-dark:bg-clip-padding group-data-[size=default]/switch:h-5 group-data-[size=default]/switch:w-8 group-data-[size=sm]/switch:h-4 group-data-[size=sm]/switch:w-6.5 data-unchecked:translate-x-0 group-data-[size=default]/switch:data-checked:translate-x-4 group-data-[size=sm]/switch:data-checked:translate-x-3.5 rtl:group-data-[size=default]/switch:data-checked:-translate-x-4 rtl:group-data-[size=sm]/switch:data-checked:-translate-x-3.5 group-[:active:not([data-disabled])]/switch:group-data-[size=default]/switch:w-9 group-[:active:not([data-disabled])]/switch:group-data-[size=sm]/switch:w-7.5 group-[:active:not([data-disabled])]/switch:group-data-[size=default]/switch:data-checked:translate-x-3 group-[:active:not([data-disabled])]/switch:group-data-[size=sm]/switch:data-checked:translate-x-2.5 rtl:group-[:active:not([data-disabled])]/switch:group-data-[size=default]/switch:data-checked:-translate-x-3 rtl:group-[:active:not([data-disabled])]/switch:group-data-[size=sm]/switch:data-checked:-translate-x-2.5 dark:bg-foreground pointer-events-none block ring-0"
            />
            {children}
          </>
        )}
      </SwitchButton>
    </SwitchField>
  );
}

export { Switch };

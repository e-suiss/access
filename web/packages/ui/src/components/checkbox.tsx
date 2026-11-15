import { Checkbox as CheckboxPrimitive } from "@base-ui/react/checkbox";
import { CheckIcon } from "@phosphor-icons/react";
import { cn } from "@access/ui/lib/utils";

function Checkbox({ className, ...props }: CheckboxPrimitive.Root.Props) {
  return (
    <CheckboxPrimitive.Root
      data-slot="checkbox"
      className={cn(
        "flex size-4 items-center justify-center rounded-[calc(var(--radius)*0.4)] border border-foreground/25 bg-background shadow-[0_0.5px_1px_color-mix(in_oklab,var(--foreground)_12%,transparent)] focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:not-data-checked:border-transparent dark:not-data-checked:bg-border dark:shadow-none data-checked:border-primary data-checked:bg-primary data-checked:text-primary-foreground data-checked:shadow-none data-disabled:cursor-not-allowed data-disabled:shadow-none data-disabled:data-checked:border-transparent aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:aria-checked:border-primary group-has-focus-visible/field-label:ring-0 group-has-focus-visible/field-label:data-checked:border-primary data-disabled:opacity-50 group-has-disabled/field:opacity-50 peer relative shrink-0 outline-none after:absolute after:-inset-x-3 after:-inset-y-2",
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator
        data-slot="checkbox-indicator"
        className="grid place-content-center text-current transition-none [&>svg]:size-3.5"
      >
        <CheckIcon />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

export { Checkbox };

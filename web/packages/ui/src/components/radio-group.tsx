import { Radio as RadioPrimitive } from "@base-ui/react/radio";
import { RadioGroup as RadioGroupPrimitive } from "@base-ui/react/radio-group";
import { cn } from "@access/ui/lib/utils";

function RadioGroup({ className, ...props }: RadioGroupPrimitive.Props) {
  return (
    <RadioGroupPrimitive
      data-slot="radio-group"
      className={cn("grid gap-3 w-full", className)}
      {...props}
    />
  );
}

function RadioGroupItem({ className, ...props }: RadioPrimitive.Root.Props) {
  return (
    <RadioPrimitive.Root
      data-slot="radio-group-item"
      className={cn(
        "flex size-4 rounded-full border-foreground/25 bg-background shadow-[0_0.5px_1px_color-mix(in_oklab,var(--foreground)_12%,transparent)] group-has-focus-visible/field-label:ring-0 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:not-data-checked:border-transparent dark:not-data-checked:bg-border dark:shadow-none data-checked:border-primary data-checked:bg-primary data-checked:text-primary-foreground data-checked:shadow-none data-disabled:cursor-not-allowed data-disabled:shadow-none data-disabled:data-checked:border-transparent aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 data-disabled:opacity-50 peer relative aspect-square shrink-0 border outline-none after:absolute after:-inset-x-3 after:-inset-y-2 group/radio-group-item",
        className,
      )}
      {...props}
    >
      <RadioPrimitive.Indicator
        data-slot="radio-group-indicator"
        className="flex size-4 items-center justify-center"
      >
        <span className="absolute top-1/2 inset-s-1/2 size-2 -translate-x-1/2 rtl:translate-x-1/2 -translate-y-1/2 rounded-full bg-primary-foreground dark:size-2.5" />
      </RadioPrimitive.Indicator>
    </RadioPrimitive.Root>
  );
}

export { RadioGroup, RadioGroupItem };

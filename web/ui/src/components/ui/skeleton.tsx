import { cn } from "@suiss/access-ui/lib/utils";

function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      className={cn("rounded-md bg-muted animate-pulse", className)}
      {...props}
    />
  );
}

export { Skeleton };

import { Dialog as DialogPrimitive } from "@base-ui/react/dialog";
import type * as React from "react";
import { XIcon } from "@phosphor-icons/react";
import { Button } from "@access/ui/components/button";
import { useScrollbarGap } from "@access/ui/hooks/use-scrollbar-gap";
import { cn } from "@access/ui/lib/utils";

function Dialog({ ...props }: DialogPrimitive.Root.Props) {
  return <DialogPrimitive.Root data-slot="dialog" {...props} />;
}

function DialogTrigger({ ...props }: DialogPrimitive.Trigger.Props) {
  return <DialogPrimitive.Trigger data-slot="dialog-trigger" {...props} />;
}

function DialogPortal({ ...props }: DialogPrimitive.Portal.Props) {
  return <DialogPrimitive.Portal data-slot="dialog-portal" {...props} />;
}

function DialogClose({ ...props }: DialogPrimitive.Close.Props) {
  return <DialogPrimitive.Close data-slot="dialog-close" {...props} />;
}

function DialogOverlay({ className, ...props }: DialogPrimitive.Backdrop.Props) {
  useScrollbarGap();

  return (
    <DialogPrimitive.Backdrop
      data-slot="dialog-overlay"
      className={cn(
        "bg-black/50 duration-100 data-open:animate-in data-open:fade-in-0 data-closed:animate-out data-closed:fade-out-0 fixed inset-0 isolate z-50",
        className,
      )}
      {...props}
    />
  );
}

function DialogContent({
  className,
  children,
  showCloseButton = true,
  closeLabel,
  ...props
}: DialogPrimitive.Popup.Props & {
  showCloseButton?: boolean;
  closeLabel?: string;
}) {
  return (
    <DialogPortal>
      <DialogOverlay />
      <DialogPrimitive.Popup
        data-slot="dialog-content"
        className={cn(
          "-translate-x-1/2 inset-s-1/2 grid max-w-[calc(100%-2rem)] rtl:translate-x-1/2 gap-6 rounded-2xl bg-popover p-6 text-base text-popover-foreground shadow-xl ring-1 ring-foreground/5 duration-100 sm:max-w-md dark:ring-foreground/10 data-open:animate-in data-open:fade-in-0 data-open:zoom-in-95 data-closed:animate-out data-closed:fade-out-0 data-closed:zoom-out-95 fixed top-1/2 z-50 w-full -translate-y-1/2 outline-none has-[>[data-slot=dialog-close]]:*:first:pe-8 has-[>[data-slot=dialog-close][data-label]]:*:first:pe-18",
          className,
        )}
        {...props}
      >
        {children}
        {showCloseButton && (
          <DialogPrimitive.Close
            data-slot="dialog-close"
            data-label={closeLabel ? "" : undefined}
            render={
              <Button
                variant={closeLabel ? "plain" : "ghost"}
                className={cn(
                  "absolute top-4.75 inset-e-4",
                  closeLabel && "text-base",
                  !closeLabel &&
                    "bg-secondary hover:bg-[color-mix(in_oklab,var(--secondary),var(--foreground)_5%)]",
                )}
                size={closeLabel ? "sm" : "icon-sm"}
              />
            }
          >
            {closeLabel ?? (
              <>
                <XIcon />
                <span className="sr-only">Close</span>
              </>
            )}
          </DialogPrimitive.Close>
        )}
      </DialogPrimitive.Popup>
    </DialogPortal>
  );
}

function DialogHeader({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div data-slot="dialog-header" className={cn("gap-1.5 flex flex-col", className)} {...props} />
  );
}

function DialogFooter({
  className,
  showCloseButton = false,
  children,
  ...props
}: React.ComponentProps<"div"> & {
  showCloseButton?: boolean;
}) {
  return (
    <div
      data-slot="dialog-footer"
      className={cn("flex flex-col-reverse gap-2 sm:flex-row sm:justify-end", className)}
      {...props}
    >
      {children}
      {showCloseButton && (
        <DialogPrimitive.Close render={<Button variant="secondary" />}>Close</DialogPrimitive.Close>
      )}
    </div>
  );
}

function DialogTitle({ className, ...props }: DialogPrimitive.Title.Props) {
  return (
    <DialogPrimitive.Title
      data-slot="dialog-title"
      className={cn("cn-font-heading text-base font-semibold", className)}
      {...props}
    />
  );
}

function DialogDescription({ className, ...props }: DialogPrimitive.Description.Props) {
  return (
    <DialogPrimitive.Description
      data-slot="dialog-description"
      className={cn(
        "text-sm text-muted-foreground *:[a]:underline *:[a]:hover:text-foreground",
        className,
      )}
      {...props}
    />
  );
}

export {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogOverlay,
  DialogPortal,
  DialogTitle,
  DialogTrigger,
};

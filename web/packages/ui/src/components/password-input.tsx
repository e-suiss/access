import { EyeIcon, EyeSlashIcon } from "@phosphor-icons/react";
import { type ComponentProps, type KeyboardEvent, useEffect, useId, useRef, useState } from "react";
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@access/ui/components/input-group";

/** The words a password field speaks, in the page's language. */
interface PasswordWords {
  readonly show: string;
  readonly hide: string;
  readonly capsLock: string;
}

/**
 * TN-165: a password field that can be shown and is hidden again when its form is sent, and that
 * says when Caps Lock is on.
 */
function PasswordInput({
  words,
  compact = false,
  ref,
  onKeyDown,
  onKeyUp,
  onBlur,
  "aria-describedby": describedBy,
  ...props
}: Omit<ComponentProps<"input">, "size" | "type"> & {
  readonly words: PasswordWords;
  readonly compact?: boolean;
}) {
  const [shown, setShown] = useState(false);
  const [caps, setCaps] = useState(false);
  const own = useRef<HTMLInputElement | null>(null);
  const capsId = useId();

  useEffect(() => {
    const form = own.current?.form;
    if (form === null || form === undefined) return;
    const hide = () => {
      if (own.current !== null) own.current.type = "password";
      setShown(false);
    };
    form.addEventListener("submit", hide, true);
    return () => {
      form.removeEventListener("submit", hide, true);
    };
  }, []);

  const watchCaps = (e: KeyboardEvent<HTMLInputElement>) => {
    setCaps(e.getModifierState("CapsLock"));
  };

  const describedByAll = [describedBy, caps ? capsId : undefined].filter(Boolean).join(" ");

  return (
    <>
      <InputGroup {...(compact ? { className: "h-9 text-sm" } : {})}>
        <InputGroupInput
          {...props}
          ref={(node) => {
            own.current = node;
            if (typeof ref === "function") return ref(node);
            if (ref !== null && ref !== undefined) ref.current = node;
            return undefined;
          }}
          type={shown ? "text" : "password"}
          {...(describedByAll === "" ? {} : { "aria-describedby": describedByAll })}
          onKeyDown={(e) => {
            watchCaps(e);
            onKeyDown?.(e);
          }}
          onKeyUp={(e) => {
            watchCaps(e);
            onKeyUp?.(e);
          }}
          onBlur={(e) => {
            setCaps(false);
            onBlur?.(e);
          }}
        />
        <InputGroupAddon align="inline-end">
          <InputGroupButton
            size="icon-sm"
            aria-label={shown ? words.hide : words.show}
            onClick={() => setShown((s) => !s)}
          >
            {shown ? <EyeSlashIcon /> : <EyeIcon />}
          </InputGroupButton>
        </InputGroupAddon>
      </InputGroup>
      <p id={capsId} aria-live="polite" className="text-sm text-muted-foreground empty:hidden">
        {caps ? words.capsLock : ""}
      </p>
    </>
  );
}

export { PasswordInput, type PasswordWords };

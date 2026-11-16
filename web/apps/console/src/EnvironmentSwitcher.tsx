// OP-159 m.43 (b), m.42 (c), m.47 (a), IA-5: the environments the viewer can go to, in the header: the
// tenant's home and environments, which the session administers without a new sign-in, and the ones
// this browser signed in to. The list is metadata only; what an environment's console shows comes
// from that environment's probes.

import { Button } from "@access/ui/components/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@access/ui/components/dropdown-menu";
import { type ReactElement, useState } from "react";

import { type Key, t } from "./i18n/index.js";
import { MONO } from "./ui.js";

/**
 * The switcher over `current`: the tenant's home `home` and its environments `tenant`, and the
 * ones this browser signed in to.
 */
export function EnvironmentSwitcher({
  current,
  home,
  tenant,
  known,
  onGo,
}: {
  readonly current: string;
  readonly home: string | undefined;
  readonly tenant: readonly string[];
  readonly known: readonly string[];
  readonly onGo: (environment: string) => void;
}): ReactElement {
  const ours = home === undefined ? [] : [home, ...tenant.filter((r) => r !== home)];
  const others = known.filter((r) => !ours.includes(r));
  const listed = ours.includes(current) || others.includes(current);
  const groups: readonly (readonly [Key, readonly string[]])[] = [
    ["environmentSwitchTenant", ours],
    ["environmentSwitchKnown", listed ? others : [current, ...others]],
  ];
  const shown = groups.filter(([, list]) => list.length > 0);
  const [open, setOpen] = useState(false);
  const go = (v: unknown) => {
    setOpen(false);
    if (typeof v === "string" && v !== current) onGo(v);
  };
  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="sm"
            data-testid="environment-switcher"
            aria-label={t("environmentSwitch", { environment: current })}
          />
        }
      >
        <span className={`${MONO} text-muted-foreground`}>{current}</span>
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden>
          <path d="M4 6l4 4 4-4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-auto min-w-56">
        {shown.map(([label, list], i) => (
          <DropdownMenuGroup key={label}>
            {i > 0 && <DropdownMenuSeparator />}
            <DropdownMenuLabel>{t(label)}</DropdownMenuLabel>
            <DropdownMenuRadioGroup value={current} onValueChange={go}>
              {list.map((r) => (
                <DropdownMenuRadioItem key={r} value={r} className={MONO}>
                  {r === home ? t("environmentSwitchHome", { environment: r }) : r}
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
          </DropdownMenuGroup>
        ))}
        <DropdownMenuSeparator />
        <p className="px-3 py-2 text-xs text-muted-foreground">{t("environmentSwitchNote")}</p>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

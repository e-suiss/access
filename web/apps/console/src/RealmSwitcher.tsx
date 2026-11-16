// OP-159 m.43 (b), m.42 (c), IA-5: the realms the viewer can go to, in the header. Each is a
// separate identity provider: choosing one opens its console, which signs in there when needed.
// The list is metadata only; what a realm's console shows comes from that realm's probes.
import type { ReactElement } from "react";

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

import { t, type Key } from "./i18n/index.js";
import { MONO } from "./ui.js";

/** The switcher over `current`, the platform's realms and the ones this browser signed in to. */
export function RealmSwitcher({
  current,
  platform,
  known,
  onGo,
}: {
  readonly current: string;
  readonly platform: readonly string[];
  readonly known: readonly string[];
  readonly onGo: (realm: string) => void;
}): ReactElement {
  const others = known.filter((r) => !platform.includes(r));
  const listed = platform.includes(current) || others.includes(current);
  const groups: readonly (readonly [Key, readonly string[]])[] = [
    ["realmSwitchPlatform", platform],
    ["realmSwitchKnown", listed ? others : [current, ...others]],
  ];
  const shown = groups.filter(([, list]) => list.length > 0);
  const go = (v: unknown) => {
    if (typeof v === "string" && v !== current) onGo(v);
  };
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="sm"
            data-testid="realm-switcher"
            aria-label={t("realmSwitch", { realm: current })}
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
                  {r}
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
          </DropdownMenuGroup>
        ))}
        <DropdownMenuSeparator />
        <p className="px-3 py-2 text-xs text-muted-foreground">{t("realmSwitchNote")}</p>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

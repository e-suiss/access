// OP-159 m.46 (g), IA-5: the command palette (Ctrl/⌘ K). It lists only the screens the viewer may see
// in this environment, as the probes answered, and the environments the switcher offers; choosing
// one goes there. It changes nothing by itself.

import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@access/ui/components/command";
import { useNavigate } from "@tanstack/react-router";
import type { ReactElement } from "react";

import { t } from "./i18n/index.js";
import { SCREENS, type Screen, type Section } from "./lib/sections.js";
import { SCREEN_TITLE, SECTION_TITLE, SECTION_TO } from "./screens/Section.js";
import { MONO } from "./ui.js";

export function CommandPalette({
  open,
  onOpenChange,
  environment,
  screens,
  tenant,
  known,
  onEnvironment,
}: {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly environment: string;
  readonly screens: ReadonlySet<Screen>;
  readonly tenant: readonly string[];
  readonly known: readonly string[];
  readonly onEnvironment: (environment: string) => void;
}): ReactElement {
  const navigate = useNavigate();
  const setOpen = onOpenChange;

  const shown = (Object.keys(SCREENS) as Section[]).flatMap((section) =>
    (SCREENS[section] as readonly Screen[])
      .filter((s) => screens.has(s))
      .map((screen) => ({ section, screen })),
  );
  const environments = [...new Set([...tenant, ...known])].filter((r) => r !== environment);

  return (
    <CommandDialog
      open={open}
      onOpenChange={setOpen}
      title={t("paletteTitle")}
      description={t("paletteDescription")}
    >
      <Command>
        <CommandInput placeholder={t("palettePlaceholder")} aria-label={t("palettePlaceholder")} />
        <CommandList>
          <CommandEmpty>{t("paletteEmpty")}</CommandEmpty>
          {shown.length > 0 && (
            <CommandGroup heading={t("paletteScreens")}>
              {shown.map(({ section, screen }) => (
                <CommandItem
                  key={`${section}/${screen}`}
                  value={`${section}/${screen}`}
                  keywords={[t(SCREEN_TITLE[screen]), t(SECTION_TITLE[section])]}
                  onSelect={() => {
                    setOpen(false);
                    void navigate({
                      to: SECTION_TO[section],
                      params: { environment, screen },
                    });
                  }}
                >
                  <span>{t(SCREEN_TITLE[screen])}</span>
                  <span className="text-sm text-muted-foreground group-data-selected/command-item:text-primary-foreground">
                    {t(SECTION_TITLE[section])}
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          )}
          {environments.length > 0 && (
            <CommandGroup heading={t("paletteEnvironments")}>
              {environments.map((r) => (
                <CommandItem
                  key={r}
                  value={`environment/${r}`}
                  keywords={[r]}
                  onSelect={() => {
                    setOpen(false);
                    onEnvironment(r);
                  }}
                >
                  <span className={MONO}>{r}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          )}
        </CommandList>
      </Command>
    </CommandDialog>
  );
}

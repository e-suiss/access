import { followColorScheme } from "@access/ui/lib/color-scheme";

/** OP-159 m.31: the dark theme follows the system. */
export function prepareDocument(): void {
  followColorScheme();
}

import { followColorScheme } from "@suiss/access-ui/lib/color-scheme";

/** OP-159 m.31: the dark theme follows the system, and React Aria's pressable rule comes from
 * theme.css; the marker stops React Aria injecting it as an inline style the CSP refuses. */
export function prepareDocument(): void {
  followColorScheme();
  if (document.getElementById("react-aria-pressable-style") === null) {
    const marker = document.createElement("meta");
    marker.id = "react-aria-pressable-style";
    document.head.append(marker);
  }
}

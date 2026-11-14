// §14.5
const PRESSABLE_STYLE = "react-aria-pressable-style";

/** React Aria adds a `<style>` element, which `style-src 'self'` refuses, unless an element
 * with its id is already in the head; the rule it carries is in styles.css instead. */
export function keepStylesInStylesheet(): void {
  if (document.getElementById(PRESSABLE_STYLE) !== null) return;
  const marker = document.createElement("meta");
  marker.id = PRESSABLE_STYLE;
  document.head.append(marker);
}

/** OP-159 m.31: the theme's `.dark` follows the system colour scheme. */
export function followColorScheme(root: HTMLElement = document.documentElement): () => void {
  const query = window.matchMedia("(prefers-color-scheme: dark)");
  const apply = (): void => {
    root.classList.toggle("dark", query.matches);
  };
  apply();
  query.addEventListener("change", apply);
  return () => {
    query.removeEventListener("change", apply);
  };
}

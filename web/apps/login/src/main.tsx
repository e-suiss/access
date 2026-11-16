import { prepareDocument } from "@access/ui/lib/document";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.js";
import { linkTheme } from "./Branding.js";
import { applyDocument, loadOverrides } from "./i18n.js";
import "./styles.css";

applyDocument();
linkTheme();
prepareDocument();
const root = document.getElementById("root");
if (root === null) {
  throw new Error("missing #root element");
}
const mount = root;
void loadOverrides().finally(() => {
  createRoot(mount).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
});

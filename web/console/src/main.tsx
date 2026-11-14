import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { prepareDocument } from "@suiss/access-ui/lib/document";

import { App } from "./App.js";
import { locale } from "./i18n/index.js";
import "./styles.css";

document.documentElement.lang = locale;
prepareDocument();
const root = document.getElementById("root");
if (root === null) {
  throw new Error("missing #root element");
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

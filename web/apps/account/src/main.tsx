import { prepareDocument } from "@access/ui/lib/document";
import { QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.js";
import { locale } from "./lib/i18n.js";
import { queryClient } from "./lib/query.js";
import "./styles.css";

document.documentElement.lang = locale;
prepareDocument();
const root = document.getElementById("root");
if (root === null) {
  throw new Error("missing #root element");
}
createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);

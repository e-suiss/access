import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { prepareDocument } from "@access/ui/lib/document";

import { locale } from "./i18n/index.js";
import { router } from "./router.js";
import "./styles.css";

// OP-159 m.46 (d), §13.7.4: a read that fails shows that it failed; nothing is asked again on its
// own, which would spend the session's check budget and could repeat a change.
const client = new QueryClient({
  defaultOptions: {
    queries: { retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false },
    mutations: { retry: false },
  },
});

document.documentElement.lang = locale;
prepareDocument();
const root = document.getElementById("root");
if (root === null) {
  throw new Error("missing #root element");
}
createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);

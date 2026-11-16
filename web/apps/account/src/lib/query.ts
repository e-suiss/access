// OP-159 m.46 (d): the account pages' server state. A read is retried once only when the server
// or the network failed, never on a refusal; a write is never retried and never shown done before
// the server answered (TN-* honesty).
import { QueryClient } from "@tanstack/react-query";

import { Problem } from "./api.js";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failures, e) => failures < 1 && !(e instanceof Problem && e.status < 500),
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
    },
    mutations: { retry: false },
  },
});

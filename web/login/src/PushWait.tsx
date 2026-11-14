// OP-156 m.3 (d), TN-102: a push waits for the approver. The page shows the two-digit number the
// person types into the approver; the push itself never carries it. The page polls the flow until
// the push is answered or its 120 seconds are over.
import type { LoginUi, PushNumberNode } from "./contract.js";
import { maybe } from "./i18n.js";

/** The waiting push of a step, if it has one. */
export function pushOf(ui: LoginUi): PushNumberNode | undefined {
  return ui.nodes.find((n): n is PushNumberNode => n.type === "push_number");
}

/** A step that waits on the approver's answer. */
export function waitsForPush(ui: LoginUi): boolean {
  return pushOf(ui) !== undefined;
}

/** How often the page asks whether the push was answered. */
export const PUSH_POLL_MS = 2000;

/** One more poll after the end, so the server's expiry is what the page shows. */
export function pushGiveUpMs(node: PushNumberNode, now: number): number {
  const end = Date.parse(node.expires_at);
  return Number.isNaN(end) ? 0 : Math.max(0, end - now) + PUSH_POLL_MS;
}

function caption(node: PushNumberNode): string {
  if (node.approver === undefined) return node.label.text;
  return (
    maybe(node.label.id, { approver: node.approver, number: String(node.number) }) ??
    node.label.text
  );
}

export function PushWait({ node }: { readonly node: PushNumberNode }) {
  return (
    <div className="flex flex-col items-center gap-2 text-center" data-testid="push-wait">
      <p className="text-sm text-muted-foreground">{caption(node)}</p>
      <p
        className="text-5xl font-bold tracking-widest text-(color:--link) tabular-nums"
        aria-label={String(node.number)}
        data-testid="push-number"
      >
        {String(node.number)}
      </p>
    </div>
  );
}

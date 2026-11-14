// OP-153 m.3 (t), IA-4, X28
import { createElement, type ReactElement } from "react";
import { createRoot, type Root } from "react-dom/client";

import { AgentBadge, AgentConnections } from "./agents/Agents.js";
import type { AgentFace, Connection } from "./agents/model.js";
import { StatusLadder, type Rung } from "./StatusLadder.js";
import { WhyPanel, type Depth, type Explanation } from "./WhyPanel.js";

/** A custom element that renders one component from its `data` property; it keeps no copy of
 * Access data beyond what it was last given and sends nothing anywhere. */
abstract class Rendered<T> extends HTMLElement {
  #root: Root | undefined;
  #data: T | undefined;

  set data(value: T) {
    this.#data = value;
    this.#render();
  }

  connectedCallback(): void {
    this.#root ??= createRoot(this);
    this.#render();
  }

  disconnectedCallback(): void {
    this.#root?.unmount();
    this.#root = undefined;
  }

  protected abstract view(data: T): ReactElement;

  #render(): void {
    if (this.#root && this.#data !== undefined) this.#root.render(this.view(this.#data));
  }
}

class LadderElement extends Rendered<readonly Rung[]> {
  protected view(rungs: readonly Rung[]): ReactElement {
    return createElement(StatusLadder, { rungs });
  }
}

class WhyElement extends Rendered<{ explanation: Explanation; depth: Depth }> {
  protected view(d: { explanation: Explanation; depth: Depth }): ReactElement {
    return createElement(WhyPanel, d);
  }
}

/** What `<access-agent-badge>` and `<access-agent-connections>` are given: the host's names
 * of Parties, never looked up by the element. */
export interface Names {
  readonly names?: Readonly<Record<string, string>>;
  readonly catalogue?: Readonly<Record<string, string>>;
}

function named(d: Names): (party: string) => string {
  return (party) => d.names?.[party] ?? party;
}

class AgentBadgeElement extends Rendered<Names & { face: AgentFace }> {
  protected view(d: Names & { face: AgentFace }): ReactElement {
    return createElement(AgentBadge, { face: d.face, name: named(d), catalogue: d.catalogue });
  }
}

/** Disconnect asks the host by an `access-disconnect` event with `{ connection }`; the element
 * sends nothing itself. */
class AgentConnectionsElement extends Rendered<Names & { connections: readonly Connection[] }> {
  protected view(d: Names & { connections: readonly Connection[] }): ReactElement {
    return createElement(AgentConnections, {
      connections: d.connections,
      name: named(d),
      time: (ms: number) => new Date(ms).toLocaleString(),
      onDisconnect: (connection: string) => {
        this.dispatchEvent(
          new CustomEvent("access-disconnect", { detail: { connection }, bubbles: true }),
        );
      },
      catalogue: d.catalogue,
    });
  }
}

/** Registers `<access-status-ladder>`, `<access-why>`, `<access-agent-badge>` and
 * `<access-agent-connections>` once. */
export function defineElements(registry: CustomElementRegistry = customElements): void {
  if (!registry.get("access-status-ladder")) registry.define("access-status-ladder", LadderElement);
  if (!registry.get("access-why")) registry.define("access-why", WhyElement);
  if (!registry.get("access-agent-badge")) registry.define("access-agent-badge", AgentBadgeElement);
  if (!registry.get("access-agent-connections")) {
    registry.define("access-agent-connections", AgentConnectionsElement);
  }
}

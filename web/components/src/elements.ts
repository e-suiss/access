// OP-153 m.3 (t), IA-4, X28
import { createElement, type ReactElement } from "react";
import { createRoot, type Root } from "react-dom/client";

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

/** Registers `<access-status-ladder>` and `<access-why>` once. */
export function defineElements(registry: CustomElementRegistry = customElements): void {
  if (!registry.get("access-status-ladder")) registry.define("access-status-ladder", LadderElement);
  if (!registry.get("access-why")) registry.define("access-why", WhyElement);
}

// OP-157 m.3 (m), §13.7.3, §8.17.6.3, SEC26
// A CT1 batch: every item is listed with its own render and gets its own assertion; the action is
// labelled with the server's count, and there is no way to approve the items unseen.

/** One field of an item's canonical render. */
export interface BatchField {
  readonly name: string;
  readonly text: string;
  readonly material: boolean;
}

/** One item of `POST /v1/approve/batch`. */
export interface BatchEntry {
  readonly flow: string;
  readonly render: { readonly fields: readonly BatchField[]; readonly reason: string };
}

export interface BatchProps {
  /** The server's label: "Approve these 4 requests". */
  readonly title: string;
  readonly items: readonly BatchEntry[];
  readonly busy?: boolean | undefined;
  /** Runs one assertion per item, in the listed order. */
  readonly onApprove: () => void;
}

/** Whether a batch can be offered: at most ten items, each with something to show. */
export function offerable(items: readonly BatchEntry[]): boolean {
  return items.length > 0 && items.length <= 10 && items.every((i) => i.render.fields.length > 0);
}

export function Batch({ title, items, busy, onApprove }: BatchProps) {
  if (!offerable(items)) return null;
  return (
    <section aria-label={title}>
      <ol>
        {items.map((item) => (
          <li key={item.flow}>
            <dl>
              {item.render.fields.map((f) => (
                <div key={f.name} data-material={f.material ? "true" : undefined}>
                  <dt>{f.name}</dt>
                  <dd>{f.text}</dd>
                </div>
              ))}
            </dl>
            <p>{item.render.reason}</p>
          </li>
        ))}
      </ol>
      <button type="button" disabled={busy === true} onClick={onApprove}>
        {title}
      </button>
    </section>
  );
}

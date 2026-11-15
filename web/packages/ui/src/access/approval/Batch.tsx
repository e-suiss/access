// OP-157 m.3 (m), §13.7.3, §8.17.6.3, SEC26
// A CT1 batch: every item is listed with its own render and gets its own assertion; the action is
// labelled with the server's count, and there is no way to approve the items unseen.
import { Button } from "@access/ui/components/button";
import { Card, CardContent, CardFooter } from "@access/ui/components/card";
import { Item, ItemContent, ItemDescription } from "@access/ui/components/item";

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
    <Card size="sm" variant="filled" role="region" aria-label={title}>
      <CardContent>
        <ol className="flex flex-col gap-2">
          {items.map((item) => (
            <Item key={item.flow} render={<li />} variant="outline" size="sm" className="bg-card">
              <ItemContent>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                  {item.render.fields.map((f) => (
                    <div
                      key={f.name}
                      data-material={f.material ? "true" : undefined}
                      className="col-span-2 grid grid-cols-subgrid data-[material=true]:font-semibold"
                    >
                      <dt className="text-muted-foreground">{f.name}</dt>
                      <dd className="break-words">{f.text}</dd>
                    </div>
                  ))}
                </dl>
                <ItemDescription>{item.render.reason}</ItemDescription>
              </ItemContent>
            </Item>
          ))}
        </ol>
      </CardContent>
      <CardFooter>
        <Button type="button" disabled={busy === true} onClick={onApprove}>
          {title}
        </Button>
      </CardFooter>
    </Card>
  );
}

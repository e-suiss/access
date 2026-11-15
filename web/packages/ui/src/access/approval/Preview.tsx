// OP-157 m.3 (l), §6.4, XI-4, §8.17.6.2
// The typed preview of a widening before it is signed: what the Kernel's describeIntent reads
// from the exact intent bytes, each parameter under the type the accepted Action Schema declares.
// A parameter with no declared type is never shown as a value, and the preview is then not
// complete: a widening is signed only from a complete preview.
import { Card, CardContent, CardHeader, CardTitle } from "@access/ui/components/card";

import { text } from "../texts.js";

/** What the Kernel's `describeIntent` answers for an intent envelope. */
export interface DescribedIntent {
  readonly digest: string;
  readonly action: { readonly namespace: string; readonly name: string; readonly major: number };
  readonly resources: readonly {
    readonly namespace: string;
    readonly path: readonly string[];
    readonly incarnation: string;
  }[];
  readonly params: Readonly<Record<string, string>>;
  readonly opaque: readonly string[];
  readonly recipient: string | null;
  readonly validity: { readonly from: number | string; readonly until: number | string };
}

export interface PreviewProps {
  /** The Kernel's reading of the exact bytes that will be signed. */
  readonly intent: DescribedIntent;
  /** The parameter types the accepted Action Schema declares, by parameter name. */
  readonly types: Readonly<Record<string, string>>;
  /** The host's catalogue; English otherwise. */
  readonly catalogue?: Readonly<Record<string, string>> | undefined;
}

/** The parameters without a declared type: they can't be shown, so nothing can be signed. */
export function untyped(
  intent: DescribedIntent,
  types: Readonly<Record<string, string>>,
): readonly string[] {
  return Object.keys(intent.params)
    .filter((name) => !Object.hasOwn(types, name))
    .sort();
}

/** Whether every parameter has a declared type, so the preview shows the whole intent. */
export function complete(
  intent: DescribedIntent,
  types: Readonly<Record<string, string>>,
): boolean {
  return untyped(intent, types).length === 0;
}

const DL = "grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm";
const ROW = "col-span-2 grid grid-cols-subgrid";
const DT = "text-muted-foreground";
const DD = "font-mono break-all";

function resourceText(r: DescribedIntent["resources"][number]): string {
  const path = [r.namespace, ...r.path].join("/");
  return r.incarnation === "0" ? path : `${path}@${r.incarnation}`;
}

/** The typed preview (Ek B 5596). */
export function Preview({ intent, types, catalogue }: PreviewProps) {
  const missing = new Set(untyped(intent, types));
  const names = Object.keys(intent.params).sort();
  return (
    <Card
      size="sm"
      variant="filled"
      role="region"
      className="access-approval-preview"
      aria-label={text("approval.preview_title", catalogue)}
    >
      <CardHeader>
        <CardTitle>
          <h2>{text("approval.preview_title", catalogue)}</h2>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <dl className={DL}>
          <dt className={DT}>action</dt>
          <dd className={DD}>
            {`${intent.action.namespace}/${intent.action.name}@${String(intent.action.major)}`}
          </dd>
          {intent.resources.map((r, i) => (
            <div key={`resource-${String(i)}`} className={ROW}>
              <dt className={DT}>resource</dt>
              <dd className={DD}>{resourceText(r)}</dd>
            </div>
          ))}
          {names.map((name) => (
            <div key={name} data-type={missing.has(name) ? undefined : types[name]} className={ROW}>
              <dt className={DT}>{name}</dt>
              {missing.has(name) ? (
                <dd className="access-approval-untyped text-destructive" role="note">
                  {text("approval.preview_untyped", catalogue)}
                </dd>
              ) : (
                <dd className={DD}>{intent.params[name]}</dd>
              )}
            </div>
          ))}
          {intent.recipient === null ? null : (
            <div className={ROW}>
              <dt className={DT}>recipient</dt>
              <dd className={DD}>{intent.recipient}</dd>
            </div>
          )}
          <dt className={DT}>validity</dt>
          <dd className={DD}>
            {`${String(intent.validity.from)}..${String(intent.validity.until)}`}
          </dd>
        </dl>
      </CardContent>
    </Card>
  );
}

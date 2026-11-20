import { CheckIcon, CopyIcon, DownloadSimpleIcon, PrinterIcon } from "@phosphor-icons/react";
import { useState } from "react";
import { Button } from "@access/ui/components/button";
import { cn } from "@access/ui/lib/utils";

/** The words a recovery code list speaks, in the page's language. */
interface RecoveryCodeWords {
  readonly copy: string;
  readonly copied: string;
  readonly download: string;
  readonly print: string;
  /** The first line of the saved or printed page: what the codes are for. */
  readonly title: string;
}

/** The text a saved or printed list carries: what it is for, then one code per line. */
function codesText(title: string, codes: readonly string[]): string {
  return `${title}\n\n${codes.join("\n")}\n`;
}

function save(fileName: string, body: string) {
  const url = URL.createObjectURL(new Blob([body], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/**
 * TN-166: recovery codes shown once, with ways to keep them: copy, download as a text file and
 * print. Printing shows only the list (`data-print-area`).
 */
function RecoveryCodeList(props: {
  readonly codes: readonly string[];
  readonly words: RecoveryCodeWords;
  readonly fileName: string;
  readonly className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const body = codesText(props.words.title, props.codes);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(props.codes.join("\n"));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  const print = () => {
    document.body.dataset["printing"] = "codes";
    const done = () => {
      delete document.body.dataset["printing"];
      window.removeEventListener("afterprint", done);
    };
    window.addEventListener("afterprint", done);
    window.print();
  };
  return (
    <div className="flex flex-col gap-3">
      <div data-print-area="" className="flex flex-col gap-2">
        <p className="hidden print:block">{props.words.title}</p>
        <ul
          className={cn(
            "grid grid-cols-2 gap-2 rounded-lg bg-muted px-3 py-2 font-mono text-sm",
            props.className,
          )}
          data-testid="code-list"
        >
          {props.codes.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      </div>
      <div className="flex flex-wrap items-center justify-center gap-2 print:hidden">
        <Button type="button" variant="ghost" size="sm" onClick={() => void copy()}>
          {copied ? <CheckIcon data-icon="inline-start" /> : <CopyIcon data-icon="inline-start" />}
          {copied ? props.words.copied : props.words.copy}
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={() => save(props.fileName, body)}>
          <DownloadSimpleIcon data-icon="inline-start" />
          {props.words.download}
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={print}>
          <PrinterIcon data-icon="inline-start" />
          {props.words.print}
        </Button>
      </div>
      <span role="status" className="sr-only">
        {copied ? props.words.copied : ""}
      </span>
    </div>
  );
}

export { RecoveryCodeList, type RecoveryCodeWords };

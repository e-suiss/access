// XI-19, §8.17.4.1, X39
import { Button } from "@access/ui/components/button";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@access/ui/components/card";

import { text } from "./texts.js";

export interface StepUpProps {
  /** Why the step-up is needed, already in the viewer's language. */
  readonly reason: string;
  /** What the viewer is asked to present, already in the viewer's language. */
  readonly method: string;
  readonly onStart: () => void;
  readonly onCancel: () => void;
  readonly catalogue?: Readonly<Record<string, string>>;
}

/** The step-up ceremony prompt. It starts the ceremony and nothing more: there is no "remember
 * this" and no way to skip a later step-up from here. */
export function StepUp({ reason, method, onStart, onCancel, catalogue }: StepUpProps) {
  return (
    <Card className="access-stepup" role="dialog" aria-label={text("stepup.title", catalogue)}>
      <CardHeader>
        <CardTitle>
          <h2>{text("stepup.title", catalogue)}</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <p className="text-base">{reason}</p>
        <p className="text-sm text-muted-foreground">{method}</p>
      </CardContent>
      <CardFooter className="flex-wrap gap-2">
        <Button type="button" onClick={onStart}>
          {text("stepup.start", catalogue)}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel}>
          {text("stepup.cancel", catalogue)}
        </Button>
      </CardFooter>
    </Card>
  );
}

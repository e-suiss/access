// XI-19, §8.17.4.1, X39
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
    <section className="access-stepup" role="dialog" aria-label={text("stepup.title", catalogue)}>
      <h2>{text("stepup.title", catalogue)}</h2>
      <p>{reason}</p>
      <p>{method}</p>
      <button type="button" onClick={onStart}>
        {text("stepup.start", catalogue)}
      </button>
      <button type="button" onClick={onCancel}>
        {text("stepup.cancel", catalogue)}
      </button>
    </section>
  );
}

// OP-157 m.3 (f), §8.16, X37
import type { ReactNode } from "react";

import { EN } from "../texts.js";
import { type Banner, bannerArgs, complete, say } from "./model.js";

export interface SupportBannerProps {
  readonly banner: Banner;
  readonly catalogue?: Readonly<Record<string, string>> | undefined;
}

/** The operator's lasting banner: "Acting for Ayşe K. with her support access (case #4411) ·
 * read-only · ends 15:30 · every action is recorded under your name". A tenant's support tool
 * embeds it; the Access console uses it too. */
export function SupportBanner({ banner, catalogue }: SupportBannerProps) {
  if (!complete(banner)) {
    return null;
  }
  const mode = say(EN, banner.readOnly ? "support.read_only" : "support.can_change", catalogue);
  return (
    <div className="access-support-banner" role="status" aria-live="polite">
      {say(EN, "support.banner", catalogue, bannerArgs(banner, mode))}
    </div>
  );
}

export interface SupportViewProps {
  /** The banner; without a complete one nothing renders. */
  readonly banner: Banner | undefined;
  readonly children: ReactNode;
  readonly catalogue?: Readonly<Record<string, string>> | undefined;
}

/** A support view: the banner, always, above what the operator sees. There is no support view
 * without the banner (X37). */
export function SupportView({ banner, children, catalogue }: SupportViewProps) {
  if (!complete(banner)) {
    return null;
  }
  return (
    <section className="access-support-view">
      <SupportBanner banner={banner} catalogue={catalogue} />
      {children}
    </section>
  );
}

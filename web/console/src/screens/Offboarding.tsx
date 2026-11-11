// §8.17.9.6, E6, EI-8: the Admin section's offboarding screen.
import { useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { type MetaPayload, type MetaResult, metaWrites } from "../lib/meta.js";
import { WriteOutcome } from "./Admin.js";
import { type Ctx, Field, Panel, Show, useRun } from "./parts.js";

function lines(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

type Choice = "keep" | "revoke";

/**
 * §8.17.9.6, E6, EI-8: departure needs an explicit choice for every direct delegation (no
 * default), and running copies are ended one by one. "Offboarded" is shown only once the
 * departure Exercise is recorded.
 */
export function Offboarding({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [party, setParty] = useState("");
  const [grantsText, setGrantsText] = useState("");
  const [instancesText, setInstancesText] = useState("");
  const [choices, setChoices] = useState<Readonly<Record<string, Choice>>>({});
  const [w, write] = useRun<readonly MetaResult[]>();
  const grants = lines(grantsText);
  const instances = lines(instancesText);
  const decided = grants.every((g) => choices[g] !== undefined);
  const depart = () => {
    const payloads: MetaPayload[] = instances.map((instance) => ({
      instance_terminate: { instance },
    }));
    payloads.push({
      party_depart: {
        party,
        disposition: grants.map((g) => ({ grant: g, disposition: choices[g] })),
      },
    });
    write(() => metaWrites(ctx.instance, ctx.confirm, ctx.instance.party ?? "", payloads));
  };
  const done = w.status === "done" && w.value.length > 0 && w.value.every((r) => r.decision);
  return (
    <>
      <p>{t("offboardingIntro")}</p>
      <p>{t("offboardingChannels")}</p>
      <Panel id="offboard" title={t("offboardingTitle")}>
        <Field id="off-party" label={t("offboardingParty")} value={party} onChange={setParty} />
        <p className="field">
          <label htmlFor="off-grants">{t("offboardingGrants")}</label>
          <textarea
            id="off-grants"
            value={grantsText}
            onChange={(e) => {
              setGrantsText(e.target.value);
            }}
          />
        </p>
        {grants.length > 0 && <p role="note">{t("offboardingSurvive")}</p>}
        {grants.map((g) => (
          <fieldset key={g}>
            <legend className="mono">{g}</legend>
            {(["keep", "revoke"] as const).map((c) => (
              <label key={c}>
                <input
                  type="radio"
                  name={`off-${g}`}
                  checked={choices[g] === c}
                  onChange={() => {
                    setChoices({ ...choices, [g]: c });
                  }}
                />{" "}
                {c === "keep" ? t("offboardingKeep") : t("offboardingRevoke")}
              </label>
            ))}
          </fieldset>
        ))}
        <p className="field">
          <label htmlFor="off-instances">{t("offboardingInstances")}</label>
          <textarea
            id="off-instances"
            value={instancesText}
            onChange={(e) => {
              setInstancesText(e.target.value);
            }}
          />
        </p>
        <button
          type="button"
          data-testid="depart"
          disabled={party === "" || !decided}
          onClick={depart}
        >
          {t("offboardingDepart")}
        </button>
        {!decided && grants.length > 0 && <p className="hint">{t("offboardingChooseAll")}</p>}
        <Show l={w}>
          {(rs) => (
            <>
              {rs.map((r, i) => (
                <WriteOutcome key={String(i)} r={r} />
              ))}
              {done && <p data-testid="offboarded">{t("offboardingDone")}</p>}
            </>
          )}
        </Show>
      </Panel>
      <p>{t("offboardingLabel")}</p>
    </>
  );
}

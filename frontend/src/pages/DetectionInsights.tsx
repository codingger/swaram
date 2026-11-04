import { useState } from "react";
import { api } from "../api";
import { type Column } from "../components/ResultViewer";
import { Badge, Button, Card, Empty, type Status } from "../components/ui";
import { pct, shortId } from "../lib/format";
import { useRunData } from "../state";
import type { AgentAssessment, AuditItem } from "../types";

function RiskBar({ value }: { value: number }) {
  const color = value >= 0.9 ? "#ff3b30" : value >= 0.6 ? "#ff9500" : value >= 0.2 ? "#ffcc00" : "#34c759";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-black/[0.06]">
        <div className="h-full rounded-full" style={{ width: `${Math.max(2, value * 100)}%`, background: color }} />
      </div>
      <span className="tabular-nums">{pct(value)}</span>
    </div>
  );
}

export const riskColumns: Column<AgentAssessment>[] = [
  { key: "agent_id", label: "agent", render: (a) => <span className="font-mono" title={a.agent_id}>{shortId(a.agent_id)}</span> },
  { key: "role", label: "role" },
  { key: "risk", label: "risk (posterior)", render: (a) => <RiskBar value={a.risk} /> },
  { key: "level", label: "level", render: (a) => <Badge value={a.level} /> },
  { key: "anomaly_bits", label: "anomaly", render: (a) => (a.anomaly_bits ? `${a.anomaly_bits} bits` : "") },
  { key: "best_explanation", label: "best explanation", className: "max-w-xs whitespace-normal", render: (a) => a.best_explanation ?? "" },
];

export const auditColumns: Column<AuditItem>[] = [
  { key: "priority", label: "priority", render: (i) => <RiskBar value={i.priority} /> },
  { key: "timestamp", label: "time (UTC)", render: (i) => <span className="font-mono">{i.timestamp.slice(11, 19)}</span> },
  { key: "agent_id", label: "agent", render: (i) => <span className="font-mono" title={i.agent_id}>{shortId(i.agent_id)}</span> },
  { key: "summary", label: "action", className: "max-w-sm whitespace-normal" },
  { key: "reasons", label: "why review", className: "max-w-xs whitespace-normal", render: (i) => i.reasons.join(" · ") },
];

/** Why an agent got its risk: Bayesian factors, System-1 behaviors and ranked hypotheses. */
export function AssessmentDetail({ a }: { a: AgentAssessment | null }) {
  if (!a) return <Card title="Why this agent"><Empty>Select an agent in the risk ranking.</Empty></Card>;
  return (
    <Card title="Why this agent" actions={<Badge value={a.level} />}>
      <div className="space-y-5 text-[14px]">
        <div>
          <div className="font-mono text-[13px] text-faint">{a.agent_id} · {a.role}</div>
          <div className="mt-1 text-[22px] font-semibold tracking-[-0.02em]">{pct(a.prior)} → {pct(a.risk)}</div>
          <div className="text-[12px] text-faint">prior → posterior probability of malicious behavior</div>
        </div>

        <section>
          <h3 className="mb-1.5 text-[13px] font-semibold">Evidence (Bayesian update)</h3>
          {a.evidence.length ? (
            <ul className="space-y-1 text-[13px] text-ink">
              {a.evidence.map((e) => <li key={e} className="font-mono">{e}</li>)}
            </ul>
          ) : <p className="text-[13px] text-faint">No evidence moved this agent's risk.</p>}
        </section>

        {a.rare_behaviors.length > 0 && (
          <section>
            <h3 className="mb-1.5 text-[13px] font-semibold">Rare for its role (System 1)</h3>
            <ul className="space-y-1.5">
              {a.rare_behaviors.map((r) => (
                <li key={r.behavior} className="rounded-xl bg-canvas px-3 py-2">
                  <div className="break-all font-mono text-[12px] text-ink">{r.behavior}</div>
                  <div className="mt-0.5 text-[12px] tabular-nums text-faint">seen in {pct(r.p)} of same-role agents · {r.bits} bits</div>
                </li>
              ))}
            </ul>
          </section>
        )}

        {a.hypotheses.length > 0 && (
          <section>
            <h3 className="mb-2 text-[13px] font-semibold">Possible explanations (abductive)</h3>
            <ul className="space-y-2.5">
              {a.hypotheses.map((h, i) => (
                <li key={h.hypothesis}>
                  <div className="flex items-baseline justify-between gap-3 text-[13px]">
                    <span className={i === 0 ? "font-semibold text-ink" : "text-muted"}>{h.label}</span>
                    <span className="tabular-nums text-faint">{pct(h.score)}</span>
                  </div>
                  <div className="mt-1 h-1 overflow-hidden rounded-full bg-black/[0.06]">
                    <div className="h-full rounded-full" style={{ width: `${h.score * 100}%`, background: i === 0 ? "#0071e3" : "#c7c7cc" }} />
                  </div>
                  {h.supporting.length > 0 && <div className="mt-1 text-[12px] text-faint">{h.supporting.join(" · ")}</div>}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </Card>
  );
}

/** System-1 baseline status and continual learning controls. */
export function BaselineCard({ runId, runHasAlerts, onStatus, onChanged }: {
  runId: string | null; runHasAlerts: boolean; onStatus: (s: Status) => void; onChanged: () => void;
}) {
  const summary = useRunData(() => api.baseline(), "baseline");
  const [busy, setBusy] = useState<string | null>(null);
  const s = summary.data;
  const learned = !!(runId && s?.learned_run_ids.includes(runId));

  async function train(source: "synthetic" | "run") {
    setBusy(source);
    try {
      const res = await api.trainBaseline(source === "run" ? { source, run_id: runId ?? undefined } : { source });
      summary.setData(res);
      onChanged();
      onStatus({ kind: "success", message: source === "run"
        ? `Folded ${runId} into the baseline (${res.agents_learned} agents learned). Re-run detection to use it.`
        : `Baseline retrained from synthetic normal runs (${res.agents_learned} agents). Re-run detection to use it.` });
    } catch (e) {
      onStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card title="Behavioral baseline">
      <div className="space-y-4 text-[14px]">
        <p className="text-[13px] leading-relaxed text-muted">
          What each role normally does, learned from benign runs. SG-004 scores how surprising an agent's behavior is
          for its role. Free-text messages are never used.
        </p>
        {s ? (
          <dl className="grid grid-cols-2 gap-3">
            <div><dt className="text-[12px] text-faint">Agents learned</dt><dd className="text-[22px] font-semibold tabular-nums">{s.agents_learned}</dd></div>
            <div><dt className="text-[12px] text-faint">Runs learned</dt><dd className="text-[22px] font-semibold tabular-nums">{s.runs_learned}</dd></div>
            <div className="col-span-2 flex flex-wrap gap-1.5">
              {Object.entries(s.roles).map(([role, r]) => (
                <span key={role} className="rounded-full bg-black/[0.05] px-2.5 py-1 text-[12px] text-muted">{role}: {r.agents} agents · {r.behaviors} behaviors</span>
              ))}
            </div>
          </dl>
        ) : <p className="text-[13px] text-faint">{summary.error ?? "Loading…"}</p>}
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" busy={busy === "run"} disabled={!runId || runHasAlerts || learned} onClick={() => train("run")}
            title={runHasAlerts ? "Only runs with no alerts can be learned" : learned ? "Already learned" : "Add this run to the baseline"}>
            Learn from this run
          </Button>
          <Button variant="ghost" busy={busy === "synthetic"} onClick={() => train("synthetic")}>Retrain from scratch</Button>
        </div>
        <p className="text-[12px] text-faint">
          {learned ? "This run is already part of the baseline." : runHasAlerts ? "This run has alerts, so it can't be learned as normal." : "Continual learning: confirm a run is clean, then add it."}
        </p>
      </div>
    </Card>
  );
}

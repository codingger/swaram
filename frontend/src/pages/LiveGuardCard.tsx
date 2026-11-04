import { useState } from "react";
import { api } from "../api";
import { Badge, Button, Card, Empty, Field, Segmented, Stat, inputCls } from "../components/ui";
import { shortId } from "../lib/format";
import { useAppState, useRunData } from "../state";
import type { AgentCount, GatewayMode, LiveReport } from "../types";

type Step = { seq: number; kind: "detect" | "contain"; title: string; detail: string; badge: string };

function timeline(r: LiveReport): Step[] {
  const steps: Step[] = [
    ...r.detections.map((d) => ({ seq: d.sequence, kind: "detect" as const, badge: d.severity,
      title: `${d.rule_id} ${d.rule_name} · ${d.agent_ids.map(shortId).join(", ") || "run"}`, detail: d.reason })),
    ...r.containment.map((c) => ({ seq: c.paused_at_sequence, kind: "contain" as const, badge: c.scope === "egress" ? "held" : "paused",
      title: c.scope === "egress" ? `Egress held: ${shortId(c.agent_id)} (${c.role})` : `Agent paused: ${shortId(c.agent_id)} (${c.role}) at risk ${Math.round(c.risk * 100)}%`,
      detail: `${c.explanation ?? ""} · ${c.blocked_actions} later action(s) denied before execution` })),
  ];
  return steps.sort((a, b) => a.seq - b.seq || (a.kind === "detect" ? -1 : 1));
}

/** Run a scenario with detection streaming alongside it, and show what was caught and stopped in time. */
export function LiveGuardCard() {
  const { selectedRunId, selectRun, refreshRuns } = useAppState();
  const stored = useRunData(api.liveReport, selectedRunId);
  const [scenario, setScenario] = useState("coordinated_leakage");
  const [count, setCount] = useState<AgentCount>(5);
  const [mode, setMode] = useState<"contain" | "detect">("contain");
  const [gateway, setGateway] = useState<GatewayMode>("monitor");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const report = stored.data;

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.simulate({ scenario_id: scenario, agent_count: count, seed: 7, gateway_mode: gateway, drop_rate: 0,
        agent_backend: "deterministic", auto_pipeline: true, live_guard: mode, persist: true });
      await refreshRuns();
      selectRun(res.run.run_id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const m = report?.metrics ?? {};
  return (
    <Card title="Live guard">
      <p className="mb-5 text-[13px] leading-relaxed text-muted">
        Detection runs <strong>while the agents act</strong>. Every event is checked as it happens. In <em>contain</em> mode an
        agent reaching {Math.round((report?.pause_at ?? 0.6) * 100)}% risk is paused, and an agent handed restricted data it may not hold
        gets its outbound transfers held. Their next actions are denied <strong>before they execute</strong>.
      </p>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Field label="Scenario">
          <select className={inputCls} value={scenario} onChange={(e) => setScenario(e.target.value)}>
            <option value="coordinated_leakage">Coordinated data leakage</option>
            <option value="unauthorized_access">Unauthorized resource access</option>
            <option value="normal_collaboration">Normal collaboration</option>
          </select>
        </Field>
        <Field label="Agents" asDiv>
          <Segmented full value={count} onChange={setCount} options={[5, 10, 20].map((n) => ({ value: n as AgentCount, label: n }))} />
        </Field>
        <Field label="Mode" asDiv>
          <Segmented full value={mode} onChange={setMode} options={[{ value: "contain", label: "Contain" }, { value: "detect", label: "Detect only" }]} />
        </Field>
        <Field label="Static gateway" hint="Monitor shows what the live guard adds on its own.">
          <select className={inputCls} value={gateway} onChange={(e) => setGateway(e.target.value as GatewayMode)}>
            <option value="monitor">monitor</option>
            <option value="enforce">enforce</option>
          </select>
        </Field>
      </div>
      <div className="mt-5 flex items-center justify-end gap-3">
        {error && <span className="text-[13px] text-[#d70015]">{error}</span>}
        <Button onClick={run} busy={busy}>Run live</Button>
      </div>

      <div className="mt-6 border-t border-black/[0.06] pt-6">
        {!report && <Empty>{selectedRunId ? "This run wasn't simulated with the live guard. Click Run live." : "Click Run live to start."}</Empty>}
        {report && (
          <div className="space-y-6">
            <div className="text-[12px] text-faint">Run <span className="font-mono">{report.run_id}</span> · {report.events_processed} events checked live · mode {report.mode}</div>
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
              <Stat label="Data left the system" value={m.data_left_the_system ? "Yes" : "No"} tone={m.data_left_the_system ? "danger" : "ok"} />
              <Stat label="Attack actions stopped" value={`${m.attack_actions_blocked_by_pause ?? 0} / ${m.attack_actions ?? 0}`} />
              <Stat label="Agents contained" value={`${m.paused_malicious ?? 0} / ${m.malicious_agents ?? 0}`} tone={m.paused_innocent ? "danger" : undefined} />
              <Stat label="Detection latency" value={m.mean_latency_events == null ? "n/a" : `${m.mean_latency_events} ev · ${m.mean_latency_s}s`} />
            </div>
            {m.paused_innocent ? <p className="text-[13px] text-[#d70015]">{String(m.paused_innocent)} innocent agent(s) were paused.</p> : null}
            <ol className="relative space-y-4 border-l-2 border-black/[0.08] pl-5">
              {timeline(report).map((s, i) => (
                <li key={i} className="relative">
                  <span className={`absolute -left-[27px] top-1 h-3 w-3 rounded-full border-2 border-white ${s.kind === "contain" ? "bg-[#ff3b30]" : "bg-[#0071e3]"}`} />
                  <div className="flex flex-wrap items-center gap-2 text-[13px]">
                    <span className="font-mono text-faint">#{s.seq}</span>
                    <Badge value={s.badge} />
                    <span className="font-medium text-ink">{s.title}</span>
                  </div>
                  <p className="mt-0.5 text-[12px] leading-snug text-muted">{s.detail}</p>
                </li>
              ))}
              {!report.detections.length && <li className="text-[13px] text-muted">Nothing suspicious happened; no agent was paused.</li>}
            </ol>
          </div>
        )}
      </div>
    </Card>
  );
}

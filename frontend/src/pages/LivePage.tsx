import { useMemo, useState } from "react";
import { api } from "../api";
import { GeminiQuota } from "../components/GeminiQuota";
import { Badge, Button, Card, Empty, Field, PageHeader, Segmented, StatusBanner, inputCls, type Status } from "../components/ui";
import { shortId } from "../lib/format";
import { type LiveMessage, useLiveStream } from "../lib/live";
import { useAppState } from "../state";
import type { AgentCount } from "../types";

type AnyData = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const TONE: Record<string, string> = {
  detection: "bg-[#ff9500]/14 text-[#a35a00]",
  containment: "bg-[#ff3b30]/12 text-[#d70015]",
  quarantine: "bg-[#af52de]/12 text-[#7d2fa8]",
  run_started: "bg-[#0071e3]/10 text-[#0058b0]",
  run_finished: "bg-[#34c759]/14 text-[#1f7a37]",
  run_failed: "bg-[#ff3b30]/12 text-[#d70015]",
};

function describe(m: LiveMessage<AnyData>): string {
  const d = m.data;
  switch (m.type) {
    case "event":
      return `${shortId(d.agent_id)} ${d.event_type}:${d.action} ${d.resource ?? d.target ?? ""}${d.status === "denied" ? " — BLOCKED" : ""}`;
    case "detection":
      return `${d.rule_id} ${d.rule_name} · ${(d.agent_ids ?? []).map(shortId).join(", ") || "run-level"} · ${d.reason}`;
    case "containment":
      return `${d.scope === "egress" ? "Egress held" : "Agent paused"}: ${shortId(d.agent_id)} (${d.role}) · ${d.explanation ?? ""}`;
    case "quarantine":
      return `Quarantined input for ${shortId(d.agent_id)}: ${d.resource} (claims to be from ${d.claimed_sender})`;
    case "run_started":
      return `Run started: ${d.config?.scenario_id ?? ""}`;
    case "run_finished":
      return `Run finished · ${d.live_metrics ? `data left the system: ${d.live_metrics.data_left_the_system ? "yes" : "no"}` : "no live guard"}`;
    case "run_failed":
      return `Run failed: ${d.error}`;
    default:
      return m.type;
  }
}

/** Live monitor: everything that happens in any run, pushed as it happens (reference UI for the live stream). */
export function LivePage() {
  const { meta } = useAppState();
  const { messages, connected, clear } = useLiveStream();
  const [scenario, setScenario] = useState("sg003_leak_chain");
  const [count, setCount] = useState<AgentCount>(5);
  const [ai, setAi] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [showEvents, setShowEvents] = useState(true);

  const agents = useMemo(() => {
    const out = new Map<string, { role: string; state: string }>();
    for (const m of messages as LiveMessage<AnyData>[]) {
      if (m.type === "run_agents") for (const a of m.data.agents) out.set(a.agent_id, { role: a.role, state: "active" });
      if (m.type === "containment" && out.has(m.data.agent_id))
        out.get(m.data.agent_id)!.state = m.data.scope === "egress" ? "egress held" : "paused";
    }
    return [...out.entries()].slice(-20);
  }, [messages]);
  const feed = (messages as LiveMessage<AnyData>[]).filter((m) => showEvents || m.type !== "event").slice(-200).reverse();

  async function start() {
    setBusy(true);
    setStatus(null);
    try {
      const r = await api.startRun({ scenario_id: scenario, agent_count: count, seed: Math.floor(Math.random() * 1000),
        gateway_mode: "monitor", drop_rate: 0, agent_backend: ai ? "gemini" : "deterministic",
        agent_mode: ai ? "autonomous" : "scripted", auto_pipeline: true, live_guard: "contain", persist: true });
      setStatus({ kind: "success", message: <>Started <code className="font-mono">{r.run_id}</code>; watch it below.</> });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-w-0 space-y-5">
      <PageHeader step={6} module="dashboard" title="Live monitor"
        description="Everything that happens in a run (events, detections, pauses, quarantines) streams here the moment it happens, from simulated runs and from real agents reporting through the ingest API." />
      <StatusBanner status={status} onClose={() => setStatus(null)} />
      <Card title="Start a run">
        <div className="grid gap-4 sm:grid-cols-3 [&>*]:min-w-0">
          <Field label="Scenario">
            <select className={inputCls} value={scenario} onChange={(e) => setScenario(e.target.value)}>
              {meta?.scenarios.filter((s) => s.scenario_id !== "user_directed").map((s) => <option key={s.scenario_id} value={s.scenario_id}>{s.name}</option>)}
            </select>
          </Field>
          <Field label="Agents" asDiv>
            <Segmented full value={count} onChange={setCount} options={[5, 10, 20].map((n) => ({ value: n as AgentCount, label: n }))} />
          </Field>
          <Field label="Driven by" asDiv>
            <Segmented full value={ai ? "ai" : "scripted"} onChange={(v) => setAi(v === "ai")}
              options={[{ value: "scripted", label: "Scripted" }, { value: "ai", label: "AI decides" }]} />
          </Field>
        </div>
        {ai && <div className="mt-4 max-w-md"><GeminiQuota agentCount={count} agentMode="autonomous" /></div>}
        <div className="mt-5 flex items-center justify-between gap-3">
          <span className="flex items-center gap-2 text-[13px] text-muted">
            <span className={`h-2.5 w-2.5 rounded-full ${connected ? "bg-[#34c759]" : "bg-[#ff3b30]"}`} />
            {connected ? "Live stream connected" : "Connecting…"}
          </span>
          <Button onClick={start} busy={busy}>Start live run</Button>
        </div>
      </Card>

      <div className="grid gap-5 lg:grid-cols-[260px_1fr] [&>*]:min-w-0">
        <Card title="Agents">
          {agents.length ? (
            <ul className="space-y-2 text-[13px]">
              {agents.map(([id, a]) => (
                <li key={id} className="flex items-center justify-between gap-2">
                  <span><span className="font-mono">{shortId(id)}</span> <span className="text-muted">{a.role}</span></span>
                  <Badge value={a.state === "active" ? "allowed" : a.state === "paused" ? "blocked" : "would_block"} />
                </li>
              ))}
            </ul>
          ) : <Empty>Agents appear when a run starts.</Empty>}
        </Card>
        <Card title={`Live feed (${messages.length})`}>
          <div className="mb-3 flex items-center justify-between text-[12px] text-muted">
            <label className="flex items-center gap-2"><input type="checkbox" checked={showEvents} onChange={(e) => setShowEvents(e.target.checked)} /> Show every event</label>
            <button className="underline" onClick={clear}>Clear</button>
          </div>
          {feed.length ? (
            <ol className="max-h-[560px] space-y-1.5 overflow-y-auto text-[13px]" aria-label="Live feed">
              {feed.map((m) => (
                <li key={m.seq} className="flex items-start gap-2">
                  <span className="w-12 shrink-0 font-mono text-[11px] text-faint">#{m.seq}</span>
                  <span className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium ${TONE[m.type] ?? "bg-black/[0.05] text-muted"}`}>{m.type}</span>
                  <span className={`min-w-0 [overflow-wrap:anywhere] ${m.type === "event" && (m.data as AnyData).status === "denied" ? "text-[#d70015]" : "text-ink"}`}>{describe(m as LiveMessage<AnyData>)}</span>
                </li>
              ))}
            </ol>
          ) : <Empty>Waiting for activity. Start a run, or send events through the ingest API.</Empty>}
        </Card>
      </div>
    </div>
  );
}

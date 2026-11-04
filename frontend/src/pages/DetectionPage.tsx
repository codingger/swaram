import { useState } from "react";
import { api } from "../api";
import { GraphView } from "../components/GraphView";
import { ResultViewer, type Column } from "../components/ResultViewer";
import { Badge, Button, Card, Empty, OutputSelect, PageHeader, RunSelect, StatusBanner, type Status } from "../components/ui";
import { shortId } from "../lib/format";
import { useAppState, useRunData } from "../state";
import type { AgentAssessment, Alert, AgentGraph, DetectionRule } from "../types";
import { AssessmentDetail, auditColumns, BaselineCard, BenchmarkCard, riskColumns } from "./DetectionInsights";

const columns: Column<Alert>[] = [
  { key: "severity", label: "severity", render: (a) => <Badge value={a.severity} /> },
  { key: "rule_id", label: "rule", render: (a) => <span title={a.rule_name}>{a.rule_id}</span> },
  { key: "agent_ids", label: "agents", render: (a) => <span className="font-mono">{a.agent_ids.map(shortId).join(", ")}</span> },
  { key: "resource", label: "resource" },
  { key: "event_ids", label: "events", render: (a) => a.event_ids.length },
  { key: "recommended_action", label: "recommended" },
  { key: "status", label: "status", render: (a) => <Badge value={a.status} /> },
  { key: "reason", label: "reason", className: "max-w-md whitespace-normal" },
];

export function DetectionPage() {
  const { selectedRunId, refreshRuns } = useAppState();
  const [persist, setPersist] = useState(true);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ alerts: Alert[]; graph: AgentGraph; assessments: AgentAssessment[] } | null>(null);
  const alerts = useRunData(api.alerts, selectedRunId);
  const graph = useRunData(api.graph, selectedRunId);
  const assessments = useRunData(api.assessments, selectedRunId);
  const audit = useRunData(api.auditQueue, selectedRunId);
  const rules = useRunData(() => api.rules(), "rules");

  const shownAlerts = preview?.alerts ?? alerts.data;
  const shownGraph = preview?.graph ?? graph.data;
  const shownRisk = preview?.assessments ?? assessments.data;
  const current = shownAlerts?.find((a) => a.alert_id === selected) ?? null;
  const currentAgent = shownRisk?.find((a) => a.agent_id === selectedAgent) ?? shownRisk?.[0] ?? null;

  async function run() {
    if (!selectedRunId) return setStatus({ kind: "error", message: "Select a run first." });
    setBusy(true);
    setStatus(null);
    try {
      const res = await api.detect(selectedRunId, persist);
      if (persist) {
        setPreview(null);
        await Promise.all([alerts.reload(), graph.reload(), assessments.reload(), audit.reload(), refreshRuns()]);
      } else {
        setPreview({ alerts: res.alerts, graph: res.graph, assessments: res.assessments });
      }
      setSelected(res.alerts[0]?.alert_id ?? null);
      setSelectedAgent(res.assessments[0]?.agent_id ?? null);
      const risky = res.assessments.filter((a) => a.level === "high" || a.level === "critical").length;
      setStatus({ kind: res.alerts.length ? "warning" : "success",
        message: `${res.alerts.length} alert(s) generated${persist ? " and saved" : " (preview)"} · ${risky} agent(s) at high or critical risk.` });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  async function toggleRule(rule: DetectionRule) {
    try {
      await api.saveRule({ ...rule, enabled: !rule.enabled });
      await rules.reload();
      setStatus({ kind: "info", message: `${rule.rule_id} ${rule.enabled ? "disabled" : "enabled"}. Re-run detection to apply.` });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    }
  }

  return (
    <div className="space-y-5">
      <PageHeader step={3} module="detection" title="Threat Detection"
        description="Two layers, like fast and slow thinking: a quick behavioral screen against a learned baseline, and explicit rules for unauthorized access, external transfers and leak chains. Each agent gets a risk score and a best explanation. Every alert cites its event IDs; message text is never evidence." />
      <StatusBanner status={status} onClose={() => setStatus(null)} />

      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Run detection" className="lg:col-span-1">
          <div className="space-y-4">
            <RunSelect requireStage="collected" />
            <OutputSelect value={persist} onChange={setPersist} collection="alerts" />
            <Button onClick={run} busy={busy} className="w-full">Run detection</Button>
          </div>
        </Card>
        <Card title="Detection rules" className="lg:col-span-2">
          {rules.error && <p className="text-[14px] text-[#d70015]">{rules.error}</p>}
          <ul className="divide-y divide-black/[0.06]">
            {rules.data?.map((r) => (
              <li key={r.rule_id} className="flex items-start justify-between gap-4 py-3 first:pt-0 last:pb-0">
                <div className="min-w-0">
                  <div className="text-[14px] font-medium text-ink">{r.name}</div>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-[12px] text-faint">
                    <span className="font-mono">{r.rule_id}</span><Badge value={r.severity} /><span>recommends {r.recommended_action}</span>
                  </div>
                  <p className="mt-1.5 text-[13px] leading-snug text-muted">{r.description}</p>
                </div>
                <label className="flex shrink-0 items-center gap-1.5 text-[13px]">
                  <input type="checkbox" checked={r.enabled} onChange={() => toggleRule(r)} /> enabled
                </label>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <ResultViewer title={preview ? "Alerts (preview)" : "Alerts"} rows={shownAlerts} columns={columns}
        filename={`alerts_${selectedRunId}`} rowKey={(a) => a.alert_id} selectedKey={selected}
        onRowClick={(a) => setSelected(a.alert_id)} empty="No alerts. Run detection on a collected run." />

      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Evidence">
          {current ? (
            <div className="space-y-3 text-[14px]">
              <div className="flex flex-wrap items-center gap-2">
                <Badge value={current.severity} /><span className="font-medium">{current.rule_name}</span>
                <span className="font-mono text-[13px] text-faint">{current.alert_id}</span>
              </div>
              <p className="text-ink">{current.reason}</p>
              <ol className="space-y-1.5 border-l-2 border-black/10 pl-3">
                {current.evidence.map((ev) => (
                  <li key={ev.event_id} className="text-[13px]">
                    <span className="font-mono text-faint">{ev.timestamp.slice(11, 23)} · {ev.event_id}</span>
                    <div className="text-ink">{ev.summary}</div>
                  </li>
                ))}
              </ol>
            </div>
          ) : <Empty>Select an alert to inspect its evidence chain.</Empty>}
        </Card>
        <Card title="Agent relationship graph">
          <GraphView graph={shownGraph} />
        </Card>
      </div>

      <ResultViewer title={preview ? "Agent risk ranking (preview)" : "Agent risk ranking"} rows={shownRisk} columns={riskColumns}
        filename={`agent_risk_${selectedRunId}`} rowKey={(a) => a.agent_id} selectedKey={currentAgent?.agent_id ?? null}
        onRowClick={(a) => setSelectedAgent(a.agent_id)} empty="Run detection to rank agents by risk." />

      <ResultViewer title="Audit queue" rows={preview ? null : audit.data} columns={auditColumns}
        filename={`audit_queue_${selectedRunId}`} rowKey={(i) => i.event_id}
        extraActions={<span className="hidden text-[12px] text-faint sm:inline">Not alerts: actions worth a reviewer's time</span>}
        empty={preview ? "Save detection results to build the audit queue." : "Nothing needs review in this run."} />

      <div className="grid gap-5 lg:grid-cols-2">
        <AssessmentDetail a={currentAgent} />
        <BaselineCard runId={selectedRunId} runHasAlerts={!!shownAlerts?.length} onStatus={setStatus}
          onChanged={() => { rules.reload(); }} />
      </div>

      <BenchmarkCard />
    </div>
  );
}

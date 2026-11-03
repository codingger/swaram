import { useState } from "react";
import { api } from "../api";
import { GraphView } from "../components/GraphView";
import { ResultViewer, type Column } from "../components/ResultViewer";
import { Badge, Button, Card, Empty, OutputSelect, PageHeader, RunSelect, StatusBanner, type Status } from "../components/ui";
import { shortId } from "../lib/format";
import { useAppState, useRunData } from "../state";
import type { Alert, AgentGraph, DetectionRule } from "../types";

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
  const [preview, setPreview] = useState<{ alerts: Alert[]; graph: AgentGraph } | null>(null);
  const alerts = useRunData(api.alerts, selectedRunId);
  const graph = useRunData(api.graph, selectedRunId);
  const rules = useRunData(() => api.rules(), "rules");

  const shownAlerts = preview?.alerts ?? alerts.data;
  const shownGraph = preview?.graph ?? graph.data;
  const current = shownAlerts?.find((a) => a.alert_id === selected) ?? null;

  async function run() {
    if (!selectedRunId) return setStatus({ kind: "error", message: "Select a run first." });
    setBusy(true);
    setStatus(null);
    try {
      const res = await api.detect(selectedRunId, persist);
      if (persist) {
        setPreview(null);
        await Promise.all([alerts.reload(), graph.reload(), refreshRuns()]);
      } else {
        setPreview({ alerts: res.alerts, graph: res.graph });
      }
      setSelected(res.alerts[0]?.alert_id ?? null);
      setStatus({ kind: res.alerts.length ? "warning" : "success", message: `${res.alerts.length} alert(s) generated${persist ? " and saved" : " (preview)"}.` });
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
        description="Rule-based detection over normalized events: unauthorized access, external transfers and multi-agent leakage chains. Every alert cites the event IDs that prove it; message text is never used as evidence." />
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
          {rules.error && <p className="text-sm text-red-700">{rules.error}</p>}
          <ul className="divide-y divide-zinc-100">
            {rules.data?.map((r) => (
              <li key={r.rule_id} className="flex items-start justify-between gap-3 py-2">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
                    <span className="font-mono text-xs">{r.rule_id}</span>{r.name}<Badge value={r.severity} />
                    <span className="text-xs font-normal text-zinc-500">→ {r.recommended_action}</span>
                  </div>
                  <p className="text-xs text-zinc-600">{r.description}</p>
                </div>
                <label className="flex shrink-0 items-center gap-1.5 text-xs">
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
            <div className="space-y-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <Badge value={current.severity} /><span className="font-medium">{current.rule_name}</span>
                <span className="font-mono text-xs text-zinc-500">{current.alert_id}</span>
              </div>
              <p className="text-zinc-700">{current.reason}</p>
              <ol className="space-y-1.5 border-l-2 border-zinc-200 pl-3">
                {current.evidence.map((ev) => (
                  <li key={ev.event_id} className="text-xs">
                    <span className="font-mono text-zinc-500">{ev.timestamp.slice(11, 23)} · {ev.event_id}</span>
                    <div className="text-zinc-800">{ev.summary}</div>
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
    </div>
  );
}

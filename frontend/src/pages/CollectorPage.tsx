import { useState } from "react";
import { api } from "../api";
import { ResultViewer, type Column } from "../components/ResultViewer";
import { Badge, Button, Card, Field, OutputSelect, PageHeader, RunSelect, Segmented, Stat, StatusBanner, inputCls, type Status } from "../components/ui";
import { parseJsonOrJsonl } from "../lib/export";
import { shortId } from "../lib/format";
import { useAppState, useRunData } from "../state";
import type { CollectionReport, CollectorIssue, NormalizedEvent } from "../types";

const columns: Column<NormalizedEvent>[] = [
  { key: "timestamp", label: "time (UTC)", render: (e) => <span className="font-mono">{e.timestamp.slice(11, 23)}</span> },
  { key: "event_id", label: "event_id", render: (e) => <span className="font-mono" title={e.event_id}>{shortId(e.event_id)}</span> },
  { key: "agent_role", label: "role" },
  { key: "event_type", label: "type" },
  { key: "summary", label: "summary", className: "max-w-md whitespace-normal" },
  { key: "status", label: "status", render: (e) => <Badge value={e.status} /> },
  { key: "issues", label: "issues", render: (e) => e.issues.join(", ") },
];

const issueCols: Column<CollectorIssue & { level: string }>[] = [
  { key: "level", label: "level", render: (i) => <Badge value={i.level} /> },
  { key: "index", label: "line" },
  { key: "event_id", label: "event_id", render: (i) => <span className="font-mono">{i.event_id ?? ""}</span> },
  { key: "code", label: "code" },
  { key: "message", label: "message", className: "whitespace-normal" },
];

export function CollectorPage() {
  const { selectedRunId, refreshRuns } = useAppState();
  const [source, setSource] = useState<"run" | "upload">("run");
  const [text, setText] = useState("");
  const [persist, setPersist] = useState(true);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [report, setReport] = useState<CollectionReport | null>(null);
  const [preview, setPreview] = useState<NormalizedEvent[] | null>(null);
  const stored = useRunData(api.normalizedEvents, selectedRunId);
  const events = preview ?? stored.data;

  async function onFile(file: File | undefined) {
    if (file) setText(await file.text());
  }

  async function run() {
    setBusy(true);
    setStatus(null);
    try {
      let body: { run_id?: string | null; events?: unknown[]; persist: boolean };
      if (source === "upload") {
        const events = parseJsonOrJsonl(text);
        if (!events.length) throw new Error("Paste or upload JSON / JSONL events first.");
        // Uploaded events are validated against the selected run only if one is chosen and persist is on.
        body = { run_id: persist ? selectedRunId : null, events, persist };
      } else {
        if (!selectedRunId) throw new Error("Select a run first.");
        body = { run_id: selectedRunId, persist };
      }
      const res = await api.collect(body);
      setReport(res.report);
      const saved = body.persist && !!body.run_id;
      setPreview(saved ? null : res.events);
      if (saved) {
        await stored.reload();
        await refreshRuns();
      }
      const kind = res.report.errors.length ? "warning" : "success";
      setStatus({ kind, message: `Normalized ${res.report.valid} of ${res.report.total_input} events · ${res.report.duplicates} duplicate(s) · ${res.report.errors.length} error(s) · ${res.report.warnings.length} warning(s)${saved ? " · saved to normalized_events" : " · preview only"}.` });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  const issues = report ? [...report.errors.map((e) => ({ ...e, level: "error" })), ...report.warnings.map((w) => ({ ...w, level: "warning" }))] : null;

  return (
    <div className="space-y-5">
      <PageHeader step={2} module="collector" title="Event Collector"
        description="Validates raw events, removes duplicates, normalizes timestamps, event types and statuses, checks agent/run identity, and keeps the original evidence with a hash." />
      <StatusBanner status={status} onClose={() => setStatus(null)} />

      <Card title="Input">
        <div className="mb-5">
          <Segmented value={source} onChange={setSource}
            options={[{ value: "run", label: "Stored raw events" }, { value: "upload", label: "Upload or paste" }]} />
        </div>
        <div className="grid gap-5 md:grid-cols-2">
          <RunSelect requireStage={source === "run" ? "simulated" : undefined} />
          <OutputSelect value={persist} onChange={setPersist} collection="normalized_events" />
        </div>
        {source === "upload" && (
          <div className="mt-4 space-y-2">
            <Field label="Raw events" hint="Try fixtures/raw_events_messy.jsonl. With 'Save' selected, events must belong to the selected run.">
              <textarea className={`${inputCls} h-40 font-mono text-[13px]`} value={text} onChange={(e) => setText(e.target.value)}
                placeholder='{"run_id": "...", "event_id": "...", ...}' />
            </Field>
            <input type="file" accept=".json,.jsonl,application/json" onChange={(e) => onFile(e.target.files?.[0])}
              className="text-[13px] text-muted file:mr-3 file:rounded-full file:border-0 file:bg-black/[0.05] file:px-4 file:py-1.5 file:text-[13px] file:font-medium file:text-ink hover:file:bg-black/[0.08]" />
          </div>
        )}
        <div className="mt-6 flex justify-end">
          <Button onClick={run} busy={busy}>Normalize events</Button>
        </div>
      </Card>

      {report && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat label="Input" value={report.total_input} />
          <Stat label="Valid" value={report.valid} tone="ok" />
          <Stat label="Invalid" value={report.invalid} tone={report.invalid ? "danger" : undefined} />
          <Stat label="Duplicates" value={report.duplicates} />
          <Stat label="Warnings" value={report.warnings.length} />
        </div>
      )}
      {issues && issues.length > 0 && (
        <ResultViewer title="Validation issues" rows={issues} columns={issueCols} filename="collector_issues" />
      )}
      <ResultViewer title={preview ? "Normalized events (preview)" : "Normalized events"} rows={events} columns={columns}
        filename={`normalized_events_${selectedRunId ?? "preview"}`} rowKey={(e) => e.event_id}
        empty="Normalize a run's raw events to see results here." />
      {stored.error && <p className="text-[14px] text-[#d70015]">{stored.error}</p>}
      <p className="px-1 text-[12px] text-faint">Times shown in UTC. Full ISO timestamps, the SHA-256 <code>raw_hash</code> and the untouched original event (<code>raw</code>) are in the JSON view and exports.</p>
    </div>
  );
}

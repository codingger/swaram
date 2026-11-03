import { useEffect, useState, type ReactNode } from "react";
import { api } from "../api";
import { download, type ExportFormat } from "../lib/export";
import { dateTime } from "../lib/format";
import { useAppState } from "../state";
import type { ModuleInfo, ModuleInfoPart, Run } from "../types";

export const STAGES = ["simulated", "collected", "detected", "responded", "evaluated"] as const;

export function Button({ children, variant = "primary", busy, ...props }:
  React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost"; busy?: boolean }) {
  const styles = {
    primary: "bg-zinc-900 text-white hover:bg-zinc-700 disabled:bg-zinc-400",
    secondary: "border border-zinc-300 bg-white text-zinc-800 hover:bg-zinc-100 disabled:text-zinc-400",
    ghost: "text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900",
  }[variant];
  return (
    <button {...props} disabled={props.disabled || busy}
      className={`inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${styles} ${props.className ?? ""}`}>
      {busy && <span className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" />}
      {children}
    </button>
  );
}

export function Card({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-zinc-200 bg-white ${className}`}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-100 px-4 py-2.5">
          <h2 className="text-sm font-semibold text-zinc-800">{title}</h2>
          <div className="flex flex-wrap items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-zinc-600">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-zinc-500">{hint}</span>}
    </label>
  );
}

export const inputCls = "w-full rounded-md border border-zinc-300 bg-white px-2.5 py-1.5 text-sm focus:border-zinc-500 focus:outline-none focus:ring-1 focus:ring-zinc-500";

export function Banner({ kind, children, onClose }: { kind: "error" | "success" | "info" | "warning"; children: ReactNode; onClose?: () => void }) {
  const styles = {
    error: "border-red-200 bg-red-50 text-red-800",
    success: "border-emerald-200 bg-emerald-50 text-emerald-800",
    info: "border-sky-200 bg-sky-50 text-sky-800",
    warning: "border-amber-200 bg-amber-50 text-amber-900",
  }[kind];
  return (
    <div role={kind === "error" ? "alert" : "status"} className={`flex items-start justify-between gap-3 rounded-md border px-3 py-2 text-sm ${styles}`}>
      <div className="min-w-0 break-words">{children}</div>
      {onClose && <button onClick={onClose} className="shrink-0 opacity-60 hover:opacity-100" aria-label="Dismiss">✕</button>}
    </div>
  );
}

export type Status = { kind: "error" | "success" | "info" | "warning"; message: ReactNode } | null;

export function StatusBanner({ status, onClose }: { status: Status; onClose: () => void }) {
  return status ? <Banner kind={status.kind} onClose={onClose}>{status.message}</Banner> : null;
}

const BADGE: Record<string, string> = {
  critical: "bg-red-600 text-white", high: "bg-red-100 text-red-800", medium: "bg-amber-100 text-amber-800", low: "bg-zinc-100 text-zinc-700",
  blocked: "bg-red-600 text-white", would_block: "bg-orange-100 text-orange-800", would_pause: "bg-violet-100 text-violet-800",
  alerted: "bg-amber-100 text-amber-800", allowed: "bg-zinc-100 text-zinc-700",
  denied: "bg-red-100 text-red-800", success: "bg-emerald-50 text-emerald-700", failed: "bg-zinc-200 text-zinc-700",
  open: "bg-amber-100 text-amber-800", responded: "bg-sky-100 text-sky-800", contained: "bg-emerald-100 text-emerald-800",
  simulated: "bg-sky-50 text-sky-700", enforced: "bg-red-50 text-red-700",
};

export function Badge({ value }: { value: string | null | undefined }) {
  if (!value) return null;
  return <span className={`inline-block whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-medium ${BADGE[value] ?? "bg-zinc-100 text-zinc-700"}`}>{value}</span>;
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: "danger" | "ok" }) {
  const color = tone === "danger" ? "text-red-700" : tone === "ok" ? "text-emerald-700" : "text-zinc-900";
  return (
    <div className="rounded-lg border border-zinc-200 bg-white px-4 py-3">
      <div className="text-xs text-zinc-500">{label}</div>
      <div className={`mt-0.5 text-xl font-semibold tabular-nums ${color}`}>{value}</div>
    </div>
  );
}

export function StageBadges({ run }: { run: Run }) {
  return (
    <div className="flex flex-wrap gap-1">
      {STAGES.map((s) => (
        <span key={s} title={run.stages[s] ?? "not run"}
          className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${run.stages[s] ? "bg-emerald-100 text-emerald-800" : "bg-zinc-100 text-zinc-400"}`}>
          {s}
        </span>
      ))}
    </div>
  );
}

/** Input dataset selector: which run's stored data the module reads. */
export function RunSelect({ label = "Input dataset (run)", requireStage }: { label?: string; requireStage?: string }) {
  const { runs, selectedRunId, selectRun } = useAppState();
  const run = runs.find((r) => r.run_id === selectedRunId);
  return (
    <Field label={label}>
      <select className={inputCls} value={selectedRunId ?? ""} onChange={(e) => selectRun(e.target.value || null)}>
        {!runs.length && <option value="">No runs yet: create one in Agent Simulator</option>}
        {runs.map((r) => (
          <option key={r.run_id} value={r.run_id}>
            {r.run_id} · {r.scenario_id} · {r.agent_count} agents · {dateTime(r.created_at)}
          </option>
        ))}
      </select>
      {run && (
        <div className="mt-1.5 space-y-1">
          <StageBadges run={run} />
          {requireStage && !run.stages[requireStage] && (
            <p className="text-xs text-amber-700">This run has not completed the “{requireStage}” stage yet.</p>
          )}
        </div>
      )}
    </Field>
  );
}

/** Output dataset selector: persist to the shared workspace or preview only. */
export function OutputSelect({ value, onChange, collection }: { value: boolean; onChange: (v: boolean) => void; collection: string }) {
  const { health } = useAppState();
  return (
    <Field label="Output dataset">
      <select className={inputCls} value={value ? "store" : "preview"} onChange={(e) => onChange(e.target.value === "store")}>
        <option value="store">Save to {health?.workspace ?? "default"}/{collection} ({health?.storage ?? "store"})</option>
        <option value="preview">Preview only (don't persist)</option>
      </select>
    </Field>
  );
}

export function ExportMenu({ data, filename }: { data: unknown; filename: string }) {
  const [open, setOpen] = useState(false);
  const empty = data === null || data === undefined || (Array.isArray(data) && data.length === 0);
  return (
    <div className="relative">
      <Button variant="secondary" disabled={empty} onClick={() => setOpen((o) => !o)} aria-haspopup="menu">Export ▾</Button>
      {open && (
        <div role="menu" className="absolute right-0 z-20 mt-1 w-32 rounded-md border border-zinc-200 bg-white py-1 shadow-lg" onMouseLeave={() => setOpen(false)}>
          {(["json", "jsonl", "csv"] as ExportFormat[]).map((f) => (
            <button key={f} role="menuitem" className="block w-full px-3 py-1.5 text-left text-sm hover:bg-zinc-100"
              onClick={() => { download(data, filename, f); setOpen(false); }}>
              .{f}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function JsonBlock({ value, maxHeight = "24rem" }: { value: unknown; maxHeight?: string }) {
  return (
    <pre className="overflow-auto rounded-md bg-zinc-950 p-3 font-mono text-xs leading-relaxed text-zinc-100" style={{ maxHeight }}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function InfoPart({ title, part }: { title: string; part?: ModuleInfoPart }) {
  const [view, setView] = useState<"sample" | "schema">("sample");
  if (!part) return null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold">{title}: <code className="font-mono text-xs">{part.model}</code>
          {part.fixture && <span className="ml-2 text-xs font-normal text-zinc-500">fixtures/{part.fixture}</span>}</h3>
        <div className="flex rounded-md border border-zinc-200 text-xs">
          {(["sample", "schema"] as const).map((v) => (
            <button key={v} onClick={() => setView(v)} className={`px-2 py-1 ${view === v ? "bg-zinc-900 text-white" : "text-zinc-600"}`}>{v}</button>
          ))}
        </div>
      </div>
      <JsonBlock value={view === "sample" ? part.sample ?? "(no sample fixture)" : part.schema} maxHeight="16rem" />
    </div>
  );
}

export function InfoButton({ module }: { module: string }) {
  const [open, setOpen] = useState(false);
  const [info, setInfo] = useState<ModuleInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (open && !info) api.moduleInfo(module).then(setInfo).catch((e) => setError(e.message));
  }, [open, info, module]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <>
      <button onClick={() => setOpen(true)} title="Input/output schema and sample JSON"
        className="flex h-7 w-7 items-center justify-center rounded-full border border-zinc-300 text-sm font-semibold text-zinc-600 hover:bg-zinc-100">
        i
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4 sm:p-10" onClick={() => setOpen(false)}>
          <div role="dialog" aria-modal="true" className="w-full max-w-3xl space-y-4 rounded-lg bg-white p-5 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h2 className="font-semibold">Data contract</h2>
              <button onClick={() => setOpen(false)} className="text-zinc-500 hover:text-zinc-900" aria-label="Close">✕</button>
            </div>
            {error && <Banner kind="error">{error}</Banner>}
            {!info && !error && <p className="text-sm text-zinc-500">Loading…</p>}
            {info && (
              <>
                <InfoPart title="Input" part={info.input} />
                <InfoPart title="Output" part={info.output} />
                <InfoPart title="Also returns" part={info.extra} />
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export function PageHeader({ step, title, description, module, children }: { step: number; title: string; description: string; module: string; children?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <div className="text-xs font-medium uppercase tracking-wide text-zinc-500">Module {step}</div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-semibold">{title}</h1>
          <InfoButton module={module} />
        </div>
        <p className="mt-1 max-w-2xl text-sm text-zinc-600">{description}</p>
      </div>
      {children}
    </header>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-zinc-500">{children}</p>;
}

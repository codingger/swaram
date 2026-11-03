import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../api";
import { download, type ExportFormat } from "../lib/export";
import { dateTime } from "../lib/format";
import { useAppState } from "../state";
import type { ModuleInfo, ModuleInfoPart, Run } from "../types";

export const STAGES = ["simulated", "collected", "detected", "responded", "evaluated"] as const;

export function Button({ children, variant = "primary", busy, ...props }:
  React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost"; busy?: boolean }) {
  const styles = {
    primary: "bg-accent text-white hover:bg-accent-hover",
    secondary: "bg-black/[0.05] text-ink hover:bg-black/[0.08]",
    ghost: "text-accent hover:bg-accent/[0.06]",
  }[variant];
  return (
    <button {...props} disabled={props.disabled || busy}
      className={`inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full px-[18px] py-2 text-[14px] font-medium transition-colors duration-150 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-accent/25 disabled:cursor-not-allowed disabled:opacity-40 ${styles} ${props.className ?? ""}`}>
      {busy && <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />}
      {children}
    </button>
  );
}

export function Card({ title, actions, children, className = "", flush = false }:
  { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; flush?: boolean }) {
  return (
    <section className={`rounded-[20px] bg-white shadow-card ${className}`}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-3 px-6 pt-5">
          <h2 className="text-[17px] font-semibold tracking-[-0.015em] text-ink">{title}</h2>
          <div className="flex flex-wrap items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={flush ? "pt-4" : "p-6"}>{children}</div>
    </section>
  );
}

export function Field({ label, hint, children, asDiv = false }: { label: string; hint?: ReactNode; children: ReactNode; asDiv?: boolean }) {
  const Tag = asDiv ? "div" : "label";
  return (
    <Tag className="block">
      <span className="mb-1.5 block text-[13px] font-medium text-muted">{label}</span>
      {children}
      {hint && <span className="mt-1.5 block text-[12px] leading-snug text-faint">{hint}</span>}
    </Tag>
  );
}

export const inputCls =
  "w-full rounded-xl border border-line bg-white px-3.5 py-2 text-[14px] text-ink transition placeholder:text-faint focus:border-accent focus:outline-none focus:ring-4 focus:ring-accent/15";

/** iOS/macOS-style segmented control. */
export function Segmented<T extends string | number>({ options, value, onChange, full = false, size = "md" }: {
  options: { value: T; label: ReactNode }[]; value: T; onChange: (v: T) => void; full?: boolean; size?: "sm" | "md";
}) {
  return (
    <div role="radiogroup" className={`${full ? "flex w-full" : "inline-flex"} rounded-[10px] bg-black/[0.06] p-[3px]`}>
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button key={String(o.value)} type="button" role="radio" aria-checked={on} onClick={() => onChange(o.value)}
            className={`${full ? "flex-1" : ""} rounded-[8px] font-medium transition-all duration-150 ${size === "sm" ? "px-3 py-1 text-[12px]" : "px-3.5 py-1.5 text-[13px]"} ${on ? "bg-white text-ink shadow-[0_1px_3px_rgba(0,0,0,0.12)]" : "text-muted hover:text-ink"}`}>
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

export function Banner({ kind, children, onClose }: { kind: "error" | "success" | "info" | "warning"; children: ReactNode; onClose?: () => void }) {
  const styles = {
    error: "bg-[#fff1f0] text-[#c4161c]",
    success: "bg-[#edfaf1] text-[#1b7a3a]",
    info: "bg-[#eef5ff] text-[#0058b0]",
    warning: "bg-[#fff7e8] text-[#935400]",
  }[kind];
  return (
    <div role={kind === "error" ? "alert" : "status"} className={`flex items-start justify-between gap-3 rounded-2xl px-4 py-3 text-[14px] leading-relaxed ${styles}`}>
      <div className="min-w-0 break-words">{children}</div>
      {onClose && (
        <button onClick={onClose} className="-mr-1 shrink-0 rounded-full p-1 opacity-50 transition hover:bg-black/5 hover:opacity-100" aria-label="Dismiss">
          <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden><path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
        </button>
      )}
    </div>
  );
}

export type Status = { kind: "error" | "success" | "info" | "warning"; message: ReactNode } | null;

export function StatusBanner({ status, onClose }: { status: Status; onClose: () => void }) {
  return status ? <Banner kind={status.kind} onClose={onClose}>{status.message}</Banner> : null;
}

const RED = "bg-[#ff3b30]/10 text-[#d70015]";
const ORANGE = "bg-[#ff9500]/12 text-[#a35200]";
const GREEN = "bg-[#34c759]/14 text-[#1f7a37]";
const BLUE = "bg-[#0071e3]/10 text-[#0058b0]";
const GRAY = "bg-black/[0.05] text-muted";
const BADGE: Record<string, string> = {
  critical: "bg-[#ff3b30] text-white", high: RED, medium: ORANGE, low: GRAY,
  blocked: "bg-[#ff3b30] text-white", would_block: ORANGE, would_pause: "bg-[#af52de]/12 text-[#8a3cad]",
  alerted: ORANGE, allowed: GRAY,
  denied: RED, success: GREEN, failed: GRAY, pending: GRAY,
  open: ORANGE, responded: BLUE, contained: GREEN,
  simulated: BLUE, enforced: RED, error: RED, warning: ORANGE,
};

export function Badge({ value }: { value: string | null | undefined }) {
  if (!value) return null;
  return <span className={`inline-block whitespace-nowrap rounded-full px-2.5 py-[3px] text-[12px] font-medium leading-none ${BADGE[value] ?? GRAY}`}>{value.replace(/_/g, " ")}</span>;
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: "danger" | "ok" }) {
  const color = tone === "danger" ? "text-[#d70015]" : tone === "ok" ? "text-[#1f7a37]" : "text-ink";
  return (
    <div className="rounded-[18px] bg-white px-5 py-4 shadow-card">
      <div className="text-[13px] text-muted">{label}</div>
      <div className={`mt-1 text-[28px] font-semibold leading-tight tracking-[-0.02em] tabular-nums ${color}`}>{value}</div>
    </div>
  );
}

/** Pipeline progress as a compact stepper. */
export function StageBadges({ run }: { run: Run }) {
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
      {STAGES.map((s) => {
        const done = !!run.stages[s];
        return (
          <span key={s} title={run.stages[s] ?? "not run"} className={`flex items-center gap-1 text-[11px] font-medium ${done ? "text-[#1f7a37]" : "text-faint"}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${done ? "bg-[#34c759]" : "bg-black/15"}`} />
            {s}
          </span>
        );
      })}
    </div>
  );
}

/** Input dataset selector: which run's stored data the module reads. */
export function RunSelect({ label = "Input dataset", requireStage }: { label?: string; requireStage?: string }) {
  const { runs, selectedRunId, selectRun } = useAppState();
  const run = runs.find((r) => r.run_id === selectedRunId);
  return (
    <Field label={label}>
      <select className={inputCls} value={selectedRunId ?? ""} onChange={(e) => selectRun(e.target.value || null)}>
        {!runs.length && <option value="">No runs yet. Create one in Agent Simulator.</option>}
        {runs.map((r) => (
          <option key={r.run_id} value={r.run_id}>
            {r.run_id} · {r.scenario_id} · {r.agent_count} agents · {dateTime(r.created_at)}
          </option>
        ))}
      </select>
      {run && (
        <div className="mt-2 space-y-1">
          <StageBadges run={run} />
          {requireStage && !run.stages[requireStage] && (
            <p className="text-[12px] text-[#935400]">This run hasn't completed the “{requireStage}” stage yet.</p>
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
        <option value="preview">Preview only (don't save)</option>
      </select>
    </Field>
  );
}

export function ExportMenu({ data, filename }: { data: unknown; filename: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const empty = data === null || data === undefined || (Array.isArray(data) && data.length === 0);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);
  return (
    <div className="relative" ref={ref}>
      <Button variant="secondary" disabled={empty} onClick={() => setOpen((o) => !o)} aria-haspopup="menu" className="!px-4 !py-1.5 !text-[13px]">
        Export
        <svg width="10" height="6" viewBox="0 0 12 8" aria-hidden><path d="M1 1.5l5 5 5-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>
      </Button>
      {open && (
        <div role="menu" className="absolute right-0 z-20 mt-2 w-40 overflow-hidden rounded-xl bg-white/95 p-1 shadow-pop ring-1 ring-black/5 backdrop-blur-xl">
          {(["json", "jsonl", "csv"] as ExportFormat[]).map((f) => (
            <button key={f} role="menuitem" className="block w-full rounded-lg px-3 py-1.5 text-left text-[13px] text-ink hover:bg-accent hover:text-white"
              onClick={() => { download(data, filename, f); setOpen(false); }}>
              Download .{f}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function JsonBlock({ value, maxHeight = "24rem" }: { value: unknown; maxHeight?: string }) {
  return (
    <pre className="overflow-auto rounded-2xl bg-[#1d1d1f] p-4 font-mono text-[12px] leading-relaxed text-[#f5f5f7]" style={{ maxHeight }}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function InfoPart({ title, part }: { title: string; part?: ModuleInfoPart }) {
  const [view, setView] = useState<"sample" | "schema">("sample");
  if (!part) return null;
  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-[15px] font-semibold">{title} <code className="ml-1 font-mono text-[13px] font-normal text-muted">{part.model}</code></h3>
          {part.fixture && <div className="text-[12px] text-faint">fixtures/{part.fixture}</div>}
        </div>
        <Segmented size="sm" value={view} onChange={setView} options={[{ value: "sample", label: "Sample" }, { value: "schema", label: "Schema" }]} />
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
      <button onClick={() => setOpen(true)} title="Data contract: input/output schema and sample JSON" aria-label="Show data contract"
        className="flex h-7 w-7 items-center justify-center rounded-full text-faint transition hover:bg-black/[0.05] hover:text-accent">
        <svg width="18" height="18" viewBox="0 0 20 20" aria-hidden>
          <circle cx="10" cy="10" r="8.25" fill="none" stroke="currentColor" strokeWidth="1.5" />
          <path d="M10 9v5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          <circle cx="10" cy="6.2" r="1" fill="currentColor" />
        </svg>
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/25 p-4 backdrop-blur-sm sm:p-12" onClick={() => setOpen(false)}>
          <div role="dialog" aria-modal="true" className="w-full max-w-3xl space-y-6 rounded-[24px] bg-white p-6 shadow-pop sm:p-8" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="text-[24px] font-semibold tracking-[-0.02em]">Data contract</h2>
                <p className="text-[14px] text-muted">What this module reads and writes.</p>
              </div>
              <button onClick={() => setOpen(false)} aria-label="Close"
                className="flex h-8 w-8 items-center justify-center rounded-full bg-black/[0.05] text-muted hover:bg-black/[0.08] hover:text-ink">
                <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden><path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
              </button>
            </div>
            {error && <Banner kind="error">{error}</Banner>}
            {!info && !error && <p className="text-[14px] text-muted">Loading…</p>}
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
    <header className="flex flex-wrap items-end justify-between gap-4 pb-2">
      <div className="min-w-0">
        <div className="text-[14px] font-semibold text-[#bf4800]">Module {step}</div>
        <div className="mt-1 flex items-center gap-2">
          <h1 className="text-[32px] font-semibold leading-[1.1] tracking-[-0.025em] sm:text-[40px]">{title}</h1>
          <InfoButton module={module} />
        </div>
        <p className="mt-3 max-w-2xl text-[17px] leading-relaxed text-muted">{description}</p>
      </div>
      {children}
    </header>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-10 text-center text-[14px] text-faint">{children}</p>;
}

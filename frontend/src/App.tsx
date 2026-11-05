import { useEffect, useState } from "react";
import { Banner, StageBadges } from "./components/ui";
import { dateTime } from "./lib/format";
import { CollectorPage } from "./pages/CollectorPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DetectionPage } from "./pages/DetectionPage";
import { LivePage } from "./pages/LivePage";
import { ResponsePage } from "./pages/ResponsePage";
import { SimulatorPage } from "./pages/SimulatorPage";
import { useAppState } from "./state";

const PAGES = [
  { id: "simulator", label: "Agent Simulator", Component: SimulatorPage },
  { id: "collector", label: "Event Collector", Component: CollectorPage },
  { id: "detection", label: "Threat Detection", Component: DetectionPage },
  { id: "response", label: "Security Response", Component: ResponsePage },
  { id: "dashboard", label: "Dashboard & Evaluation", Component: DashboardPage },
  { id: "live", label: "Live monitor", Component: LivePage },
] as const;

function useHashRoute(): string {
  const read = () => window.location.hash.replace(/^#\/?/, "") || "simulator";
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const onChange = () => setRoute(read());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <span className="flex h-8 w-8 items-center justify-center rounded-[9px] bg-ink text-white">
        <svg width="16" height="18" viewBox="0 0 16 18" aria-hidden>
          <path d="M8 1.2l6 2.3v4.8c0 4-2.6 7.2-6 8.5-3.4-1.3-6-4.5-6-8.5V3.5l6-2.3z" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
          <path d="M5.3 9l1.9 1.9 3.6-3.8" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
      <div className="leading-tight">
        <div className="text-[17px] font-semibold tracking-[-0.02em]">SwarmGuard</div>
        <div className="text-[12px] text-faint">Multi-agent security</div>
      </div>
    </div>
  );
}

function Sidebar({ route, onNavigate }: { route: string; onNavigate: () => void }) {
  const { runs, selectedRunId, selectRun, health } = useAppState();
  return (
    <nav className="flex h-full flex-col gap-7 overflow-y-auto px-4 py-6">
      <div className="hidden px-2 lg:block"><Logo /></div>
      <div>
        <div className="mb-2 px-3 text-[12px] font-semibold text-faint">Pipeline</div>
        <ol className="space-y-0.5">
          {PAGES.map((p, i) => {
            const on = route === p.id;
            return (
              <li key={p.id}>
                <a href={`#/${p.id}`} onClick={onNavigate} aria-current={on ? "page" : undefined}
                  className={`flex items-center gap-3 rounded-[10px] px-3 py-2 text-[14px] transition-colors ${on ? "bg-white font-medium text-ink shadow-[0_1px_3px_rgba(0,0,0,0.08)]" : "text-[#424245] hover:bg-black/[0.04]"}`}>
                  <span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold tabular-nums ${on ? "bg-accent text-white" : "bg-black/[0.06] text-muted"}`}>{i + 1}</span>
                  {p.label}
                </a>
              </li>
            );
          })}
        </ol>
      </div>
      <div className="min-h-0 flex-1">
        <div className="mb-2 px-3 text-[12px] font-semibold text-faint">Recent runs</div>
        {!runs.length && <p className="px-3 text-[13px] text-faint">No runs yet.</p>}
        <ul className="space-y-1">
          {runs.slice(0, 12).map((r) => {
            const on = r.run_id === selectedRunId;
            return (
              <li key={r.run_id}>
                <button onClick={() => { selectRun(r.run_id); onNavigate(); }}
                  className={`w-full rounded-xl px-3 py-2.5 text-left transition-colors ${on ? "bg-white shadow-[0_1px_3px_rgba(0,0,0,0.08)]" : "hover:bg-black/[0.04]"}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-[12px] text-ink">{r.run_id}</span>
                    <span className="shrink-0 text-[11px] text-faint">{dateTime(r.created_at)}</span>
                  </div>
                  <div className="mt-0.5 truncate text-[12px] text-muted">{r.scenario_id.replace(/_/g, " ")} · {r.agent_count} agents · {r.gateway_mode}</div>
                  {on && <div className="mt-2"><StageBadges run={r} /></div>}
                </button>
              </li>
            );
          })}
        </ul>
      </div>
      <div className="flex items-center gap-2 px-3 text-[12px] text-faint">
        <span className={`h-1.5 w-1.5 rounded-full ${health ? "bg-[#34c759]" : "bg-black/20"}`} />
        {health ? <>{health.storage} · workspace “{health.workspace}”</> : "connecting…"}
      </div>
    </nav>
  );
}

export default function App() {
  const route = useHashRoute();
  const { apiError } = useAppState();
  const [menuOpen, setMenuOpen] = useState(false);
  const page = PAGES.find((p) => p.id === route) ?? PAGES[0];
  const Page = page.Component;

  return (
    <div className="min-h-screen bg-canvas text-ink lg:flex">
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-black/[0.06] bg-white/75 px-4 py-3 backdrop-blur-xl lg:hidden">
        <Logo />
        <button onClick={() => setMenuOpen((o) => !o)} aria-expanded={menuOpen}
          className="rounded-full bg-black/[0.05] px-4 py-1.5 text-[13px] font-medium hover:bg-black/[0.08]">
          {menuOpen ? "Close" : "Menu"}
        </button>
      </header>
      <aside className={`${menuOpen ? "block" : "hidden"} border-b border-black/[0.06] bg-[#ececf0]/80 backdrop-blur-xl lg:sticky lg:top-0 lg:block lg:h-screen lg:w-[280px] lg:shrink-0 lg:border-b-0 lg:border-r`}>
        <Sidebar route={page.id} onNavigate={() => setMenuOpen(false)} />
      </aside>
      <main className="min-w-0 flex-1 px-4 py-8 sm:px-8 lg:px-12 lg:py-12">
        <div className="mx-auto max-w-[1080px] space-y-6">
          {apiError && (
            <Banner kind="error">
              {apiError} Start it with <code className="font-mono">uvicorn app.main:app --reload</code> in <code className="font-mono">backend/</code>.
            </Banner>
          )}
          <Page key={page.id} />
        </div>
      </main>
    </div>
  );
}

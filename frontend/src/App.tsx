import { useEffect, useState } from "react";
import { StageBadges } from "./components/ui";
import { dateTime } from "./lib/format";
import { CollectorPage } from "./pages/CollectorPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DetectionPage } from "./pages/DetectionPage";
import { ResponsePage } from "./pages/ResponsePage";
import { SimulatorPage } from "./pages/SimulatorPage";
import { useAppState } from "./state";

const PAGES = [
  { id: "simulator", label: "Agent Simulator", Component: SimulatorPage },
  { id: "collector", label: "Event Collector", Component: CollectorPage },
  { id: "detection", label: "Threat Detection", Component: DetectionPage },
  { id: "response", label: "Security Response", Component: ResponsePage },
  { id: "dashboard", label: "Dashboard & Evaluation", Component: DashboardPage },
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

function Sidebar({ route, onNavigate }: { route: string; onNavigate: () => void }) {
  const { runs, selectedRunId, selectRun, health } = useAppState();
  return (
    <nav className="flex h-full flex-col gap-6 overflow-y-auto p-4">
      <div className="hidden lg:block">
        <div className="flex items-center gap-2 font-semibold"><span className="flex h-6 w-6 items-center justify-center rounded bg-zinc-900 text-xs text-white">SG</span>SwarmGuard</div>
        <div className="mt-0.5 text-xs text-zinc-500">Multi-agent security pipeline</div>
      </div>
      <ol className="space-y-0.5">
        {PAGES.map((p, i) => (
          <li key={p.id}>
            <a href={`#/${p.id}`} onClick={onNavigate}
              className={`flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm ${route === p.id ? "bg-zinc-900 text-white" : "text-zinc-700 hover:bg-zinc-200/60"}`}>
              <span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded text-[11px] font-semibold ${route === p.id ? "bg-white/20" : "bg-zinc-200 text-zinc-600"}`}>{i + 1}</span>
              {p.label}
            </a>
          </li>
        ))}
      </ol>
      <div className="min-h-0 flex-1">
        <div className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">Recent runs</div>
        {!runs.length && <p className="text-xs text-zinc-500">No runs yet.</p>}
        <ul className="space-y-1">
          {runs.slice(0, 12).map((r) => (
            <li key={r.run_id}>
              <button onClick={() => { selectRun(r.run_id); onNavigate(); }}
                className={`w-full rounded-md border px-2 py-1.5 text-left ${r.run_id === selectedRunId ? "border-zinc-900 bg-white" : "border-transparent hover:bg-zinc-200/60"}`}>
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-xs">{r.run_id}</span>
                  <span className="shrink-0 text-[10px] text-zinc-500">{dateTime(r.created_at)}</span>
                </div>
                <div className="truncate text-[11px] text-zinc-600">{r.scenario_id} · {r.agent_count} agents · {r.gateway_mode}</div>
                {r.run_id === selectedRunId && <div className="mt-1"><StageBadges run={r} /></div>}
              </button>
            </li>
          ))}
        </ul>
      </div>
      <div className="text-[11px] text-zinc-500">
        Storage: <span className="font-medium">{health?.storage ?? "?"}</span> · workspace <span className="font-medium">{health?.workspace ?? "?"}</span>
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
    <div className="min-h-screen lg:flex">
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-zinc-200 bg-zinc-100 px-4 py-2.5 lg:hidden">
        <div className="flex items-center gap-2 font-semibold"><span className="flex h-6 w-6 items-center justify-center rounded bg-zinc-900 text-xs text-white">SG</span>SwarmGuard</div>
        <button onClick={() => setMenuOpen((o) => !o)} className="rounded-md border border-zinc-300 bg-white px-2.5 py-1 text-sm" aria-expanded={menuOpen}>
          {menuOpen ? "Close" : "Menu"}
        </button>
      </header>
      <aside className={`${menuOpen ? "block" : "hidden"} border-b border-zinc-200 bg-zinc-100 lg:sticky lg:top-0 lg:block lg:h-screen lg:w-72 lg:shrink-0 lg:border-b-0 lg:border-r`}>
        <Sidebar route={page.id} onNavigate={() => setMenuOpen(false)} />
      </aside>
      <main className="min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-6xl space-y-4">
          {apiError && (
            <div role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
              {apiError} Start it with <code className="font-mono">uvicorn app.main:app --reload</code> in <code className="font-mono">backend/</code>.
            </div>
          )}
          <Page key={page.id} />
        </div>
      </main>
    </div>
  );
}

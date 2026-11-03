import type { TimelineItem } from "../types";
import { Empty } from "./ui";

const TYPE_COLOR: Record<string, string> = {
  message: "#a1a1aa", task: "#d4d4d8", tool_call: "#6366f1", resource_access: "#0ea5e9", data_transfer: "#f59e0b",
};

/** One lane per agent, events plotted by timestamp; flagged events are red. */
export function Timeline({ items, onSelect }: { items: TimelineItem[]; onSelect?: (eventId: string) => void }) {
  if (!items.length) return <Empty>No normalized events yet.</Empty>;
  const agents = Array.from(new Set(items.map((i) => i.agent_id))).sort();
  const times = items.map((i) => new Date(i.timestamp).getTime());
  const t0 = Math.min(...times), t1 = Math.max(...times), span = Math.max(1, t1 - t0);
  const lane = 22, left = 70, W = 640, H = agents.length * lane + 24;
  const x = (t: number) => left + ((W - left - 12) * (t - t0)) / span;

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Event timeline">
        {agents.map((a, i) => (
          <g key={a}>
            <line x1={left} x2={W - 8} y1={i * lane + 12} y2={i * lane + 12} stroke="#f4f4f5" />
            <text x={left - 8} y={i * lane + 16} textAnchor="end" fontSize="10" fill="#52525b">{a.split("-").pop()}</text>
          </g>
        ))}
        {items.map((it) => {
          const yi = agents.indexOf(it.agent_id);
          return (
            <circle key={it.event_id} cx={x(new Date(it.timestamp).getTime())} cy={yi * lane + 12}
              r={it.flagged ? 5 : 3.2} fill={it.flagged ? "#dc2626" : TYPE_COLOR[it.event_type] ?? "#71717a"}
              stroke={it.status === "denied" ? "#000" : "none"} strokeWidth={1.5}
              className={onSelect ? "cursor-pointer" : ""} onClick={() => onSelect?.(it.event_id)}>
              <title>{`${it.timestamp}\n${it.summary}`}</title>
            </circle>
          );
        })}
        <text x={left} y={H - 4} fontSize="10" fill="#a1a1aa">{new Date(t0).toLocaleTimeString()}</text>
        <text x={W - 8} y={H - 4} fontSize="10" fill="#a1a1aa" textAnchor="end">{new Date(t1).toLocaleTimeString()}</text>
      </svg>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-600">
        {Object.entries(TYPE_COLOR).map(([k, c]) => (
          <span key={k} className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full" style={{ background: c }} />{k}</span>
        ))}
        <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-red-600" />cited by alert</span>
        <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full border-2 border-black" />denied</span>
      </div>
    </div>
  );
}

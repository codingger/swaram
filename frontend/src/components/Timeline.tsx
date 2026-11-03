import type { TimelineItem } from "../types";
import { Empty } from "./ui";

const TYPE_COLOR: Record<string, string> = {
  message: "#c7c7cc", task: "#aeaeb2", tool_call: "#5e5ce6", resource_access: "#0071e3", data_transfer: "#ff9500",
};
const RED = "#ff3b30";

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
            <line x1={left} x2={W - 8} y1={i * lane + 12} y2={i * lane + 12} stroke="#f2f2f7" strokeWidth={1.5} strokeLinecap="round" />
            <text x={left - 10} y={i * lane + 16} textAnchor="end" fontSize="10.5" fill="#6e6e73">agent {a.split("-").pop()}</text>
          </g>
        ))}
        {items.map((it) => {
          const yi = agents.indexOf(it.agent_id);
          return (
            <circle key={it.event_id} cx={x(new Date(it.timestamp).getTime())} cy={yi * lane + 12}
              r={it.flagged ? 5 : 3.2} fill={it.flagged ? RED : TYPE_COLOR[it.event_type] ?? "#8e8e93"}
              stroke={it.status === "denied" ? "#1d1d1f" : "none"} strokeWidth={1.5}
              className={onSelect ? "cursor-pointer" : ""} onClick={() => onSelect?.(it.event_id)}>
              <title>{`${it.timestamp}\n${it.summary}`}</title>
            </circle>
          );
        })}
        <text x={left} y={H - 4} fontSize="10" fill="#86868b">{new Date(t0).toLocaleTimeString()}</text>
        <text x={W - 8} y={H - 4} fontSize="10" fill="#86868b" textAnchor="end">{new Date(t1).toLocaleTimeString()}</text>
      </svg>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[12px] text-muted">
        {Object.entries(TYPE_COLOR).map(([k, c]) => (
          <span key={k} className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: c }} />{k.replace("_", " ")}</span>
        ))}
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-[#ff3b30]" />cited by alert</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border-2 border-ink" />denied</span>
      </div>
    </div>
  );
}

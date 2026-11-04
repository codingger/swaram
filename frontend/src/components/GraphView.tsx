import { useState } from "react";
import type { AgentGraph } from "../types";
import { Empty } from "./ui";

const ROLE_COLOR: Record<string, string> = {
  planner: "#5e5ce6", analyst: "#0071e3", coder: "#30b158", researcher: "#ff9500", reviewer: "#af52de",
};
const RED = "#ff3b30";
const EDGE = "#c7c7cc";
const HIDDEN = "#af52de";
const EDGE_COLOR = { message: EDGE, data_transfer: RED, indirect: HIDDEN } as const;

/** Circular layout of the agent communication graph; external sinks sit on the right. */
export function GraphView({ graph, height = 360 }: { graph: AgentGraph | null | undefined; height?: number }) {
  const [hover, setHover] = useState<string | null>(null);
  if (!graph || graph.nodes.length === 0) return <Empty>No graph yet: run the collector and detection.</Empty>;

  const W = 640, H = height;
  const agents = graph.nodes.filter((n) => n.kind === "agent");
  const externals = graph.nodes.filter((n) => n.kind === "external");
  const cx = externals.length ? W * 0.4 : W / 2, cy = H / 2, R = Math.min(cx, cy) - 40;
  const pos: Record<string, { x: number; y: number }> = {};
  agents.forEach((n, i) => {
    const a = (2 * Math.PI * i) / agents.length - Math.PI / 2;
    pos[n.id] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
  });
  externals.forEach((n, i) => {
    pos[n.id] = { x: W - 90, y: ((i + 1) * H) / (externals.length + 1) };
  });
  const maxCount = Math.max(1, ...graph.edges.map((e) => e.count));
  const active = (id: string) => !hover || hover === id || graph.edges.some((e) => (e.source === hover && e.target === id) || (e.target === hover && e.source === id));

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Agent communication graph">
        <defs>
          {(Object.keys(EDGE_COLOR) as (keyof typeof EDGE_COLOR)[]).map((k) => (
            <marker key={k} id={`arrow-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill={EDGE_COLOR[k]} />
            </marker>
          ))}
        </defs>
        {graph.edges.map((e) => {
          const s = pos[e.source], t = pos[e.target];
          if (!s || !t) return null;
          const dx = t.x - s.x, dy = t.y - s.y, len = Math.hypot(dx, dy) || 1;
          const off = 16;
          const x1 = s.x + (dx / len) * off, y1 = s.y + (dy / len) * off, x2 = t.x - (dx / len) * (off + 2), y2 = t.y - (dy / len) * (off + 2);
          // slight curve so reciprocal edges don't overlap
          const mx = (x1 + x2) / 2 - (dy / len) * 12, my = (y1 + y2) / 2 + (dx / len) * 12;
          const hidden = e.kind === "indirect";
          const dim = hover && e.source !== hover && e.target !== hover;
          return (
            <path key={`${e.source}-${e.target}`} d={`M${x1},${y1} Q${mx},${my} ${x2},${y2}`} fill="none"
              stroke={EDGE_COLOR[e.kind]} strokeWidth={hidden ? 2.5 : 1 + (3 * e.count) / maxCount} strokeOpacity={dim ? 0.12 : 0.9} strokeLinecap="round"
              strokeDasharray={hidden ? "5 4" : undefined} markerEnd={`url(#arrow-${e.kind})`}>
              <title>{`${e.source} → ${e.target}: ${e.count} ${e.kind}(s)`}</title>
            </path>
          );
        })}
        {graph.nodes.map((n) => {
          const p = pos[n.id];
          const ext = n.kind === "external";
          const label = ext ? n.id.replace("external:", "") : n.id.split("-").pop();
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`} opacity={active(n.id) ? 1 : 0.25}
              onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)} className="cursor-default">
              {n.flagged && !ext && <circle r={20} fill={RED} fillOpacity={0.12} />}
              {ext ? (
                <rect x={-14} y={-14} width={28} height={28} rx={8} fill="#fff" stroke={RED} strokeWidth={1.5} />
              ) : (
                <circle r={14} fill={ROLE_COLOR[n.role ?? ""] ?? "#8e8e93"} stroke={n.flagged ? RED : "#fff"} strokeWidth={n.flagged ? 3 : 2} />
              )}
              <text y={4} textAnchor="middle" fontSize="10" fontWeight="600" fill={ext ? RED : "#fff"}>{ext ? "EXT" : label}</text>
              <text y={30} textAnchor="middle" fontSize="10.5" fill="#6e6e73">{ext ? label : n.role}</text>
              <title>{`${n.id}${n.role ? ` (${n.role})` : ""}\nevents: ${n.event_count}\ndegree: ${n.degree_centrality}\nbetweenness: ${n.betweenness}${n.flagged ? "\nFLAGGED" : ""}`}</title>
            </g>
          );
        })}
      </svg>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[12px] text-muted">
        {Object.entries(ROLE_COLOR).map(([r, c]) => (
          <span key={r} className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: c }} />{r}</span>
        ))}
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border-2 border-[#ff3b30]" />flagged</span>
        <span className="flex items-center gap-1.5"><span className="h-0.5 w-4 rounded bg-[#ff3b30]" />external transfer</span>
        <span className="flex items-center gap-1.5"><span className="w-4 border-t-2 border-dashed border-[#af52de]" />hidden channel</span>
      </div>
    </div>
  );
}

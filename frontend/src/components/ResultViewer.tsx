import { useMemo, useState, type ReactNode } from "react";
import { Card, Empty, ExportMenu, JsonBlock, Segmented } from "./ui";

export interface Column<T> {
  key: string;
  label: string;
  render?: (row: T) => ReactNode;
  className?: string;
}

const PAGE = 100;

/** Table + JSON viewer with filtering and export, used by every module page. */
export function ResultViewer<T extends object>({ title, rows, columns, filename, onRowClick, selectedKey, rowKey, empty, extraActions }: {
  title: ReactNode;
  rows: T[] | null;
  columns: Column<T>[];
  filename: string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
  rowKey?: (row: T) => string;
  empty?: ReactNode;
  extraActions?: ReactNode;
}) {
  const [view, setView] = useState<"table" | "json">("table");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(PAGE);

  const filtered = useMemo(() => {
    if (!rows) return [];
    const q = query.trim().toLowerCase();
    return q ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(q)) : rows;
  }, [rows, query]);

  return (
    <Card flush
      title={<>{title}{rows && <span className="ml-2 text-[15px] font-normal text-faint">{query ? `${filtered.length} of ${rows.length}` : rows.length}</span>}</>}
      actions={
        <>
          {extraActions}
          <div className="relative">
            <svg className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" width="13" height="13" viewBox="0 0 16 16" aria-hidden>
              <circle cx="7" cy="7" r="5.25" fill="none" stroke="currentColor" strokeWidth="1.6" />
              <path d="M11 11l3.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
            <input aria-label="Filter rows" placeholder="Search" value={query} onChange={(e) => { setQuery(e.target.value); setLimit(PAGE); }}
              className="w-40 rounded-full bg-black/[0.05] py-1.5 pl-8 pr-3 text-[13px] text-ink placeholder:text-faint focus:bg-white focus:outline-none focus:ring-4 focus:ring-accent/15" />
          </div>
          <Segmented size="sm" value={view} onChange={setView} options={[{ value: "table", label: "Table" }, { value: "json", label: "JSON" }]} />
          <ExportMenu data={filtered} filename={filename} />
        </>
      }
    >
      {!rows || rows.length === 0 ? (
        <div className="px-6 pb-4"><Empty>{empty ?? "No data yet."}</Empty></div>
      ) : view === "json" ? (
        <div className="px-6 pb-6"><JsonBlock value={filtered.slice(0, limit)} maxHeight="32rem" /></div>
      ) : (
        <div className="max-h-[32rem] overflow-auto pb-2">
          <table className="w-full min-w-max text-left text-[13px]">
            <thead className="sticky top-0 z-10 bg-white/95 backdrop-blur">
              <tr>
                {columns.map((c, i) => (
                  <th key={c.key} className={`border-b border-black/[0.08] py-2.5 pr-4 text-[12px] font-medium text-faint ${i === 0 ? "pl-6" : ""}`}>{c.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, limit).map((row, i) => {
                const key = rowKey ? rowKey(row) : String(i);
                return (
                  <tr key={key} onClick={onRowClick ? () => onRowClick(row) : undefined}
                    className={`border-b border-black/[0.05] text-ink transition-colors last:border-0 ${onRowClick ? "cursor-pointer" : ""} ${selectedKey === key ? "bg-accent/[0.07]" : "hover:bg-canvas"}`}>
                    {columns.map((c, ci) => (
                      <td key={c.key} className={`py-2.5 pr-4 align-top ${ci === 0 ? "pl-6" : ""} ${c.className ?? ""}`}>
                        {c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? "")}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {filtered.length > limit && (
        <div className="border-t border-black/[0.05] py-3 text-center">
          <button className="text-[13px] font-medium text-accent hover:underline" onClick={() => setLimit((l) => l + PAGE)}>
            Show more ({filtered.length - limit} remaining)
          </button>
        </div>
      )}
    </Card>
  );
}

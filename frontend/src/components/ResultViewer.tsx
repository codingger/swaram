import { useMemo, useState, type ReactNode } from "react";
import { Card, Empty, ExportMenu, JsonBlock, inputCls } from "./ui";

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
    <Card
      title={<>{title} <span className="ml-1 font-normal text-zinc-500">{rows ? `${filtered.length}${query ? ` / ${rows.length}` : ""}` : ""}</span></>}
      actions={
        <>
          {extraActions}
          <input aria-label="Filter rows" placeholder="Filter…" value={query} onChange={(e) => { setQuery(e.target.value); setLimit(PAGE); }}
            className={`${inputCls} !w-36 !py-1`} />
          <div className="flex rounded-md border border-zinc-200 text-xs">
            {(["table", "json"] as const).map((v) => (
              <button key={v} onClick={() => setView(v)} className={`px-2.5 py-1.5 ${view === v ? "bg-zinc-900 text-white" : "text-zinc-600 hover:bg-zinc-50"}`}>
                {v === "table" ? "Table" : "JSON"}
              </button>
            ))}
          </div>
          <ExportMenu data={filtered} filename={filename} />
        </>
      }
    >
      {!rows || rows.length === 0 ? (
        <Empty>{empty ?? "No data yet."}</Empty>
      ) : view === "json" ? (
        <JsonBlock value={filtered.slice(0, limit)} maxHeight="32rem" />
      ) : (
        <div className="-mx-4 -my-4 max-h-[32rem] overflow-auto">
          <table className="w-full min-w-max text-left text-xs">
            <thead className="sticky top-0 z-10 bg-zinc-50 text-zinc-500">
              <tr>{columns.map((c) => <th key={c.key} className="border-b border-zinc-200 px-3 py-2 font-medium">{c.label}</th>)}</tr>
            </thead>
            <tbody>
              {filtered.slice(0, limit).map((row, i) => {
                const key = rowKey ? rowKey(row) : String(i);
                return (
                  <tr key={key} onClick={onRowClick ? () => onRowClick(row) : undefined}
                    className={`border-b border-zinc-100 ${onRowClick ? "cursor-pointer hover:bg-zinc-50" : ""} ${selectedKey === key ? "bg-sky-50" : ""}`}>
                    {columns.map((c) => (
                      <td key={c.key} className={`px-3 py-1.5 align-top ${c.className ?? ""}`}>
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
        <div className="mt-3 text-center">
          <button className="text-xs text-sky-700 hover:underline" onClick={() => setLimit((l) => l + PAGE)}>
            Show more ({filtered.length - limit} remaining)
          </button>
        </div>
      )}
    </Card>
  );
}

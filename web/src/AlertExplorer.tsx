import { useEffect, useState } from "react";
import { CombinedExport } from "./CombinedExport";
import {
  NAMES,
  count,
  engineNames,
  useApi,
  type AlertPage,
  type AlertRow,
  type Engine,
  type Options,
} from "./api";
import { stamp } from "./time";

type Column = { title: string; value: (row: AlertRow) => string; className?: string };

const TIME: Column = { title: "Time", value: (row) => stamp(row.time_ms) };
const GID: Column = { title: "GID", value: (row) => String(row.gid ?? ""), className: "number" };
const SID: Column = { title: "SID", value: (row) => String(row.sid ?? ""), className: "number" };
const REV: Column = { title: "Rev", value: (row) => String(row.rev ?? ""), className: "number" };
const SEVERITY: Column = { title: "Severity", value: (row) => String(row.severity), className: "number" };
// The message comes last: it can be long.
const MESSAGE: Column = { title: "Message", value: (row) => row.message, className: "message" };
const PANEL_COLUMNS = [TIME, GID, SID, REV, SEVERITY, MESSAGE];
const TABLE_COLUMNS: Column[] = [
  TIME,
  { title: "Engine", value: (row) => NAMES[row.engine] ?? row.engine },
  GID,
  SID,
  REV,
  SEVERITY,
  { title: "Protocol", value: (row) => row.protocol ?? "" },
  { title: "Source", value: (row) => row.src ?? "" },
  { title: "Destination", value: (row) => row.dst ?? "" },
  MESSAGE,
];

function useDebounced<T>(value: T, delayMs: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delayMs);
    return () => window.clearTimeout(timer);
  }, [value, delayMs]);
  return settled;
}

export function AlertExplorer({ options, onUnauthorized }: { options: Options; onUnauthorized: () => void }) {
  const [layout, setLayout] = useState<"side" | "combined">("side");
  const [range, setRange] = useState(options.time_ranges[0]?.label ?? "");
  const [search, setSearch] = useState("");
  const [pageSize, setPageSize] = useState(options.page_sizes.includes(25) ? 25 : options.page_sizes[0]);
  const settledSearch = useDebounced(search.trim(), 300);

  // Back to the first page whenever a filter changes.
  const filters = JSON.stringify([layout, range, settledSearch, pageSize]);
  const [paging, setPaging] = useState<{ filters: string; pages: Record<string, number> }>({ filters, pages: {} });
  const pages = paging.filters === filters ? paging.pages : {};
  const pageSetter = (table: string) => (page: number) =>
    setPaging({ filters, pages: { ...pages, [table]: page } });
  const query = { range, search: settledSearch, page_size: pageSize };

  return (
    <>
      <div className="filters">
        <fieldset>
          <legend>Layout</legend>
          {(["side", "combined"] as const).map((value) => (
            <label key={value} className="choice">
              <input type="radio" checked={layout === value} onChange={() => setLayout(value)} />
              {value === "side" ? "Side by side" : "Combined"}
            </label>
          ))}
        </fieldset>
        <label>
          Time range
          <select value={range} onChange={(event) => setRange(event.target.value)}>
            {options.time_ranges.map((choice) => (
              <option key={choice.label}>{choice.label}</option>
            ))}
          </select>
        </label>
        <label className="grow">
          Search
          <input
            type="search"
            placeholder="Message, SID, address or time"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
        <label>
          Rows per page
          <select value={pageSize} onChange={(event) => setPageSize(Number(event.target.value))}>
            {options.page_sizes.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </label>
      </div>

      {layout === "side" ? (
        <div className="columns">
          {options.engines.map((engine) => (
            <AlertTable
              key={engine}
              engine={engine}
              title={NAMES[engine]}
              columns={PANEL_COLUMNS}
              query={query}
              page={pages[engine] ?? 1}
              onPage={pageSetter(engine)}
              onUnauthorized={onUnauthorized}
            />
          ))}
        </div>
      ) : (
        <AlertTable
          title={engineNames(options.engines)}
          columns={TABLE_COLUMNS}
          query={query}
          page={pages.all ?? 1}
          onPage={pageSetter("all")}
          onUnauthorized={onUnauthorized}
        />
      )}

      <CombinedExport options={options} onUnauthorized={onUnauthorized} />
    </>
  );
}

function AlertTable({
  engine,
  title,
  columns,
  query,
  page,
  onPage,
  onUnauthorized,
}: {
  engine?: Engine;
  title: string;
  columns: Column[];
  query: { range: string; search: string; page_size: number };
  page: number;
  onPage: (page: number) => void;
  onUnauthorized: () => void;
}) {
  const { data, error } = useApi<AlertPage>("/alerts", { ...query, engine, page }, onUnauthorized);
  const first = data ? (data.page - 1) * data.page_size + 1 : 0;

  return (
    <div className="panel">
      <h3>
        {title}
        {data && ` · ${count(data.total)}`}
      </h3>
      {error && <p className="error">{error}</p>}
      {data && !data.total && <p className="muted">No matching alerts.</p>}
      {data && data.total > 0 && (
        <>
          <div className="pager">
            <button type="button" disabled={data.page <= 1} onClick={() => onPage(data.page - 1)}>
              ‹
            </button>
            <label>
              Page
              <input
                type="number"
                min={1}
                max={data.pages}
                value={data.page}
                onChange={(event) => {
                  const wanted = Number(event.target.value);
                  if (wanted >= 1 && wanted <= data.pages) onPage(wanted);
                }}
              />
              of {count(data.pages)}
            </label>
            <button type="button" disabled={data.page >= data.pages} onClick={() => onPage(data.page + 1)}>
              ›
            </button>
            <span className="muted">
              {count(first)}–{count(first + data.rows.length - 1)} of {count(data.total)}
            </span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {columns.map((column) => (
                    <th key={column.title} className={column.className}>
                      {column.title}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.rows.map((row) => (
                  <tr key={row.id}>
                    {columns.map((column) => (
                      <td key={column.title} className={column.className}>
                        {column.value(row)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

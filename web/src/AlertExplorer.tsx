import { useCallback, useEffect, useState } from "react";
import { CombinedExport } from "./CombinedExport";
import { OldAlerts } from "./OldAlerts";
import {
  NAMES,
  count,
  engineNames,
  ruleName,
  useApi,
  useRemembered,
  type AlertPage,
  type AlertRow,
  type Engine,
  type Options,
  type RulePair,
  type RulePairs,
} from "./api";
import { stamp } from "./time";

type Column = {
  title: string;
  value: (row: AlertRow) => string;
  className?: string;
  /** Shown on hover over the heading. */
  hint?: string;
};

const TIME: Column = { title: "Time", value: (row) => stamp(row.time_ms), className: "time" };
// Only when both engines run.
const BOTH: Column = {
  title: "Both",
  value: (row) => (row.both ? "✓" : ""),
  className: "both",
  hint: "Both engines alerted on this packet",
};
const RULE: Column = { title: "Rule", value: ruleName, className: "rule", hint: "GID:SID:Rev" };
const SEVERITY: Column = { title: "Severity", value: (row) => String(row.severity), className: "number" };
// The message comes last and takes the width the others leave, on one line:
// a longer one ends in "…" and shows whole on hover.
const MESSAGE: Column = { title: "Message", value: (row) => row.message, className: "message" };
const PANEL_COLUMNS = [TIME, BOTH, RULE, SEVERITY, MESSAGE];
const TABLE_COLUMNS: Column[] = [
  TIME,
  { title: "Engine", value: (row) => NAMES[row.engine] ?? row.engine },
  BOTH,
  RULE,
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

/** A search to start with: a rule clicked elsewhere, and when, so the same rule clicked again starts it again. */
export interface SearchRequest {
  text: string;
  at: number;
}

export function AlertExplorer({
  options,
  onUnauthorized,
  searchRequest,
}: {
  options: Options;
  onUnauthorized: () => void;
  searchRequest?: SearchRequest | null;
}) {
  // The layout, time range and rows per page are kept in this browser.
  const [layout, setLayout] = useRemembered<"side" | "combined">("ids-explorer-layout", "side", ["side", "combined"]);
  const [range, setRange] = useRemembered(
    "ids-explorer-range",
    options.time_ranges[0]?.label ?? "",
    options.time_ranges.map((choice) => choice.label),
  );
  const [search, setSearch] = useState("");
  // A rule clicked on the Overview or in the rule pairs: search for it, from
  // the top of the screen, where its alerts are.
  const searchFor = useCallback((text: string) => {
    setSearch(text);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);
  useEffect(() => {
    if (searchRequest) searchFor(searchRequest.text);
  }, [searchRequest, searchFor]);
  const [pageSize, setPageSize] = useRemembered(
    "ids-explorer-page-size",
    options.page_sizes.includes(25) ? 25 : options.page_sizes[0],
    options.page_sizes,
  );
  const settledSearch = useDebounced(search.trim(), 300);
  const columns = (all: Column[]) => (options.engines.length > 1 ? all : all.filter((column) => column !== BOTH));

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
            placeholder="Message, rule, address or time"
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
              columns={columns(PANEL_COLUMNS)}
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
          columns={columns(TABLE_COLUMNS)}
          query={query}
          page={pages.all ?? 1}
          onPage={pageSetter("all")}
          onUnauthorized={onUnauthorized}
        />
      )}

      {options.engines.length > 1 && <RulePairSection onUnauthorized={onUnauthorized} onSearch={searchFor} />}

      <CombinedExport options={options} onUnauthorized={onUnauthorized} />
      <OldAlerts onUnauthorized={onUnauthorized} />
    </>
  );
}

// Page 1 holds the newest alerts and is fetched again this often. Other pages
// stay as they are, so that their rows don't move while they are read.
const NEWEST_REFRESH_MS = 10_000;

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
  const { data, error } = useApi<AlertPage>(
    "/alerts",
    { ...query, engine, page },
    onUnauthorized,
    page === 1 ? NEWEST_REFRESH_MS : 0,
  );
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
                    <th key={column.title} className={column.className} title={column.hint}>
                      {column.title}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.rows.map((row) => (
                  <tr key={row.id}>
                    {columns.map((column) => {
                      const text = column.value(row);
                      return (
                        <td key={column.title} className={column.className} title={column === MESSAGE ? text : undefined}>
                          {text}
                        </td>
                      );
                    })}
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

// As often as the Overview's last hour, which they explain.
const PAIRS_REFRESH_MS = 30_000;

/**
 * The rules behind the Overview's "Both engines": over the last hour, a Snort
 * rule and a Suricata rule that fired on one packet, with how many packets.
 */
function RulePairSection({ onUnauthorized, onSearch }: { onUnauthorized: () => void; onSearch: (text: string) => void }) {
  const { data, error } = useApi<RulePairs>("/rule-pairs", {}, onUnauthorized, PAIRS_REFRESH_MS);
  return (
    <section>
      <div className="section-head">
        <h2>Both engines: rule pairs</h2>
        <span className="muted">last hour</span>
      </div>
      {error && <p className="error">{error}</p>}
      {data && (data.pairs.length ? <PairTable pairs={data.pairs} onSearch={onSearch} /> : <p className="muted">None</p>)}
    </section>
  );
}

/** A rule's gid:sid:rev, as a link that searches the alerts for it. */
function RuleLink({ name, onSearch }: { name: string; onSearch: (text: string) => void }) {
  return (
    <button type="button" className="link" title="Search the alerts for it" onClick={() => onSearch(name)}>
      {name}
    </button>
  );
}

function PairTable({ pairs, onSearch }: { pairs: RulePair[]; onSearch: (text: string) => void }) {
  return (
    <div className="table-wrap">
      <table className="pairs">
        <thead>
          <tr>
            <th className="rule" title="GID:SID:Rev">
              Snort
            </th>
            <th>Message</th>
            <th className="rule" title="GID:SID:Rev">
              Suricata
            </th>
            <th>Message</th>
            <th className="number alerts">Packets</th>
          </tr>
        </thead>
        <tbody>
          {pairs.map((pair) => (
            <tr key={`${ruleName(pair.snort)} ${ruleName(pair.suricata)}`}>
              <td className="rule">
                <RuleLink name={ruleName(pair.snort)} onSearch={onSearch} />
              </td>
              <td className="message" title={pair.snort.message}>
                {pair.snort.message}
              </td>
              <td className="rule">
                <RuleLink name={ruleName(pair.suricata)} onSearch={onSearch} />
              </td>
              <td className="message" title={pair.suricata.message}>
                {pair.suricata.message}
              </td>
              <td className="number">{count(pair.packets)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

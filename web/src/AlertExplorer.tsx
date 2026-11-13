import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AlertDetail } from "./AlertDetail";
import { CombinedExport } from "./CombinedExport";
import { Fold } from "./Fold";
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
  type FilterValues,
  type Options,
  type Params,
  type RulePair,
  type RulePairs,
} from "./api";
import { OPEN, filterParams, narrowing } from "./filters";
import { clock, stamp } from "./time";

type Column = {
  title: string;
  value: (row: AlertRow) => string;
  /** What the cell shows, when that is not the value as text. */
  render?: (row: AlertRow) => ReactNode;
  className?: string;
  /** Shown on hover over the heading. */
  hint?: string;
  /** Shown on hover over a cell. */
  tip?: (row: AlertRow) => string;
};

// The time of day, with the date only when it is not today; whole on hover.
const TIME: Column = {
  title: "Time",
  value: (row) => clock(row.time_ms, Date.now()),
  className: "time",
  tip: (row) => `${stamp(row.time_ms)} PKT`,
};
// Only when both engines run.
const BOTH: Column = {
  title: "Both",
  value: (row) => (row.both ? "✓" : ""),
  className: "both",
  hint: "Both engines alerted on this packet",
};
// The alerts on one packet carry one ID, in both engines' lists, and sit
// together with one shade behind them.
/** A packet's ID: the UID (7 characters) of its first stored alert. */
export function packetKey(row: AlertRow): string {
  return row.packet ?? row.uid ?? String(row.id);
}

const PACKET: Column = {
  title: "Packet",
  value: packetKey,
  className: "packet",
  hint: "The packet's ID, the same on all its alerts: its first alert's UID, from the minute it came in and its number in it",
};
const RULE: Column = { title: "Rule", value: ruleName, className: "rule", hint: "GID:SID:Rev" };
const SEVERITY_WORDS = ["", "most severe", "high", "medium", "not critical"];

/** How many of the three circles are filled: 3 for severity 1, none for 4. */
export function filledCircles(severity: number): number {
  return Math.min(3, Math.max(0, 4 - severity));
}

export function SeverityCircles({ severity }: { severity: number }) {
  const words = `Severity ${severity}: ${SEVERITY_WORDS[severity] ?? ""}`;
  return (
    <span className={`levels level-${severity}`} role="img" aria-label={words} title={words}>
      {[1, 2, 3].map((circle) => (
        <i key={circle} className={circle <= filledCircles(severity) ? "filled" : undefined} />
      ))}
    </span>
  );
}
// Three circles, filled as the alert is more severe: the engines count the
// other way, 1 the most severe and 4 the least.
const SEVERITY: Column = {
  title: "Severity",
  value: (row) => String(row.severity),
  className: "severity",
  hint: "Filled circles: 3 is severity 1 (the most severe), none is severity 4",
  render: (row) => <SeverityCircles severity={row.severity} />,
};
// The message comes last and takes the width the others leave, on one line:
// a longer one ends in "…" and shows whole on hover.
const MESSAGE: Column = {
  title: "Message",
  value: (row) => row.message,
  className: "message",
  tip: (row) => row.message,
  // A lab attack's alerts say so before their message.
  render: (row) => (
    <>
      {row.label === "attack" && <span className="tag attack">Lab attack</span>}
      {row.message}
    </>
  ),
};
const PANEL_COLUMNS = [TIME, PACKET, BOTH, RULE, SEVERITY, MESSAGE];
const TABLE_COLUMNS: Column[] = [
  TIME,
  PACKET,
  { title: "Engine", value: (row) => NAMES[row.engine] ?? row.engine },
  BOTH,
  RULE,
  SEVERITY,
  { title: "Protocol", value: (row) => row.protocol ?? "" },
  { title: "Source", value: (row) => row.src ?? "" },
  { title: "Destination", value: (row) => row.dst ?? "" },
  MESSAGE,
];

/**
 * Which packets get the shade: every other one down the list. A packet keeps
 * its shade from one refresh to the next while it can, so the shades move
 * down with their rows when new alerts come in at the top.
 */
function usePacketShades(rows: AlertRow[]): Map<string, boolean> {
  const remembered = useRef(new Map<string, boolean>());
  remembered.current = packetShades(rows, remembered.current);
  return remembered.current;
}

/** Which packets' rows are shaded, from the bottom of the list up: every
 * other packet, each keeping the shade it had in ``previous`` (the last
 * refresh) unless that would match the packet below it. */
export function packetShades(rows: AlertRow[], previous: Map<string, boolean>): Map<string, boolean> {
  const shades = new Map<string, boolean>();
  let below: boolean | null = null;
  for (let index = rows.length - 1; index >= 0; index--) {
    const packet = packetKey(rows[index]);
    if (shades.has(packet)) continue;
    let shade = previous.get(packet);
    if (shade === undefined || shade === below) shade = below === null ? false : !below;
    shades.set(packet, shade);
    below = shade;
  }
  return shades;
}

/** The rows that were not in the list a moment ago (``before``: the ids
 * then; null when there is nothing to compare with), to light up briefly. */
export function arrived(before: Set<number> | null, rows: AlertRow[]): Set<number> {
  return new Set(before ? rows.filter((row) => !before.has(row.id)).map((row) => row.id) : []);
}

function useDebounced<T>(value: T, delayMs: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delayMs);
    return () => window.clearTimeout(timer);
  }, [value, delayMs]);
  return settled;
}

/** A rule clicked elsewhere, for the Rule filter, and when, so the same rule clicked again shows it again. */
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
  // The layout is kept in this browser.
  const [layout, setLayout] = useRemembered<"side" | "combined">("ids-explorer-layout", "side", ["side", "combined"]);
  // The filters last while the page is open; the less used ones stand in a
  // panel that "More filters" opens, kept open or shut in this browser.
  const [filters, setFilters] = useState(OPEN);
  const change = (next: Partial<typeof OPEN>) => setFilters((current) => ({ ...current, ...next }));
  const [more, setMore] = useRemembered("ids-explorer-more-filters", false, [true, false]);
  const inPanel = [
    filters.protocol,
    filters.alertClass,
    filters.service,
    filters.rule.trim(),
    filters.source.trim(),
    filters.destination.trim(),
    filters.port.trim(),
  ].filter(Boolean).length;
  // A rule clicked on the Overview or in the rule pairs: its alerts, from
  // the top of the screen, with the panel open on its Rule box.
  const showRule = useCallback(
    (rule: string) => {
      setFilters((current) => ({ ...current, rule }));
      setMore(true);
      window.scrollTo({ top: 0, behavior: "smooth" });
    },
    [setMore],
  );
  useEffect(() => {
    if (searchRequest) showRule(searchRequest.text);
  }, [searchRequest, showRule]);
  const { data: values } = useApi<FilterValues>("/alerts/values", {}, onUnauthorized, VALUES_REFRESH_MS);
  // The alert clicked, shown whole in the side panel.
  const [opened, setOpened] = useState<number | null>(null);
  const close = useCallback(() => setOpened(null), []);

  // Typing settles before the lists ask again.
  const settled = useDebounced(JSON.stringify(filterParams(filters)), 300);
  const params = useMemo(() => JSON.parse(settled) as Params, [settled]);
  const engines = typeof params.engine === "string" ? [params.engine as Engine] : options.engines;
  const columns = (all: Column[]) => (options.engines.length > 1 ? all : all.filter((column) => column !== BOTH));

  // Back to the first page whenever a filter changes.
  const paged = JSON.stringify([layout, settled]);
  const [paging, setPaging] = useState<{ filters: string; pages: Record<string, number> }>({ filters: paged, pages: {} });
  const pages = paging.filters === paged ? paging.pages : {};
  const pageSetter = (table: string) => (page: number) => setPaging({ filters: paged, pages: { ...pages, [table]: page } });
  const query = { ...params, page_size: PAGE_SIZE };
  // Side by side, "last N" is each engine's newest N: the file holds them all.
  const exported = layout === "side" && engines.length > 1 && params.last !== undefined ? { ...params, each: 1 } : params;

  return (
    <>
      <div className="toolbar">
        <select
          aria-label="Time"
          className={filters.range ? "set" : undefined}
          value={filters.range}
          onChange={(event) => change({ range: event.target.value })}
        >
          {options.time_ranges.map((choice) => (
            // Every stored alert: no range at all.
            <option key={choice.label} value={choice.ms === null ? "" : choice.label}>
              {choice.ms === null ? "Any time" : choice.label.replace(" minutes", " min")}
            </option>
          ))}
        </select>
        {options.engines.length > 1 && (
          <select
            aria-label="Engine"
            className={filters.engine ? "set" : undefined}
            value={filters.engine}
            onChange={(event) => change({ engine: event.target.value as Engine | "" })}
          >
            <option value="">Both engines</option>
            {options.engines.map((engine) => (
              <option key={engine} value={engine}>
                {NAMES[engine]}
              </option>
            ))}
          </select>
        )}
        <select
          aria-label="Lab attack or background"
          className={filters.label ? "set" : undefined}
          value={filters.label}
          onChange={(event) => change({ label: event.target.value as typeof filters.label })}
        >
          <option value="">All traffic</option>
          <option value="attack">Lab attacks</option>
          <option value="background">Background</option>
        </select>
        <div className="chips" role="group" aria-label="Severity">
          {[1, 2, 3, 4].map((level) => {
            const on = filters.severities.includes(level);
            return (
              <button
                key={level}
                type="button"
                className={on ? "chip on" : "chip"}
                aria-pressed={on}
                onClick={() =>
                  change({ severities: on ? filters.severities.filter((chosen) => chosen !== level) : [...filters.severities, level] })
                }
              >
                <SeverityCircles severity={level} />
              </button>
            );
          })}
        </div>
        <button type="button" className={more ? "current" : undefined} aria-expanded={more} onClick={() => setMore(!more)}>
          More filters{inPanel ? ` · ${inPanel}` : ""}
        </button>
        {narrowing(filters) > 0 && (
          <button type="button" className="link" onClick={() => setFilters({ ...OPEN, last: filters.last })}>
            Clear
          </button>
        )}
        <div className="toolbar-end view" role="group" aria-label="Lists">
          {(["side", "combined"] as const).map((value) => (
            <button
              key={value}
              type="button"
              className={layout === value ? "current" : undefined}
              aria-pressed={layout === value}
              onClick={() => setLayout(value)}
            >
              {value === "side" ? "Side by side" : "Combined"}
            </button>
          ))}
        </div>
      </div>

      {more && (
        <div className="filters compact">
          <Choice label="Protocol" value={filters.protocol} values={values?.protocols} onChange={(protocol) => change({ protocol })} />
          <Choice
            label="Class"
            wide
            value={filters.alertClass}
            values={values?.classes}
            onChange={(alertClass) => change({ alertClass })}
          />
          <Choice label="Service" value={filters.service} values={values?.services} onChange={(service) => change({ service })} />
          <label>
            Rule
            <input
              type="text"
              className={filters.rule.trim() ? "rule set" : "rule"}
              title="A SID, GID:SID or GID:SID:Rev, like 116:444"
              value={filters.rule}
              onChange={(event) => change({ rule: event.target.value })}
            />
          </label>
          <label>
            Source
            <input
              type="text"
              className={filters.source.trim() ? "address set" : "address"}
              title="An address or a network: 192.168.50.122, 192.168.50.0/24 or 192.168.50."
              value={filters.source}
              onChange={(event) => change({ source: event.target.value })}
            />
          </label>
          <label>
            Destination
            <input
              type="text"
              className={filters.destination.trim() ? "address set" : "address"}
              title="An address or a network: 192.168.50.122, 192.168.50.0/24 or 192.168.50."
              value={filters.destination}
              onChange={(event) => change({ destination: event.target.value })}
            />
          </label>
          <label>
            Port
            <input
              type="number"
              className={filters.port.trim() ? "port set" : "port"}
              title="A port on either side"
              min={0}
              max={65535}
              value={filters.port}
              onChange={(event) => change({ port: event.target.value })}
            />
          </label>
        </div>
      )}

      <div className="toolbar show" role="group" aria-label="How many alerts to show">
        <span className="muted">Show the newest</span>
        {/* None chosen shows every alert: a chosen number, clicked again, goes back to that. */}
        {options.last_choices.map((choice) => (
          <button
            key={choice}
            type="button"
            className={filters.last === choice ? "current" : undefined}
            title={filters.last === choice ? "Click again for every alert" : undefined}
            onClick={() => change({ last: filters.last === choice ? null : choice })}
          >
            {choice}
          </button>
        ))}
        <input
          type="number"
          className="count"
          min={1}
          max={options.max_last}
          placeholder="Any number"
          title="Empty, with no number chosen: every alert"
          aria-label="Newest alerts to show"
          value={filters.last ?? ""}
          onChange={(event) => change({ last: lastFrom(event.target.value, options.max_last) })}
        />
        <span className="muted">{layout === "side" && engines.length > 1 ? "alerts of each engine" : "alerts"}</span>
        <div className="toolbar-end">
          <CombinedExport options={options} params={exported} onUnauthorized={onUnauthorized} />
        </div>
      </div>

      {layout === "side" ? (
        <div className="columns">
          {engines.map((engine) => (
            <AlertTable
              key={engine}
              engine={engine}
              title={NAMES[engine]}
              columns={columns(PANEL_COLUMNS)}
              query={query}
              page={pages[engine] ?? 1}
              onPage={pageSetter(engine)}
              opened={opened}
              onOpen={setOpened}
              onUnauthorized={onUnauthorized}
            />
          ))}
        </div>
      ) : (
        <AlertTable
          title={engineNames(engines)}
          columns={columns(TABLE_COLUMNS)}
          query={query}
          page={pages.all ?? 1}
          onPage={pageSetter("all")}
          opened={opened}
          onOpen={setOpened}
          onUnauthorized={onUnauthorized}
        />
      )}

      {opened !== null && (
        <AlertDetail id={opened} onOpen={setOpened} onRule={showRule} onClose={close} onUnauthorized={onUnauthorized} />
      )}

      {options.engines.length > 1 && (
        <Fold id="rule-pairs" title="Both engines: rule pairs" note="last hour">
          <RulePairList onUnauthorized={onUnauthorized} onSearch={showRule} />
        </Fold>
      )}

      <Fold id="old-alerts" title="Old alerts">
        <OldAlerts onUnauthorized={onUnauthorized} />
      </Fold>
    </>
  );
}

// The choices change slowly, as alerts of a new protocol or class come in.
const VALUES_REFRESH_MS = 300_000;
// Rows on a page of a list: more than the newest 20 of "Show".
const PAGE_SIZE = 25;

/** The newest-alerts box's number: a whole number from 1, at most ``max``;
 * null (every alert) when it is empty or not a number. */
export function lastFrom(text: string, max: number): number | null {
  const wanted = Math.floor(Number(text));
  return text.trim() && Number.isFinite(wanted) && wanted >= 1 ? Math.min(wanted, max) : null;
}

/** A filter with one value of a list, or any; ``wide`` for long values
 * (the classes). Its box keeps one width, however long the chosen value or
 * the longest choice is, so that the boxes after it don't move. */
function Choice({
  label,
  wide = false,
  value,
  values,
  onChange,
}: {
  label: string;
  wide?: boolean;
  value: string;
  values?: string[];
  onChange: (value: string) => void;
}) {
  // A value chosen earlier stays offered until the list catches up.
  const offered = value && !(values ?? []).includes(value) ? [value, ...(values ?? [])] : (values ?? []);
  return (
    <label>
      {label}
      <select
        className={wide ? "choices wide" : "choices"}
        title={value || "Any"}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value="">Any</option>
        {offered.map((choice) => (
          <option key={choice}>{choice}</option>
        ))}
      </select>
    </label>
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
  opened,
  onOpen,
  onUnauthorized,
}: {
  engine?: Engine;
  title: string;
  columns: Column[];
  query: Params & { page_size: number };
  page: number;
  onPage: (page: number) => void;
  /** The alert shown in the side panel, and a row clicked for it. */
  opened: number | null;
  onOpen: (id: number) => void;
  onUnauthorized: () => void;
}) {
  const { data, error } = useApi<AlertPage>(
    "/alerts",
    { ...query, engine, page },
    onUnauthorized,
    page === 1 ? NEWEST_REFRESH_MS : 0,
  );
  const first = data ? (data.page - 1) * data.page_size + 1 : 0;
  const shades = usePacketShades(data?.rows ?? []);
  // The alerts that came in since the last answer light up briefly: on the
  // first page of the same list only.
  const listed = JSON.stringify([query, engine]);
  const seen = useRef<{ list: string; ids: Set<number> } | null>(null);
  const fresh = useMemo(
    () => arrived(page === 1 && seen.current?.list === listed ? seen.current.ids : null, data?.rows ?? []),
    // Only when an answer comes: the rows keep their light until the next.
    [data],
  );
  useEffect(() => {
    if (data) seen.current = page === 1 ? { list: listed, ids: new Set(data.rows.map((row) => row.id)) } : null;
  }, [data]);

  return (
    <div className="panel">
      <div className="panel-head">
        <h3>
          {title}
          {data && ` · ${count(data.total)}`}
          {data && query.last !== undefined && data.matching > data.total && (
            <span className="muted"> newest of {count(data.matching)}</span>
          )}
        </h3>
        {data && data.pages > 1 && (
          <div className="pager">
            <span className="muted">
              {count(first)}–{count(first + data.rows.length - 1)}
            </span>
            <button type="button" title="The newest" disabled={data.page <= 1} onClick={() => onPage(1)}>
              «
            </button>
            <button type="button" title="Newer" disabled={data.page <= 1} onClick={() => onPage(data.page - 1)}>
              ‹
            </button>
            <button type="button" title="Older" disabled={data.page >= data.pages} onClick={() => onPage(data.page + 1)}>
              ›
            </button>
          </div>
        )}
      </div>
      {error && <p className="error">{error}</p>}
      {data && !data.total && <p className="muted">No matching alerts.</p>}
      {data && data.total > 0 && (
        <>
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
                  <tr
                    key={row.id}
                    className={[
                      shades.get(packetKey(row)) ? "shaded" : "",
                      fresh.has(row.id) ? "fresh" : "",
                      row.id === opened ? "opened" : "",
                    ]
                      .join(" ")
                      .trim()}
                    tabIndex={0}
                    onClick={() => onOpen(row.id)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") onOpen(row.id);
                    }}
                  >
                    {columns.map((column) => {
                      const text = column.value(row);
                      return (
                        <td key={column.title} className={column.className} title={column.tip?.(row)}>
                          {column.render ? column.render(row) : text}
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
function RulePairList({ onUnauthorized, onSearch }: { onUnauthorized: () => void; onSearch: (text: string) => void }) {
  const { data, error } = useApi<RulePairs>("/rule-pairs", {}, onUnauthorized, PAIRS_REFRESH_MS);
  return (
    <>
      {error && <p className="error">{error}</p>}
      {data && (data.pairs.length ? <PairTable pairs={data.pairs} onSearch={onSearch} /> : <p className="muted">None</p>)}
    </>
  );
}

/** A rule's gid:sid:rev, as a link that shows its alerts (the Rule filter). */
function RuleLink({ name, onSearch }: { name: string; onSearch: (text: string) => void }) {
  return (
    <button type="button" className="link" title="Show its alerts" onClick={() => onSearch(name)}>
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

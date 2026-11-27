import { useState, type CSSProperties, type ReactNode } from "react";
import {
  NAMES,
  byEngine,
  count,
  errorText,
  machineTime,
  offState,
  ruleName,
  setRuleOff,
  useApi,
  useNow,
  useRemembered,
  type Engine,
  type RuleOff,
  type RulesOff,
  type LiveData,
  type OffPeriod,
  type Options,
  type OverviewData,
  type TopRule,
} from "./api";
import { LineChart } from "./LineChart";
import { dayTime, duration, minuteLabel } from "./time";

// The engines store alerts several times a minute on the lab network, so
// this long without one is worth a warning.
const QUIET_MS = 30 * 60 * 1000;
// The chart's height for a 960-wide drawing: the same whatever the counts,
// so the page below it doesn't move when a burst comes and goes.
const CHART_HEIGHT = 176;
// The live chart is fetched this often, and moves with the clock in between.
const LIVE_REFRESH_MS = 5_000;
const LIVE_TICK_MS = 2 * 60 * 1000;

/** One line per engine, in its colour. */
function engineLines(alerts: Partial<Record<Engine, number[]>>) {
  return byEngine(alerts).map(([engine, values]) => ({ name: NAMES[engine], values, color: `var(--${engine})` }));
}

/**
 * The live chart: the last minutes from /live, every 5 seconds, moving with
 * the IDS machine's clock in between. Each engine's line ends where its
 * alerts are stored, so one whose alerts are stored late ends earlier until
 * it catches up.
 */
function LiveSection({ choice, onUnauthorized }: { choice: ReactNode; onUnauthorized: () => void }) {
  const live = useApi<LiveData>("/live", {}, onUnauthorized, LIVE_REFRESH_MS);
  const now = useNow();
  const { data, error } = live;
  const end = machineTime(live, now);
  return (
    <section>
      {choice}
      {error && <p className="error">{error}</p>}
      {data && end !== null && (
        <LineChart
          startMs={data.start_ms}
          stepMs={data.step_ms}
          domain={[end - data.window_ms, end]}
          tickEveryMs={LIVE_TICK_MS}
          tickLabel={minuteLabel}
          off={data.off}
          height={CHART_HEIGHT}
          yLabel={`Alerts per ${data.step_ms / 1000} seconds`}
          series={engineLines(data.alerts)}
        />
      )}
      {data && <OffNote off={data.off} />}
    </section>
  );
}

export function Tile({
  label,
  value,
  details = [],
}: {
  label: string;
  value: string;
  details?: string[];
}) {
  return (
    <div className="tile">
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {details.filter(Boolean).map((detail) => (
        <div className="tile-detail" key={detail}>
          {detail}
        </div>
      ))}
    </div>
  );
}

/** 65.6 h, or 24 min under an hour. */
function offLength(ms: number): string {
  return ms >= 3_600_000 ? `${(ms / 3_600_000).toFixed(1)} h` : duration(ms);
}

/** Under a chart: each time the machine was off, whole, as the chart shades it. */
function OffNote({ off = [] }: { off?: OffPeriod[] }) {
  if (!off.length) return null;
  return (
    <p className="muted off-note">
      Machine off:{" "}
      {off.map(([from, to]) => `${dayTime(from)} – ${dayTime(to)} (${offLength(to - from)})`).join("; ")}
    </p>
  );
}

/** How much of the window the machine was off, in its own words. */
function offInside(off: OffPeriod[] = [], startMs: number, endMs: number): number {
  return off.reduce((total, [from, to]) => total + Math.max(0, Math.min(to, endMs) - Math.max(from, startMs)), 0);
}

// The rules ticked as false positives are fetched this often, to show
// when the engines have taken them.
const RULES_OFF_REFRESH_MS = 5_000;
// Waiting this long for the engines suggests root's ids-rules-off isn't
// installed.
const RULES_OFF_SLOW_MS = 5 * 60 * 1000;

type Ticking = {
  data: RulesOff | null;
  error: string;
  /** Ticks (or unticks) a rule, after asking. */
  toggle: (rule: { engine: Engine; gid: number; sid: number; message: string; rule: string }, off: boolean) => void;
};

/** The rules ticked as false positives: the list, refreshed, and a way to
 * tick and untick, whose answer shows at once. */
function useRulesOff(onUnauthorized: () => void): Ticking {
  const fetched = useApi<RulesOff>("/rules-off", {}, onUnauthorized, RULES_OFF_REFRESH_MS);
  const [saved, setSaved] = useState<{ data: RulesOff; at: number } | null>(null);
  const [error, setError] = useState("");
  const data = saved && (!fetched.receivedMs || saved.at >= fetched.receivedMs) ? saved.data : fetched.data;
  const toggle: Ticking["toggle"] = (rule, off) => {
    const question = off
      ? `Turn off ${NAMES[rule.engine]} rule ${rule.rule} as a false positive?\n\n${rule.message}\n\n` +
        `${NAMES[rule.engine]} stops raising it within a minute or two, until you tick it back on.`
      : `Turn ${NAMES[rule.engine]} rule ${rule.rule} back on?\n\n${rule.message}`;
    if (!window.confirm(question)) return;
    setError("");
    setRuleOff(rule, off)
      .then((answer) => setSaved({ data: answer, at: Date.now() }))
      .catch((reason: unknown) => setError(errorText(reason)));
  };
  return { data, error: error || fetched.error, toggle };
}

const OFF_WORDS = {
  off: "Off",
  applying: "Turning off…",
  error: "Not turned off",
  restoring: "Turning back on…",
};

function RuleTable({
  engine,
  rules,
  onSearch,
  ticking,
}: {
  engine: Engine;
  rules: TopRule[];
  onSearch: (text: string) => void;
  ticking: Ticking;
}) {
  // A bar behind each count, as long as its share of the busiest rule's.
  const most = Math.max(1, ...rules.map((rule) => rule.alerts));
  const canTick = !!ticking.data?.enabled;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {canTick && (
              <th className="tick" title="False positive: tick to turn the rule off in its engine, untick to turn it back on">
                FP
              </th>
            )}
            <th className="rule" title="GID:SID:Rev">
              Rule
            </th>
            <th className="number alerts">Alerts</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((rule) => {
            const { gid, sid } = rule;
            const known = gid !== null && sid !== null;
            const state = known && ticking.data ? offState({ engine, gid, sid }, ticking.data) : null;
            const ticked = state === "off" || state === "applying" || state === "error";
            return (
            <tr key={`${rule.rule}:${rule.rev}`} className={state === "off" ? "ruled-off" : undefined}>
              {canTick && (
                <td className="tick">
                  {known && (
                    <input
                      type="checkbox"
                      checked={ticked}
                      title={state ? OFF_WORDS[state] : "False positive: turn this rule off"}
                      aria-label={`False positive: turn ${ruleName(rule)} off`}
                      onChange={(event) =>
                        ticking.toggle({ engine, gid, sid, message: rule.message, rule: `${gid}:${sid}` }, event.target.checked)
                      }
                    />
                  )}
                </td>
              )}
              <td className="rule">
                <button type="button" className="link" title="Show its alerts in the Alert Explorer" onClick={() => onSearch(ruleName(rule))}>
                  {ruleName(rule)}
                </button>
              </td>
              <td
                className={`number bar ${engine}`}
                style={{ "--share": `${Math.round((100 * rule.alerts) / most)}%` } as CSSProperties}
              >
                {count(rule.alerts)}
              </td>
              <td className="message" title={rule.message}>
                {state && <span className={`off-state ${state}`}>{OFF_WORDS[state]}</span>}
                {rule.message}
              </td>
            </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Overview({
  options,
  onUnauthorized,
  onSearch,
}: {
  options: Options;
  onUnauthorized: () => void;
  /** Opens the Alert Explorer searching for a rule. */
  onSearch: (text: string) => void;
}) {
  const [step, setStep] = useRemembered("ids-chart-step", options.default_chart_step, options.chart_steps);
  const [live, setLive] = useRemembered<boolean>("ids-chart-live", false);
  const [topLength, setTopLength] = useRemembered(
    "ids-top-rules-length",
    options.default_top_rules_length,
    options.export_lengths,
  );
  const ticking = useRulesOff(onUnauthorized);
  const { data, error } = useApi<OverviewData>(
    "/overview",
    { step_minutes: step, top_rules_length: topLength },
    onUnauthorized,
    30_000,
  );
  if (!data) return <p className={error ? "error" : "muted"}>{error || "Loading…"}</p>;

  const now = Date.now();
  const warnings: ReactNode[] = [];
  for (const [engine, info] of byEngine(data.engines)) {
    const name = NAMES[engine];
    const check = (
      <>
        Check {name} and <code>live_dual_collector.py</code>.
      </>
    );
    if (info.newest_ms === null) {
      warnings.push(<p className="warning" key={`${engine}-none`}>No {name} alerts stored. {check}</p>);
    } else if (now - info.newest_ms > QUIET_MS) {
      warnings.push(
        <p className="warning" key={`${engine}-quiet`}>
          No {name} alert stored for {duration(now - info.newest_ms)}. {check}
        </p>,
      );
    }
    if (info.unmatched_lab_attackers.length) {
      warnings.push(
        <p className="warning" key={`${engine}-network`}>
          {name}: EXTERNAL_NET {info.external_net} leaves out the lab attacker{" "}
          {info.unmatched_lab_attackers.join(", ")} (inside HOME_NET {info.home_net}), so $EXTERNAL_NET
          rules cannot match its attacks.
        </p>,
      );
    }
  }
  const lastHour = data.last_hour;
  const day = data.last_day;
  const top = data.top_rules;
  // Snort, Suricata or both: the engines this machine runs.
  const engines = options.engines;
  const both = engines.length > 1;
  // The chart's heading is the choice of what it shows, so it always says
  // what is on the chart: alerts per 30 seconds over the last 15 minutes,
  // moving with the clock, or per 5, 10 or 15 minutes over the last 24
  // hours. The time axis shows the span, and "Live" is left to the status
  // panel.
  const chartChoice = (
    <h2>
      <select
        className="heading-choice"
        aria-label="Chart"
        value={live ? "live" : step}
        onChange={(event) => {
          const value = event.target.value;
          setLive(value === "live");
          if (value !== "live") setStep(Number(value));
        }}
      >
        <option value="live">{`Alerts per ${options.live_step_seconds} seconds`}</option>
        {options.chart_steps.map((minutes) => (
          <option key={minutes} value={minutes}>
            {`Alerts per ${minutes} minutes`}
          </option>
        ))}
      </select>
    </h2>
  );

  return (
    <>
      {error && <p className="error">{error}</p>}
      {warnings}

      {!lastHour && <p className="muted">No alerts stored yet.</p>}
      {lastHour && (
        <section>
          <div className="section-head">
            <h2>Last hour</h2>
            {offInside(lastHour.off, lastHour.start_ms, lastHour.end_ms) > 0 && (
              <span className="muted">
                Machine off for {offLength(offInside(lastHour.off, lastHour.start_ms, lastHour.end_ms))} of it
              </span>
            )}
          </div>
          <div className="tiles">
            <Tile
              label="Alerts"
              value={count(engines.reduce((total, engine) => total + (lastHour.alerts[engine] ?? 0), 0))}
              details={
                both ? [engines.map((engine) => `${NAMES[engine]} ${count(lastHour.alerts[engine] ?? 0)}`).join(" · ")] : []
              }
            />
            <Tile label="Packets with alerts" value={count(lastHour.packets)} />
            {/* Which engines alerted on each packet, when two run. */}
            {both && (
              <>
                <Tile
                  label="Both engines"
                  value={count(lastHour.both)}
                  details={[lastHour.packets ? `${Math.round((100 * lastHour.both) / lastHour.packets)}% of packets` : ""]}
                />
                <Tile
                  label="One engine only"
                  value={count(lastHour.snort_only + lastHour.suricata_only)}
                  details={[`Snort ${count(lastHour.snort_only)} · Suricata ${count(lastHour.suricata_only)}`]}
                />
              </>
            )}
          </div>
        </section>
      )}

      {live ? (
        <LiveSection choice={chartChoice} onUnauthorized={onUnauthorized} />
      ) : (
        day && (
          <section>
            {chartChoice}
            <LineChart
              startMs={day.start_ms}
              stepMs={day.step_ms}
              height={CHART_HEIGHT}
              yLabel={`Alerts per ${day.step_ms / 60_000} minutes`}
              series={engineLines(day.alerts)}
              off={day.off}
            />
            <OffNote off={day.off} />
          </section>
        )
      )}

      {top && (
        <section>
          <div className="section-head">
            <h2>Top rules</h2>
            <label>
              Last
              <select value={topLength} onChange={(event) => setTopLength(event.target.value)}>
                {options.export_lengths.map((length) => (
                  <option key={length}>{length}</option>
                ))}
              </select>
            </label>
          </div>
          <div className="columns">
            {byEngine(top.rules).map(([engine, rules]) => (
              <div key={engine}>
                <h3>{NAMES[engine]}</h3>
                {rules.length ? (
                  <RuleTable engine={engine} rules={rules} onSearch={onSearch} ticking={ticking} />
                ) : (
                  <p className="muted">None</p>
                )}
              </div>
            ))}
          </div>
          <RulesOffList ticking={ticking} onSearch={onSearch} />
        </section>
      )}
    </>
  );
}

/** The rules turned off from here, each with where it stands and a way to
 * turn it back on; and how the engines last took the list. */
function RulesOffList({ ticking, onSearch }: { ticking: Ticking; onSearch: (text: string) => void }) {
  const now = useNow();
  const data = ticking.data;
  if (ticking.error) return <p className="error">{ticking.error}</p>;
  if (!data?.enabled) return null;
  // The rules ticked, and those unticked that an engine still has off.
  const restoring = (data.applied?.rules ?? []).filter((rule) => offState(rule, data) === "restoring");
  const shown: RuleOff[] = [
    ...data.rules,
    ...restoring.map((rule) => ({ ...rule, rule: `${rule.gid}:${rule.sid}`, message: "", added_ms: 0 })),
  ];
  if (!shown.length) {
    return (
      <p className="muted">
        Tick a rule&apos;s FP box to turn it off as a false positive in its engine; untick it to turn it back on.
      </p>
    );
  }
  const waiting = data.rules.filter((rule) => offState(rule, data) === "applying");
  const slow = waiting.some((rule) => now - rule.added_ms > RULES_OFF_SLOW_MS);
  return (
    <>
      <h3>Turned off as false positives</h3>
      <div className="table-wrap">
        <table className="rules-off">
          <thead>
            <tr>
              <th>Engine</th>
              <th className="rule">Rule</th>
              <th>State</th>
              <th>Message</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {shown.map((rule) => {
              const state = offState(rule, data);
              const engineWords = data.applied?.engines?.[rule.engine] ?? "";
              return (
                <tr key={`${rule.engine}:${rule.gid}:${rule.sid}`}>
                  <td>{NAMES[rule.engine]}</td>
                  <td className="rule">
                    <button type="button" className="link" title="Show its alerts in the Alert Explorer" onClick={() => onSearch(rule.rule)}>
                      {rule.rule}
                    </button>
                  </td>
                  <td>
                    {state && <span className={`off-state ${state}`}>{OFF_WORDS[state]}</span>}
                    {state === "error" && (
                      <div className="differs">{data.applied?.error ?? engineWords.replace(/^error: /, "")}</div>
                    )}
                  </td>
                  <td className="message" title={rule.message}>
                    {rule.message}
                  </td>
                  <td>
                    {state !== "restoring" && (
                      <button
                        type="button"
                        onClick={() =>
                          ticking.toggle({ engine: rule.engine, gid: rule.gid, sid: rule.sid, message: rule.message, rule: rule.rule }, false)
                        }
                      >
                        Turn back on
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {slow && (
        <p className="warning">
          The engines haven&apos;t taken the list for over 5 minutes: is root&apos;s watcher installed (
          <code>sudo deploy/install-rules-off.sh</code>)?
        </p>
      )}
      {data.applied && (
        <p className="muted">
          Last applied {dayTime(data.applied.applied_ms)}
          {byEngine(data.applied.engines).map(([engine, words]) => ` · ${NAMES[engine]}: ${words.startsWith("error") ? "not taken" : words}`)}
        </p>
      )}
    </>
  );
}

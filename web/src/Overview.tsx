import type { ReactNode } from "react";
import {
  NAMES,
  byEngine,
  count,
  machineTime,
  ruleName,
  runningNow,
  useApi,
  useNow,
  useRemembered,
  type Engine,
  type EngineStatus,
  type Fetched,
  type LiveData,
  type Options,
  type OverviewData,
  type Status,
  type TopRule,
} from "./api";
import { LineChart } from "./LineChart";
import { duration, minuteLabel } from "./time";

// The engines store alerts several times a minute on the lab network, so
// this long without one is worth a warning.
const QUIET_MS = 30 * 60 * 1000;
// The chart's height for a 960-wide drawing.
const CHART_HEIGHT = { small: 150, tall: 320 };
// The live chart is fetched this often, and moves with the clock in between.
const LIVE_REFRESH_MS = 5_000;
const LIVE_TICK_MS = 2 * 60 * 1000;

/**
 * Small while each engine's alerts keep near their usual level, and taller
 * as a burst rises above it, so that the usual level does not flatten into
 * the bottom of the chart: from twice the usual (median) count to six times.
 */
function chartHeight(lines: number[][]): number {
  const rise = Math.max(
    1,
    ...lines.map((values) => {
      const counted = values.filter((value) => value > 0).sort((a, b) => a - b);
      return counted.length ? counted[counted.length - 1] / counted[Math.floor(counted.length / 2)] : 1;
    }),
  );
  const grow = Math.min(1, Math.max(0, (rise - 2) / 4));
  return Math.round(CHART_HEIGHT.small + grow * (CHART_HEIGHT.tall - CHART_HEIGHT.small));
}

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
          height={chartHeight(byEngine(data.alerts).map(([, values]) => values))}
          yLabel={`Alerts per ${data.step_ms / 1000} seconds`}
          series={engineLines(data.alerts)}
        />
      )}
    </section>
  );
}

export function Tile({
  label,
  value,
  details = [],
  running,
}: {
  label: string;
  value: string;
  details?: string[];
  /** A dot: green while the program runs, red when it is stopped, grey when that is not known. */
  running?: boolean | null;
}) {
  return (
    <div className="tile">
      <div className="tile-label">
        {running !== undefined && (
          <span
            className={running === null ? "dot unknown" : running ? "dot on" : "dot off"}
            title={running === null ? "Not known" : running ? "Running" : "Not running"}
          />
        )}
        {label}
      </div>
      <div className="tile-value">{value}</div>
      {details.filter(Boolean).map((detail) => (
        <div className="tile-detail" key={detail}>
          {detail}
        </div>
      ))}
    </div>
  );
}

function RuleTable({ rules }: { rules: TopRule[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th className="rule" title="GID:SID:Rev">
              Rule
            </th>
            <th className="number alerts">Alerts</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((rule) => (
            <tr key={`${rule.rule}:${rule.rev}`}>
              <td className="rule">{ruleName(rule)}</td>
              <td className="number">{count(rule.alerts)}</td>
              <td className="message" title={rule.message}>
                {rule.message}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Each engine: whether it runs and how long ago its newest alert was, from
 * the status (it comes more often than the screen's data), with the times
 * counting on between answers and when none comes.
 */
function EngineCards({
  engines,
  status,
}: {
  engines: Partial<Record<Engine, EngineStatus>>;
  status: Fetched<Status>;
}) {
  const now = useNow();
  const machineNow = machineTime(status, now) ?? now;
  const running = runningNow(status);
  const fresh = status.data?.engines ?? engines;
  return (
    <div className="tiles">
      {byEngine(fresh).map(([engine, info]) => (
        <Tile
          key={engine}
          label={NAMES[engine]}
          running={running ? (running[engine] ?? null) : null}
          value={info.newest_ms !== null ? `${duration(machineNow - info.newest_ms)} ago` : "No alerts"}
          details={[info.rules !== null ? `${count(info.rules)} rules` : ""]}
        />
      ))}
    </div>
  );
}

export function Overview({
  options,
  status,
  onUnauthorized,
}: {
  options: Options;
  /** What the status panel shows, every 10 seconds. */
  status: Fetched<Status>;
  onUnauthorized: () => void;
}) {
  const [step, setStep] = useRemembered("ids-chart-step", options.default_chart_step, options.chart_steps);
  const [live, setLive] = useRemembered<boolean>("ids-chart-live", false);
  const [topLength, setTopLength] = useRemembered(
    "ids-top-rules-length",
    options.default_top_rules_length,
    options.export_lengths,
  );
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
  // what is on the chart: the last 24 hours with a point every 5, 10 or 15
  // minutes, or live.
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
        {options.chart_steps.map((minutes) => (
          <option key={minutes} value={minutes}>
            {`Last 24 hours, alerts per ${minutes} minutes`}
          </option>
        ))}
        <option value="live">Live</option>
      </select>
    </h2>
  );

  return (
    <>
      {error && <p className="error">{error}</p>}
      <section>
        <h2>Status</h2>
        <EngineCards engines={data.engines} status={status} />
        {warnings}
      </section>

      {!lastHour && <p className="muted">No alerts stored yet.</p>}
      {lastHour && (
        <section>
          <h2>Last hour</h2>
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
              height={chartHeight(byEngine(day.alerts).map(([, values]) => values))}
              yLabel={`Alerts per ${day.step_ms / 60_000} minutes`}
              series={engineLines(day.alerts)}
            />
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
                {rules.length ? <RuleTable rules={rules} /> : <p className="muted">None</p>}
              </div>
            ))}
          </div>
        </section>
      )}
    </>
  );
}

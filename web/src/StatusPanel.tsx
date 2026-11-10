// Whether the IDS is working now, down the right side of every screen, with
// what is stored, each engine's dropped packets and its HOME_NET. The
// engines and the collector, with their dots, head the Overview. The "… ago"
// times count on between answers, and when none comes.
import { ENGINES, NAMES, byEngine, count, machineTime, useNow, type Fetched, type Status } from "./api";
import { clock, duration } from "./time";

// The collector stores alerts several times a minute on the lab network.
const QUIET_MS = 5 * 60 * 1000;

type Level = "ok" | "warn" | "down" | "unknown";

function summary(
  { data, error, receivedMs }: Fetched<Status>,
  machineNow: number,
  now: number,
): { level: Level; label: string; detail: string } {
  if (error) {
    const updated = receivedMs !== null ? `\nUpdated ${duration(now - receivedMs)} ago` : "";
    return { level: "down", label: "Not updating", detail: `${error}${updated}` };
  }
  if (!data) return { level: "unknown", label: "Checking…", detail: "" };
  const running = data.running;
  if (!running) return { level: "unknown", label: "Status unknown", detail: "The API cannot see which programs run" };
  if (!running.collector) {
    return { level: "down", label: "Not updating", detail: "The collector is not running: no new alerts are stored" };
  }
  // The API names only the engines this machine runs.
  const stopped = ENGINES.filter((engine) => running[engine] === false);
  if (stopped.length) {
    return {
      level: "warn",
      label: "Partly working",
      detail: `${stopped.map((engine) => NAMES[engine]).join(" and ")} not running`,
    };
  }
  const saved = data.collector_saved_ms;
  if (saved === null || machineNow - saved > QUIET_MS) {
    return {
      level: "warn",
      label: "No new alerts",
      detail: saved === null ? "Nothing stored yet" : `Nothing stored for ${duration(machineNow - saved)}`,
    };
  }
  return { level: "ok", label: "Live", detail: "" };
}

export function StatusPanel({ status }: { status: Fetched<Status> }) {
  const now = useNow();
  const machineNow = machineTime(status, now) ?? now;
  const { level, label, detail } = summary(status, machineNow, now);
  const { data } = status;
  const engines = data ? byEngine(data.engines) : [];
  const oldest = engines.map(([, info]) => info.oldest_ms).filter((ms): ms is number => ms !== null);

  return (
    <aside className={`status-panel ${level}`} aria-label="IDS status">
      <div className="status-head" role="status">
        <span className="status-dot" aria-hidden="true" />
        <strong>{label}</strong>
      </div>
      {detail && <p className="status-detail">{detail}</p>}
      {data && (
        <>
          <div className="status-item">
            <div className="status-name plain">Stored alerts</div>
            <div>{count(engines.reduce((total, [, info]) => total + info.alerts, 0))}</div>
            {engines.length > 1 && (
              <div className="muted">
                {engines.map(([engine, info]) => `${NAMES[engine]} ${count(info.alerts)}`).join(" · ")}
              </div>
            )}
            {oldest.length > 0 && <div className="muted">since {clock(Math.min(...oldest), machineNow)}</div>}
            {data.alert_retention && <div className="muted">newest {count(data.alert_retention)} kept</div>}
          </div>
          {data.capture && byEngine(data.capture).length > 0 && (
            <div className="status-item">
              <div className="status-name plain">Dropped packets, last hour</div>
              {byEngine(data.capture).map(([engine, info]) => (
                <div key={engine} className={info && info.dropped > 0 ? "error" : undefined}>
                  {NAMES[engine]} {info ? `${count(info.dropped)} of ${count(info.packets)}` : "not known"}
                </div>
              ))}
            </div>
          )}
          <div className="status-item">
            <div className="status-name plain">HOME_NET</div>
            {engines.map(([engine, info]) => (
              <div key={engine}>
                {NAMES[engine]} {info.home_net ?? "not found"}
              </div>
            ))}
          </div>
        </>
      )}
    </aside>
  );
}

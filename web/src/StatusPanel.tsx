// Whether the IDS is working now. At the top of the Overview, one strip
// (StatusStrip): live or what is wrong, then each engine and the collector
// with their dots and how long ago each last alerted or stored. Down its
// right side, a panel (StatusPanel): what is stored, each engine's dropped
// packets, the disk and HOME_NET. The "… ago" times count on between
// answers, and when none comes. The Alert Explorer has neither: there a
// line says so only when something is wrong (StatusNote).
import type { ReactNode } from "react";
import {
  ENGINES,
  NAMES,
  byEngine,
  count,
  machineTime,
  runningNow,
  useNow,
  type Fetched,
  type Status,
  type Storage,
} from "./api";
import { clock, duration } from "./time";

// The collector stores alerts several times a minute on the lab network.
const QUIET_MS = 5 * 60 * 1000;
// An engine whose newest alert is older than this is shown as quiet (as the
// Overview's warning says).
const ENGINE_QUIET_MS = 30 * 60 * 1000;

type Level = "ok" | "warn" | "down" | "unknown";

export function summary(
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
  if (data.storage?.backups?.problem) {
    return { level: "down", label: "Database damaged", detail: data.storage.backups.problem };
  }
  if (data.storage && diskLow(data.storage)) {
    return { level: "warn", label: "Disk almost full", detail: `${bytes(data.storage.disk_free)} free` };
  }
  return { level: "ok", label: "Live", detail: "" };
}

/** 19.8 GB, 366 MB */
function bytes(value: number): string {
  return value >= 1e9 ? `${(value / 1e9).toFixed(1)} GB` : `${Math.round(value / 1e6)} MB`;
}

/** Under 2 GB or 5% of the disk: the database and the archive still grow. */
export function diskLow(storage: Storage): boolean {
  return storage.disk_free < Math.max(2e9, storage.disk_total * 0.05);
}

/** The nightly backup is over a day and a half old. */
export function backupLate(storage: Storage, now: number): boolean {
  const newest = storage.backups?.newest_ms;
  return newest !== null && newest !== undefined && now - newest > 36 * 60 * 60 * 1000;
}

/** A program's dot: green while it runs, red when it is stopped, grey when that is not known. */
function Dot({ running }: { running: boolean | null }) {
  return (
    <span
      className={running === null ? "dot unknown" : running ? "dot on" : "dot off"}
      title={running === null ? "Not known" : running ? "Running" : "Not running"}
    />
  );
}

/** Over the Alert Explorer: what is wrong, and nothing while the IDS is live. */
export function StatusNote({ status }: { status: Fetched<Status> }) {
  const now = useNow();
  const { level, label, detail } = summary(status, machineTime(status, now) ?? now, now);
  if (level === "ok" || level === "unknown") return null;
  return (
    <p className="warning" role="status">
      <strong>{label}</strong>
      {detail && `: ${detail}`}
    </p>
  );
}

/** One cell of the strip: a name with its dot, a value, a line under it. */
function Cell({
  name,
  dot,
  value,
  detail,
  quiet = false,
}: {
  name: string;
  dot: ReactNode;
  value: string;
  detail: string;
  quiet?: boolean;
}) {
  return (
    <div className="strip-cell">
      <div className="strip-name">
        {dot}
        {name}
      </div>
      <div className={quiet ? "strip-value quiet" : "strip-value"}>{value}</div>
      <div className="strip-detail">{detail}</div>
    </div>
  );
}

/** At the top of the Overview: live, or what is wrong; then each engine with
 * how long ago its newest alert was and its rules, and the collector with
 * how long ago it last stored alerts. */
export function StatusStrip({ status }: { status: Fetched<Status> }) {
  const now = useNow();
  const machineNow = machineTime(status, now) ?? now;
  const { level, label, detail } = summary(status, machineNow, now);
  const { data } = status;
  const running = runningNow(status);
  const engines = data ? byEngine(data.engines) : [];
  const saved = data?.collector_saved_ms ?? null;

  return (
    <section className={`status-strip ${level}`} aria-label="IDS status">
      <div className="strip-cell overall" role="status">
        <div className="strip-name">Status</div>
        <div className="strip-value">
          <span className="status-dot" aria-hidden="true" />
          {label}
        </div>
        <div className="strip-detail">{detail || (level === "ok" ? "storing alerts now" : "")}</div>
      </div>
      {engines.map(([engine, info]) => (
        <Cell
          key={engine}
          name={NAMES[engine]}
          dot={<Dot running={running ? (running[engine] ?? null) : null} />}
          value={info.newest_ms !== null ? `${duration(machineNow - info.newest_ms)} ago` : "No alerts"}
          quiet={info.newest_ms === null || machineNow - info.newest_ms > ENGINE_QUIET_MS}
          detail={`last alert${info.rules !== null ? ` · ${count(info.rules)} rules` : ""}`}
        />
      ))}
      <Cell
        name="Collector"
        dot={<Dot running={running ? running.collector : null} />}
        value={saved !== null ? `${duration(machineNow - saved)} ago` : data ? "Nothing stored" : "Checking…"}
        quiet={saved !== null && machineNow - saved > QUIET_MS}
        detail="last stored alerts"
      />
    </section>
  );
}

/** Down the Overview's right side: what is stored, the drops, the disk and HOME_NET. */
export function StatusPanel({ status }: { status: Fetched<Status> }) {
  const now = useNow();
  const machineNow = machineTime(status, now) ?? now;
  const { data } = status;
  const storage = data?.storage;
  const engines = data ? byEngine(data.engines) : [];
  const oldest = engines.map(([, info]) => info.oldest_ms).filter((ms): ms is number => ms !== null);

  return (
    <aside className="status-panel" aria-label="What is stored">
      {!data && <p className="muted">{status.error || "Checking…"}</p>}
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
          {storage && (
            <div className="status-item">
              <div className="status-name plain">Disk</div>
              <div className={diskLow(storage) ? "error" : undefined}>
                {bytes(storage.disk_free)} free of {bytes(storage.disk_total)}
              </div>
              <div className="muted">
                alerts {bytes(storage.database)}
                {storage.archive > 0 && ` · old alerts ${bytes(storage.archive)}`}
              </div>
              {storage.backups && (
                <div className={backupLate(storage, machineNow) ? "error" : "muted"}>
                  {storage.backups.newest_ms === null
                    ? "no backup yet"
                    : `backup ${duration(machineNow - storage.backups.newest_ms)} ago`}
                  {storage.backups.checked_ms !== null && storage.backups.problem === null && ", database OK"}
                </div>
              )}
              {storage.backups?.problem && (
                <div className="error" title={storage.backups.problem}>
                  Database damaged: run scripts/restore_backup.py
                </div>
              )}
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

// The API in src/dashboard_api.py; the shapes are what ids.dashboard_data
// returns (see docs/react-native-port.md).
import { useEffect, useRef, useState } from "react";

export type Engine = "snort" | "suricata";
export const ENGINES: Engine[] = ["snort", "suricata"];
export const NAMES: Record<Engine, string> = { snort: "Snort", suricata: "Suricata" };

/**
 * The engines a record from the API has, in the screens' order, with their
 * values. The API gives the engines this machine runs (IDS_ENGINES): Snort,
 * Suricata or both.
 */
export function byEngine<T>(record: Partial<Record<Engine, T>>): [Engine, T][] {
  return ENGINES.flatMap((engine) => {
    const value = record[engine];
    return value === undefined ? [] : [[engine, value] as [Engine, T]];
  });
}

/** "Snort + Suricata", or the one engine's name. */
export function engineNames(engines: Engine[]): string {
  return engines.map((engine) => NAMES[engine]).join(" + ");
}

export interface Options {
  engines: Engine[];
  export_lengths: string[];
  default_export_length: string;
  time_ranges: { label: string; ms: number | null }[];
  page_sizes: number[];
  /** Minutes between the chart's points. */
  chart_steps: number[];
  default_chart_step: number;
  /** One of export_lengths. */
  default_top_rules_length: string;
  time_zone: string;
}

export interface EngineStatus {
  newest_ms: number | null;
  alerts: number;
  oldest_ms: number | null;
  rules: number | null;
  home_net: string | null;
  external_net: string | null;
  unmatched_lab_attackers: string[];
}

export interface LastHour {
  start_ms: number;
  end_ms: number;
  alerts: Partial<Record<Engine, number>>;
  packets: number;
  both: number;
  snort_only: number;
  suricata_only: number;
}

export interface TopRule {
  rule: string;
  gid: number | null;
  sid: number | null;
  rev: number | null;
  message: string;
  alerts: number;
}

export interface LastDay {
  start_ms: number;
  end_ms: number;
  step_ms: number;
  alerts: Partial<Record<Engine, number[]>>;
}

export interface TopRules {
  length: string;
  start_ms: number;
  end_ms: number;
  rules: Partial<Record<Engine, TopRule[]>>;
}

export interface OverviewData {
  complete_end_ms: number | null;
  alert_retention: number | null;
  engines: Partial<Record<Engine, EngineStatus>>;
  last_hour: LastHour | null;
  last_day: LastDay | null;
  top_rules: TopRules | null;
}

/** What /live gives: the last minutes' alerts, for the Overview's live chart. */
export interface LiveData {
  checked_ms: number;
  window_ms: number;
  start_ms: number;
  step_ms: number;
  /** Alerts per step from start_ms; each engine's run up to where its alerts are stored. */
  alerts: Partial<Record<Engine, number[]>>;
}

/** What /status says: whether the IDS stores alerts now. */
export interface Status {
  checked_ms: number;
  /** null when the API cannot see the machine's programs. */
  running: (Partial<Record<Engine, boolean>> & { collector: boolean }) | null;
  /** When the collector last stored alerts. */
  collector_saved_ms: number | null;
  complete_end_ms: number | null;
  alert_retention: number | null;
  engines: Partial<Record<Engine, EngineStatus>>;
}

export interface AlertRow {
  id: number;
  engine: Engine;
  time_ms: number;
  rule: string;
  gid: number | null;
  sid: number | null;
  rev: number | null;
  message: string;
  class: string | null;
  severity: number;
  protocol: string | null;
  service: string | null;
  src: string | null;
  dst: string | null;
}

export interface AlertPage {
  total: number;
  page: number;
  pages: number;
  page_size: number;
  rows: AlertRow[];
}

export interface ExportWindow {
  start_ms: number;
  end_ms: number;
  complete_end_ms: number;
  moved_back: boolean;
}

export interface BuiltExport {
  filename: string;
  blob: Blob;
  startMs: number;
  endMs: number;
  alerts: Record<Engine, number>;
  packets: number;
  bothEnginePackets: number;
}

export type Params = Record<string, string | number | undefined>;

/** The API refused the token: the page asks for it again. */
export class Unauthorized extends Error {}

const TOKEN_KEY = "ids-api-token";

export function getToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

let sessionToken = getToken();

export function setToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {
    // Storage can be blocked (private windows); the token then lasts until
    // the page is closed.
  }
  sessionToken = token;
}

export function errorText(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason);
}

async function request(path: string, params: Params, signal?: AbortSignal): Promise<Response> {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(name, String(value));
  }
  const text = query.toString();
  let response: Response;
  try {
    response = await fetch(text ? `${path}?${text}` : path, {
      headers: { Authorization: `Bearer ${sessionToken}` },
      signal,
    });
  } catch (reason) {
    // No answer at all: the browser's own words ("Failed to fetch") say little.
    if (reason instanceof TypeError) throw new Error(`Cannot reach the IDS machine: ${reason.message}`);
    throw reason;
  }
  if (response.status === 401) throw new Unauthorized("Wrong API token");
  if (!response.ok) {
    let message = `The API answered ${response.status}`;
    try {
      message = (await response.json()).error ?? message;
    } catch {
      // Not JSON: keep the status.
    }
    throw new Error(message);
  }
  return response;
}

// The screens' requests normally take well under a second.
const ANSWER_LIMIT_MS = 15_000;

/**
 * The JSON at path. A request without its whole answer in ANSWER_LIMIT_MS
 * is cancelled and fails: the IDS machine or its API is stuck or very slow.
 */
export async function getJson<T>(path: string, params: Params = {}, signal?: AbortSignal): Promise<T> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  if (signal?.aborted) cancel();
  signal?.addEventListener("abort", cancel);
  let late = false;
  const timer = window.setTimeout(() => {
    late = true;
    controller.abort();
  }, ANSWER_LIMIT_MS);
  try {
    return (await (await request(path, params, controller.signal)).json()) as T;
  } catch (reason) {
    throw late ? new Error("No answer from the IDS machine") : reason;
  } finally {
    window.clearTimeout(timer);
    signal?.removeEventListener("abort", cancel);
  }
}

/** Builds the combined JSON for the window /export/window gives. */
export async function buildExport(length: string, endMs?: number): Promise<BuiltExport> {
  const response = await request("/export", { length, end_ms: endMs });
  const header = (name: string) => Number(response.headers.get(name) ?? 0);
  const disposition = response.headers.get("Content-Disposition") ?? "";
  return {
    filename: /filename="([^"]+)"/.exec(disposition)?.[1] ?? "snort_suricata_combined.json",
    blob: await response.blob(),
    startMs: header("X-Window-Start-Ms"),
    endMs: header("X-Window-End-Ms"),
    alerts: { snort: header("X-Alerts-Snort"), suricata: header("X-Alerts-Suricata") },
    packets: header("X-Packets"),
    bothEnginePackets: header("X-Both-Engine-Packets"),
  };
}

/** What useApi gives. */
export interface Fetched<T> {
  data: T | null;
  /** Why the latest request failed; "" when it did not. */
  error: string;
  /** When data came, by this browser's clock. */
  receivedMs: number | null;
}

/**
 * One endpoint's data, fetched again whenever the parameters change and,
 * with refreshMs, every refreshMs and when the page is shown again. The last
 * data stays on screen until the next answer arrives. No request is sent
 * while one waits for its answer, so one that gets none fails (getJson's
 * time limit) instead of being replaced unnoticed.
 */
export function useApi<T>(
  path: string,
  params: Params,
  onUnauthorized: () => void,
  refreshMs = 0,
): Fetched<T> {
  const [state, setState] = useState<Fetched<T>>({ data: null, error: "", receivedMs: null });
  const key = `${path}?${JSON.stringify(params)}`;
  const latest = useRef({ params, onUnauthorized });
  latest.current = { params, onUnauthorized };

  useEffect(() => {
    const controller = new AbortController();
    let waiting = false;
    const load = () => {
      if (waiting) return;
      waiting = true;
      getJson<T>(path, latest.current.params, controller.signal)
        .then((data) => setState({ data, error: "", receivedMs: Date.now() }))
        .catch((reason: unknown) => {
          if (reason instanceof Unauthorized) latest.current.onUnauthorized();
          else if (!controller.signal.aborted) setState((previous) => ({ ...previous, error: errorText(reason) }));
        })
        .finally(() => {
          waiting = false;
        });
    };
    // Browsers slow down a hidden page's timers: catch up once it is shown.
    const onShow = () => {
      if (document.visibilityState === "visible") load();
    };
    load();
    const timer = refreshMs ? window.setInterval(load, refreshMs) : undefined;
    if (refreshMs) document.addEventListener("visibilitychange", onShow);
    return () => {
      controller.abort();
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onShow);
    };
  }, [key, path, refreshMs]);

  return state;
}

/** This browser's clock, read again every second, so that "… ago" times count on. */
export function useNow(): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return now;
}

/**
 * The IDS machine's clock at browser time now: when its latest answer (a
 * status, the live chart) was made plus the time since it came, by this
 * browser's clock (so the two clocks need not agree). It keeps counting
 * when no answer comes. Null before the first answer.
 */
export function machineTime({ data, receivedMs }: Fetched<{ checked_ms: number }>, now: number): number | null {
  return data && receivedMs !== null ? data.checked_ms + (now - receivedMs) : null;
}

/** Which programs run, while the latest status request got its answer; null when that is not known. */
export function runningNow({ data, error }: Fetched<Status>): Status["running"] {
  return data && !error ? data.running : null;
}

export const count = (value: number) => value.toLocaleString("en-US");

/** A rule as gid:sid:rev, the way Snort names rules (the alert search finds it so); gid:sid without a revision. */
export function ruleName({ gid, sid, rev }: { gid: number | null; sid: number | null; rev: number | null }): string {
  return `${gid ?? ""}:${sid ?? ""}${rev === null ? "" : `:${rev}`}`;
}

/**
 * A choice this browser remembers (the chart's size, its step), kept only
 * while it is one of the allowed values.
 */
export function useRemembered<T extends string | number | boolean>(
  key: string,
  initial: T,
  allowed?: readonly T[],
): [T, (value: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(key);
      if (stored !== null) {
        const parsed = JSON.parse(stored) as T;
        if (typeof parsed === typeof initial && (!allowed || allowed.includes(parsed))) return parsed;
      }
    } catch {
      // Storage can be blocked, or hold something else.
    }
    return initial;
  });
  const remember = (next: T) => {
    setValue(next);
    try {
      localStorage.setItem(key, JSON.stringify(next));
    } catch {
      // Then the choice lasts until the page is closed.
    }
  };
  return [value, remember];
}

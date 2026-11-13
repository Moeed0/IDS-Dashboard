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
  /** The quick choices for the last N alerts, and the most N may be. */
  last_choices: number[];
  max_last: number;
  /** Where Send sends the chosen alerts (host:port); null while it is off. */
  send_to: string | null;
  /** Minutes between the chart's points. */
  chart_steps: number[];
  default_chart_step: number;
  /** Seconds between the live chart's points. */
  live_step_seconds: number;
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

/** When the IDS machine was off, [from_ms, to_ms]. */
export type OffPeriod = [number, number];

export interface LastHour {
  start_ms: number;
  end_ms: number;
  /** When the machine was off in the hour. */
  off?: OffPeriod[];
  alerts: Partial<Record<Engine, number>>;
  packets: number;
  both: number;
  snort_only: number;
  suricata_only: number;
}

/** What /rule-pairs gives: the last hour's rule pairs, for the Alert Explorer. */
export interface RulePairs {
  /** null before any alert is stored. */
  start_ms: number | null;
  end_ms: number | null;
  /** A Snort rule and a Suricata rule that fired on one packet, the most packets first. */
  pairs: RulePair[];
}

export interface PairRule {
  gid: number | null;
  sid: number | null;
  rev: number | null;
  message: string;
}

export interface RulePair {
  snort: PairRule;
  suricata: PairRule;
  packets: number;
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
  /** When the machine was off in the 24 hours. */
  off?: OffPeriod[];
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
  /** When the machine was off in the window. */
  off?: OffPeriod[];
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
  /** Each engine's packets and drops over the last hour; null when its statistics can't be read. */
  capture?: Partial<Record<Engine, Capture | null>>;
  /** The disk the database is on, and what the alerts take, in bytes. */
  storage?: Storage;
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
  /** Its UID: 7 characters from its minute and its number in that minute,
   * which no other alert has. */
  uid?: string;
  /** Its packet: the UID of the packet's first stored alert, the same on
   * every alert on that packet, in every list. */
  packet?: string;
  /** Both engines alerted on its packet. */
  both: boolean;
  /** From or to a lab attacker (config/lab_phases.json), or not. */
  label?: "attack" | "background";
}

/** One alert, whole (/alerts/{id}): as the lists show it, the other alerts
 * on its packet, and what the combined JSON gives for that packet. */
export interface AlertDetails {
  alert: AlertRow;
  same_packet: AlertRow[];
  /** Each rule on the packet, by its name in the file ("snort:116:444"). */
  rules?: Record<string, Record<string, unknown>>;
  cves?: Record<string, unknown>;
  attack_techniques?: Record<string, unknown>;
  flows?: Record<string, unknown>;
  packets?: unknown[];
}

export interface AlertPage {
  total: number;
  /** How many match before "last N" keeps the newest. */
  matching: number;
  page: number;
  pages: number;
  page_size: number;
  rows: AlertRow[];
}

/** What a download or send of the filtered alerts would hold (/export/selection). */
export interface SelectionInfo {
  alerts: Partial<Record<Engine, number>>;
  total: number;
  /** The first and last alert's time; null without alerts. */
  first_ms: number | null;
  last_ms: number | null;
  /** With both engines, the latest complete time it stops at; null with one. */
  complete_end_ms: number | null;
  /** The most one file holds. */
  max_alerts: number;
}

/** The protocols, classes and services the stored alerts have (/alerts/values). */
export interface FilterValues {
  protocols: string[];
  classes: string[];
  services: string[];
}

/** What Send says once the LLM PC has taken the file. */
export interface SentSelection {
  sent: true;
  to: string;
  filename: string;
  bytes: number;
  alerts: Partial<Record<Engine, number>>;
  packets: number;
  both_engine_packets: number;
}

export interface Storage {
  disk_free: number;
  disk_total: number;
  database: number;
  archive: number;
  /** The nightly backups, and the database check made before each (when,
   * and the problem found; both null before the first); null when they are off. */
  backups: {
    count: number;
    bytes: number;
    newest_ms: number | null;
    checked_ms: number | null;
    problem: string | null;
  } | null;
}

/** An engine's packets and drops over the last hour (minutes covered). */
export interface Capture {
  packets: number;
  dropped: number;
  minutes: number;
}

/** What /archive gives: the alerts that have left the database. */
export interface ArchiveList {
  zips: { name: string; first_day: string; last_day: string; bytes: number }[];
  days: { name: string; day: string; bytes: number }[];
  /** How long the archive keeps them; left out without an archive. */
  keep_days?: number;
  zip_days?: number;
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

async function request(path: string, params: Params, signal?: AbortSignal, method = "GET"): Promise<Response> {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(name, String(value));
  }
  const text = query.toString();
  let response: Response;
  try {
    response = await fetch(text ? `${path}?${text}` : path, {
      method,
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

/** Hands a fetched file to the browser to save. */
function save(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  // After the browser has taken the file.
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/** Saves one of the archive's files, fetched with the token. */
export async function downloadArchiveFile(name: string): Promise<void> {
  const response = await request(`/archive/${encodeURIComponent(name)}`, {});
  save(await response.blob(), name);
}

/** Saves the combined JSON of the alerts the filters choose; its file name. */
export async function downloadSelection(params: Params): Promise<string> {
  const response = await request("/export/selection/file", params);
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const filename = /filename="([^"]+)"/.exec(disposition)?.[1] ?? "snort_suricata_combined.json";
  save(await response.blob(), filename);
  return filename;
}

/** Sends the combined JSON of the alerts the filters choose to the LLM PC. */
export async function sendSelection(params: Params): Promise<SentSelection> {
  return (await (await request("/export/selection/send", params, undefined, "POST")).json()) as SentSelection;
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

// The Alert Explorer's filters: what the boxes hold, and the query they make
// for the lists, the download and Send (see docs/react-native-port.md).
import type { Engine, Params } from "./api";

export interface Filters {
  /** One of the API's time ranges; "" for every stored alert. */
  range: string;
  /** One engine's alerts; "" for every engine's. */
  engine: Engine | "";
  /** From or to a lab attacker ("attack"), or not ("background"); "" for both. */
  label: "" | "attack" | "background";
  /** 1 (the most severe) to 4; none for every severity. */
  severities: number[];
  protocol: string;
  service: string;
  alertClass: string;
  rule: string;
  source: string;
  destination: string;
  port: string;
  /** Only the newest this many; null for every alert that matches. */
  last: number | null;
}

/** Every stored alert. */
export const OPEN: Filters = {
  range: "",
  engine: "",
  label: "",
  severities: [],
  protocol: "",
  service: "",
  alertClass: "",
  rule: "",
  source: "",
  destination: "",
  port: "",
  last: null,
};

/** The query the filters make; a box left empty adds nothing. */
export function filterParams(filters: Filters): Params {
  const params: Params = {
    range: filters.range,
    engine: filters.engine,
    label: filters.label,
    severity: [...filters.severities].sort().join(","),
    protocol: filters.protocol,
    class: filters.alertClass,
    service: filters.service,
    rule: filters.rule.trim(),
    source: filters.source.trim(),
    destination: filters.destination.trim(),
    port: filters.port.trim(),
    last: filters.last ?? undefined,
  };
  return Object.fromEntries(Object.entries(params).filter(([, value]) => value !== undefined && value !== ""));
}

/** How many filters are set, past "the newest N". */
export function narrowing(filters: Filters): number {
  return [
    filters.range,
    filters.engine,
    filters.label,
    filters.severities.length,
    filters.protocol,
    filters.service,
    filters.alertClass,
    filters.rule.trim(),
    filters.source.trim(),
    filters.destination.trim(),
    filters.port.trim(),
  ].filter(Boolean).length;
}

// Times come from the API as epoch milliseconds (UTC) and are shown in PKT,
// UTC+05:00 all year (Pakistan has no daylight saving time).
export const PKT_OFFSET_MS = 5 * 60 * 60 * 1000;

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function pkt(ms: number) {
  const moment = new Date(ms + PKT_OFFSET_MS);
  return {
    year: moment.getUTCFullYear(),
    month: moment.getUTCMonth(),
    day: moment.getUTCDate(),
    hours: moment.getUTCHours(),
    minutes: moment.getUTCMinutes(),
    seconds: moment.getUTCSeconds(),
  };
}

const two = (value: number) => String(value).padStart(2, "0");

function date(ms: number): string {
  const { year, month, day } = pkt(ms);
  return `${year}-${two(month + 1)}-${two(day)}`;
}

function time(ms: number): string {
  const { hours, minutes, seconds } = pkt(ms);
  return `${two(hours)}:${two(minutes)}:${two(seconds)}`;
}

/** 2026-11-03 16:40:07 */
export function stamp(ms: number): string {
  return `${date(ms)} ${time(ms)}`;
}

/** The time, with the date when it is not today. */
export function clock(ms: number, nowMs: number): string {
  if (date(ms) === date(nowMs)) return time(ms);
  const { year, month, day } = pkt(ms);
  if (year === pkt(nowMs).year) return `${day} ${MONTHS[month]} ${time(ms)}`;
  return stamp(ms);
}

/** start → end, with both dates when the span is not all today. */
export function span(startMs: number, endMs: number, nowMs: number): string {
  if (date(startMs) === date(nowMs) && date(endMs) === date(nowMs)) {
    return `${time(startMs)} → ${time(endMs)}`;
  }
  const long = (ms: number) => {
    const { year, month, day } = pkt(ms);
    return year === pkt(nowMs).year ? `${day} ${MONTHS[month]} ${time(ms)}` : stamp(ms);
  };
  return `${long(startMs)} → ${long(endMs)}`;
}

/** 35 s, 4 min, 47 h, 17 days */
export function duration(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
  if (seconds < 48 * 3600) return `${Math.floor(seconds / 3600)} h`;
  return `${Math.floor(seconds / 86400)} days`;
}

/** An axis label: the hour, or the date at midnight. */
export function hourLabel(ms: number): string {
  const { month, day, hours } = pkt(ms);
  return hours === 0 ? `${day} ${MONTHS[month]}` : `${two(hours)}:00`;
}

/** An axis label: the hour and minute. */
export function minuteLabel(ms: number): string {
  const { hours, minutes } = pkt(ms);
  return `${two(hours)}:${two(minutes)}`;
}

/** The value of a datetime-local input showing this time in PKT. */
export function toPktInput(ms: number): string {
  const { hours, minutes } = pkt(ms);
  return `${date(ms)}T${two(hours)}:${two(minutes)}`;
}

/** The time a datetime-local input means, read as PKT. */
export function fromPktInput(value: string): number | undefined {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(value);
  if (!match) return undefined;
  const [year, month, day, hours, minutes] = match.slice(1).map(Number);
  return Date.UTC(year, month - 1, day, hours, minutes) - PKT_OFFSET_MS;
}

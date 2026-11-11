import { describe, expect, it } from "vitest";
import type { Fetched, Status, Storage } from "./api";
import { backupLate, diskLow, summary } from "./StatusPanel";

const NOW = Date.UTC(2026, 10, 11, 12, 0);
const HOUR = 60 * 60 * 1000;

function storage(changes: Partial<Storage> = {}, backups: Partial<NonNullable<Storage["backups"]>> = {}): Storage {
  return {
    disk_free: 18e9, disk_total: 52e9, database: 5e8, archive: 0,
    backups: { count: 3, bytes: 1.6e8, newest_ms: NOW - 8 * HOUR, checked_ms: NOW - 8 * HOUR, problem: null, ...backups },
    ...changes,
  };
}

function status(changes: Partial<Status> = {}): Fetched<Status> {
  const data: Status = {
    checked_ms: NOW,
    running: { snort: true, suricata: true, collector: true },
    collector_saved_ms: NOW - 20_000,
    complete_end_ms: NOW - 60_000,
    alert_retention: 600_000,
    engines: {},
    storage: storage(),
    ...changes,
  };
  return { data, error: "", receivedMs: NOW };
}

describe("the status panel's headline", () => {
  it("is Live while all is well", () => {
    expect(summary(status(), NOW, NOW).label).toBe("Live");
  });

  it("says when the database is damaged, before the disk", () => {
    const damaged = status({ storage: storage({ disk_free: 1e9 }, { problem: "Tree 4 page 912: btreeInitPage() error" }) });

    expect(summary(damaged, NOW, NOW)).toEqual({
      level: "down", label: "Database damaged", detail: "Tree 4 page 912: btreeInitPage() error",
    });
  });

  it("warns when the disk is almost full", () => {
    expect(summary(status({ storage: storage({ disk_free: 1.5e9 }) }), NOW, NOW)).toEqual({
      level: "warn", label: "Disk almost full", detail: "1.5 GB free",
    });
  });

  it("puts the collector and the engines first", () => {
    expect(summary(status({ running: { snort: true, suricata: true, collector: false } }), NOW, NOW).label).toBe("Not updating");
    expect(summary(status({ running: { snort: false, suricata: true, collector: true } }), NOW, NOW)).toMatchObject({
      label: "Partly working", detail: "Snort not running",
    });
    expect(summary(status({ collector_saved_ms: NOW - 10 * 60_000 }), NOW, NOW).label).toBe("No new alerts");
    expect(summary({ data: null, error: "the API is down", receivedMs: null }, NOW, NOW).label).toBe("Not updating");
  });
});

describe("the disk and the backup", () => {
  it("is low under 2 GB, or 5% of a big disk", () => {
    expect(diskLow(storage({ disk_free: 1.9e9 }))).toBe(true);
    // 5% of 52 GB is 2.6 GB.
    expect(diskLow(storage({ disk_free: 2.5e9 }))).toBe(true);
    expect(diskLow(storage({ disk_free: 2.7e9 }))).toBe(false);
    expect(diskLow(storage({ disk_free: 40e9, disk_total: 1e12 }))).toBe(true);
  });

  it("is late after a day and a half, and never without backups", () => {
    expect(backupLate(storage({}, { newest_ms: NOW - 37 * HOUR }), NOW)).toBe(true);
    expect(backupLate(storage({}, { newest_ms: NOW - 30 * HOUR }), NOW)).toBe(false);
    expect(backupLate(storage({}, { newest_ms: null }), NOW)).toBe(false);
    expect(backupLate(storage({ backups: null }), NOW)).toBe(false);
  });
});

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ruleEntry } from "./AlertDetail";
import { SeverityCircles, arrived, filledCircles, packetKey, packetShades } from "./AlertExplorer";
import type { AlertRow } from "./api";

/** A row on ``packet``; the list puts the newest first. */
function row(id: number, packet: number | string): AlertRow {
  return {
    id, packet: String(packet), uid: `uid-${id}`, engine: "suricata", time_ms: id * 1000, rule: "1:1:1", gid: 1, sid: 1, rev: 1,
    message: "", class: null, severity: 3, protocol: null, service: null, src: null, dst: null, both: false,
  };
}

const shaded = (shades: Map<string, boolean>) => [...shades].filter(([, shade]) => shade).map(([packet]) => packet);

describe("packetShades", () => {
  it("shades every other packet from the bottom, a packet's rows together", () => {
    const shades = packetShades([row(9, 5), row(8, 5), row(7, 4), row(6, 3), row(5, 3)], new Map());

    expect(Object.fromEntries(shades)).toEqual({ 3: false, 4: true, 5: false });
  });

  it("names a row without a packet by its own UID", () => {
    const rows = [row(2, 2), { ...row(1, 1), packet: undefined }];

    expect(Object.fromEntries(packetShades(rows, new Map()))).toEqual({ "uid-1": false, 2: true });
    expect(packetKey({ ...row(1, 1), packet: undefined, uid: undefined })).toBe("1");
  });

  it("keeps each packet's shade across a refresh, as new packets arrive on top", () => {
    const first = packetShades([row(9, 5), row(7, 4), row(6, 3)], new Map());
    // Packet 6 came in on top, and packet 3 went to the next page.
    const second = packetShades([row(10, 6), row(9, 5), row(7, 4)], first);

    expect(shaded(first)).toEqual(["4"]);
    expect(Object.fromEntries(second)).toEqual({ 4: true, 5: false, 6: true });
  });

  it("changes a kept shade only where it would match the packet below", () => {
    // 4 and 5 were both plain, apart (a packet between them is gone now).
    const previous = new Map([["5", false], ["4", false]]);

    expect(Object.fromEntries(packetShades([row(9, 5), row(7, 4)], previous))).toEqual({ 4: false, 5: true });
  });
});

describe("severity circles", () => {
  it("fills one circle more for each step more severe", () => {
    expect([1, 2, 3, 4].map(filledCircles)).toEqual([3, 2, 1, 0]);
    expect([0, 5].map(filledCircles)).toEqual([3, 0]);
  });

  it("draws three circles, says the severity, and colours them by it", () => {
    const markup = renderToStaticMarkup(<SeverityCircles severity={2} />);

    expect(markup.match(/<i/g)).toHaveLength(3);
    expect(markup.match(/class="filled"/g)).toHaveLength(2);
    expect(markup).toContain('title="Severity 2: high"');
    expect(markup).toContain("level-2");
  });
});

describe("arrived", () => {
  it("names the rows that were not in the list a moment ago", () => {
    const rows = [row(9, 5), row(8, 5), row(7, 4)];

    expect([...arrived(new Set([7, 6]), rows)]).toEqual([9, 8]);
    // Nothing to compare with (the first answer, or another list): none.
    expect(arrived(null, rows).size).toBe(0);
  });
});

describe("ruleEntry", () => {
  it("finds the alert's rule among the packet's, with its revision when two fired", () => {
    const alert = { ...row(1, 1), engine: "snort" as const, rule: "116:444", rev: 1 };

    expect(ruleEntry({ "snort:116:444": { rule_text: "a" }, "suricata:2001119": {} }, alert)).toEqual({ rule_text: "a" });
    expect(ruleEntry({ "snort:116:444:rev1": { rule_text: "b" } }, alert)).toEqual({ rule_text: "b" });
    expect(ruleEntry({ "suricata:2001119": {} }, alert)).toBeNull();
    expect(ruleEntry(undefined, alert)).toBeNull();
  });
});

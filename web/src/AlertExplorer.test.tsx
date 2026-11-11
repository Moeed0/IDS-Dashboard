import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { SeverityCircles, filledCircles, packetShades } from "./AlertExplorer";
import type { AlertRow } from "./api";

/** A row on ``packet``; the list puts the newest first. */
function row(id: number, packet: number): AlertRow {
  return {
    id, packet, engine: "suricata", time_ms: id * 1000, rule: "1:1:1", gid: 1, sid: 1, rev: 1,
    message: "", class: null, severity: 3, protocol: null, service: null, src: null, dst: null, both: false,
  };
}

const shaded = (shades: Map<number, boolean>) => [...shades].filter(([, shade]) => shade).map(([packet]) => packet);

describe("packetShades", () => {
  it("shades every other packet from the bottom, a packet's rows together", () => {
    const shades = packetShades([row(9, 5), row(8, 5), row(7, 4), row(6, 3), row(5, 3)], new Map());

    expect(Object.fromEntries(shades)).toEqual({ 3: false, 4: true, 5: false });
  });

  it("names a row without a packet by its own id", () => {
    const rows = [row(2, 2), { ...row(1, 1), packet: undefined }];

    expect(Object.fromEntries(packetShades(rows, new Map()))).toEqual({ 1: false, 2: true });
  });

  it("keeps each packet's shade across a refresh, as new packets arrive on top", () => {
    const first = packetShades([row(9, 5), row(7, 4), row(6, 3)], new Map());
    // Packet 6 came in on top, and packet 3 went to the next page.
    const second = packetShades([row(10, 6), row(9, 5), row(7, 4)], first);

    expect(shaded(first)).toEqual([4]);
    expect(Object.fromEntries(second)).toEqual({ 4: true, 5: false, 6: true });
  });

  it("changes a kept shade only where it would match the packet below", () => {
    // 4 and 5 were both plain, apart (a packet between them is gone now).
    const previous = new Map([[5, false], [4, false]]);

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

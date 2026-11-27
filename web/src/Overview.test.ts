import { describe, expect, it } from "vitest";
import { offState, type RulesOff } from "./api";

const rule = { engine: "suricata" as const, gid: 1, sid: 2002752 };
const listed = { ...rule, rule: "1:2002752", message: "ET INFO Reserved Internal IP Traffic", added_ms: 1 };

describe("offState", () => {
  it("follows a ticked rule until its engine has taken it", () => {
    const waiting: RulesOff = { enabled: true, rules: [listed], applied: null };
    expect(offState(rule, waiting)).toBe("applying");
    const taken: RulesOff = { ...waiting, applied: { applied_ms: 2, rules: [rule], engines: { suricata: "reloaded" } } };
    expect(offState(rule, taken)).toBe("off");
    const failed: RulesOff = { ...waiting, applied: { applied_ms: 2, rules: [rule], engines: { suricata: "error: no" } } };
    expect(offState(rule, failed)).toBe("error");
    const refused: RulesOff = { ...waiting, applied: { applied_ms: 2, engines: {}, error: "the list isn't JSON" } };
    expect(offState(rule, refused)).toBe("error");
  });

  it("says when an unticked rule is still off, and nothing once it is back on", () => {
    const unticked: RulesOff = { enabled: true, rules: [], applied: { applied_ms: 2, rules: [rule], engines: {} } };
    expect(offState(rule, unticked)).toBe("restoring");
    expect(offState(rule, { ...unticked, applied: { applied_ms: 3, rules: [], engines: {} } })).toBeNull();
  });
});

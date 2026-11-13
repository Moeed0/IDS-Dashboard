import { describe, expect, it } from "vitest";
import { lastFrom } from "./AlertExplorer";
import { OPEN, filterParams, narrowing } from "./filters";

describe("filterParams", () => {
  it("asks for every stored alert when nothing is set", () => {
    expect(filterParams(OPEN)).toEqual({});
  });

  it("sends every filter that is set, as the API names it", () => {
    const params = filterParams({
      range: "Last 15 minutes",
      engine: "snort",
      severities: [2, 1],
      protocol: "UDP",
      alertClass: "Potentially Bad Traffic",
      service: "dns",
      app: "IGMP",
      rule: " 116:444 ",
      source: "192.168.50.0/24",
      destination: "192.168.50.1",
      port: "53",
      last: 20,
    });

    expect(params).toEqual({
      range: "Last 15 minutes",
      engine: "snort",
      severity: "1,2",
      protocol: "UDP",
      class: "Potentially Bad Traffic",
      service: "dns",
      app: "IGMP",
      rule: "116:444",
      source: "192.168.50.0/24",
      destination: "192.168.50.1",
      port: "53",
      last: 20,
    });
  });
});

describe("narrowing", () => {
  it("counts the filters set, past the newest few", () => {
    expect(narrowing({ ...OPEN, last: 5 })).toBe(0);
    expect(narrowing({ ...OPEN, severities: [1], port: "53", rule: " " })).toBe(2);
    expect(narrowing({ ...OPEN, range: "Last 5 minutes" })).toBe(1);
  });
});

describe("lastFrom", () => {
  it("takes a whole number from 1, up to the most allowed", () => {
    expect(lastFrom("20", 150_000)).toBe(20);
    expect(lastFrom("7.9", 150_000)).toBe(7);
    expect(lastFrom("999999", 150_000)).toBe(150_000);
    expect(lastFrom("", 150_000)).toBeNull();
    expect(lastFrom("0", 150_000)).toBeNull();
    expect(lastFrom("-3", 150_000)).toBeNull();
  });
});

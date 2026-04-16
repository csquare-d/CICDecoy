import { describe, it, expect } from "vitest";
import {
  formatDuration,
  parseDict,
  resolveIP,
  resolveUser,
  resolveCommand,
  techIds,
  fmtTime,
} from "./utils";

describe("formatDuration", () => {
  it("returns -- for null", () => {
    expect(formatDuration(null)).toBe("--");
  });

  it("returns -- for undefined", () => {
    expect(formatDuration(undefined)).toBe("--");
  });

  it("returns -- for zero", () => {
    expect(formatDuration(0)).toBe("--");
  });

  it("returns -- for negative values", () => {
    expect(formatDuration(-10)).toBe("--");
  });

  it("formats seconds under a minute", () => {
    expect(formatDuration(45)).toBe("45s");
  });

  it("rounds fractional seconds", () => {
    expect(formatDuration(3.7)).toBe("4s");
  });

  it("formats minutes and seconds", () => {
    expect(formatDuration(125)).toBe("2m 5s");
  });

  it("formats exactly 60 seconds as 1m 0s", () => {
    expect(formatDuration(60)).toBe("1m 0s");
  });

  it("formats hours and minutes", () => {
    expect(formatDuration(3661)).toBe("1h 1m");
  });

  it("formats exactly one hour", () => {
    expect(formatDuration(3600)).toBe("1h 0m");
  });
});

describe("parseDict", () => {
  it("returns empty object for null", () => {
    expect(parseDict(null)).toEqual({});
  });

  it("returns empty object for undefined", () => {
    expect(parseDict(undefined)).toEqual({});
  });

  it("returns the object as-is if already an object", () => {
    const obj = { a: 1 };
    expect(parseDict(obj)).toBe(obj);
  });

  it("parses a valid JSON string", () => {
    expect(parseDict('{"key":"val"}')).toEqual({ key: "val" });
  });

  it("returns empty object for invalid JSON string", () => {
    expect(parseDict("not-json")).toEqual({});
  });

  it("returns empty object for a number", () => {
    expect(parseDict(42)).toEqual({});
  });
});

describe("resolveIP", () => {
  it("returns source_ip from top level", () => {
    expect(resolveIP({ source_ip: "1.2.3.4" })).toBe("1.2.3.4");
  });

  it("returns src_ip from top level", () => {
    expect(resolveIP({ src_ip: "5.6.7.8" })).toBe("5.6.7.8");
  });

  it("returns client_ip from top level", () => {
    expect(resolveIP({ client_ip: "9.0.1.2" })).toBe("9.0.1.2");
  });

  it("resolves IP from data field (object)", () => {
    expect(resolveIP({ data: { client_ip: "10.0.0.1" } })).toBe("10.0.0.1");
  });

  it("resolves IP from data field (JSON string)", () => {
    expect(resolveIP({ data: '{"source_ip":"10.0.0.2"}' })).toBe("10.0.0.2");
  });

  it("resolves IP from raw_data field", () => {
    expect(resolveIP({ raw_data: { ip: "172.16.0.1" } })).toBe("172.16.0.1");
  });

  it("returns empty string when no IP found", () => {
    expect(resolveIP({})).toBe("");
  });
});

describe("resolveUser", () => {
  it("returns username from top level", () => {
    expect(resolveUser({ username: "root" })).toBe("root");
  });

  it("returns user from top level", () => {
    expect(resolveUser({ user: "admin" })).toBe("admin");
  });

  it("resolves from data field", () => {
    expect(resolveUser({ data: { username: "bob" } })).toBe("bob");
  });

  it("resolves from raw_data field", () => {
    expect(resolveUser({ raw_data: { user: "eve" } })).toBe("eve");
  });

  it("returns empty string when not found", () => {
    expect(resolveUser({})).toBe("");
  });
});

describe("resolveCommand", () => {
  it("resolves command from data.command", () => {
    expect(resolveCommand({ data: { command: "ls -la" } })).toBe("ls -la");
  });

  it("resolves from data.input", () => {
    expect(resolveCommand({ data: { input: "whoami" } })).toBe("whoami");
  });

  it("resolves from raw_data.cmd", () => {
    expect(resolveCommand({ raw_data: { cmd: "cat /etc/passwd" } })).toBe("cat /etc/passwd");
  });

  it("resolves from top-level command", () => {
    expect(resolveCommand({ command: "id" })).toBe("id");
  });

  it("returns empty string when not found", () => {
    expect(resolveCommand({})).toBe("");
  });
});

describe("techIds", () => {
  it("returns empty array for null", () => {
    expect(techIds(null)).toEqual([]);
  });

  it("returns empty array for empty array", () => {
    expect(techIds([])).toEqual([]);
  });

  it("extracts technique_id from objects", () => {
    const arr = [
      { technique_id: "T1059", technique_name: "Scripting" },
      { technique_id: "T1078", technique_name: "Valid Accounts" },
    ];
    expect(techIds(arr)).toEqual(["T1059", "T1078"]);
  });

  it("converts string entries directly", () => {
    expect(techIds(["T1059", "T1078"])).toEqual(["T1059", "T1078"]);
  });

  it("filters out empty technique_ids", () => {
    expect(techIds([{ technique_id: "" }, { technique_id: "T1059" }])).toEqual(["T1059"]);
  });
});

describe("fmtTime", () => {
  it("formats an ISO timestamp to HH:MM:SS", () => {
    // Use a fixed UTC time and check format pattern
    const result = fmtTime("2024-01-15T08:30:45Z");
    // Should be in HH:MM:SS format (exact value depends on locale/timezone)
    expect(result).toMatch(/^\d{2}:\d{2}:\d{2}$/);
  });
});

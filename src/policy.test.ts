import { describe, expect, it } from "vitest";
import { compileDenyMatcher, type DenyMatcher } from "./matcher.js";
import { createFsGuardPolicy, POLICY_ID } from "./policy.js";

const matcher = compileDenyMatcher(["**/.env*", "**/.ssh/**"]);
const policy = createFsGuardPolicy(matcher);
const ctx = {} as any;

function evaluate(event: Record<string, unknown>) {
  return policy.evaluate(event as any, ctx);
}

describe("policy registration shape", () => {
  it("uses the declared policy id", () => {
    expect(policy.id).toBe(POLICY_ID);
    expect(POLICY_ID).toBe("fs-guard-path-deny");
    expect(policy.description).toBeTruthy();
  });
});

describe("guarded fs tools", () => {
  it.each(["read", "write", "edit"])("blocks %s targeting a denied path", (toolName) => {
    const decision = evaluate({ toolName, params: { path: "/work/.env" } });
    expect(decision).toEqual({
      block: true,
      blockReason: "fs-guard: /work/.env matches deny pattern **/.env*",
    });
  });

  it.each(["read", "write", "edit"])("passes %s targeting a clean path", (toolName) => {
    expect(evaluate({ toolName, params: { path: "/work/src/app.ts" } })).toBeUndefined();
  });

  it("blocks apply_patch when derivedPaths hit", () => {
    const decision = evaluate({
      toolName: "apply_patch",
      params: { input: "*** Begin Patch ..." },
      derivedPaths: ["/work/src/ok.ts", "/work/.ssh/config"],
    });
    expect(decision).toMatchObject({ block: true });
    expect((decision as any).blockReason).toContain("**/.ssh/**");
  });

  it("passes apply_patch when all derivedPaths are clean", () => {
    const decision = evaluate({
      toolName: "apply_patch",
      params: { input: "*** Begin Patch ..." },
      derivedPaths: ["/work/src/a.ts", "/work/src/b.ts"],
    });
    expect(decision).toBeUndefined();
  });

  it("checks derivedPaths in addition to params.path for read", () => {
    const decision = evaluate({
      toolName: "read",
      params: { path: "/work/ok.txt" },
      derivedPaths: ["/work/.env"],
    });
    expect(decision).toMatchObject({ block: true });
  });
});

describe("toolName casing", () => {
  it("blocks READ (uppercase) targeting a denied path", () => {
    const decision = evaluate({ toolName: "READ", params: { path: "/work/.env" } });
    expect(decision).toEqual({
      block: true,
      blockReason: "fs-guard: /work/.env matches deny pattern **/.env*",
    });
  });

  it("passes Read (title-case) targeting a clean path", () => {
    expect(evaluate({ toolName: "Read", params: { path: "/work/src/app.ts" } })).toBeUndefined();
  });
});

describe("non-fs tools", () => {
  it("returns no decision for unrelated tools", () => {
    expect(evaluate({ toolName: "exec", params: { command: "cat /work/.env" } })).toBeUndefined();
  });

  it("evaluates unknown tools that carry derivedPaths", () => {
    const decision = evaluate({
      toolName: "future_fs_tool",
      params: {},
      derivedPaths: ["/work/.env"],
    });
    expect(decision).toMatchObject({ block: true });
  });
});

describe("fail-closed", () => {
  const FAIL_CLOSED = {
    block: true,
    blockReason: "fs-guard: could not determine target path (fail-closed)",
  };

  it("blocks apply_patch without derivedPaths", () => {
    expect(evaluate({ toolName: "apply_patch", params: { input: "..." } })).toEqual(FAIL_CLOSED);
  });

  it("blocks read with missing path", () => {
    expect(evaluate({ toolName: "read", params: {} })).toEqual(FAIL_CLOSED);
  });

  it("blocks read with non-string path", () => {
    expect(evaluate({ toolName: "read", params: { path: 42 } })).toEqual(FAIL_CLOSED);
  });

  it("blocks write with empty-string path", () => {
    expect(evaluate({ toolName: "write", params: { path: "" } })).toEqual(FAIL_CLOSED);
  });

  it("blocks read with array path (non-string candidate → unresolvable)", () => {
    expect(evaluate({ toolName: "read", params: { path: ["/ok.txt", "/work/.env"] } })).toEqual(
      FAIL_CLOSED,
    );
  });

  it("blocks read when params key is missing (catch branch)", () => {
    const decision = evaluate({ toolName: "read" });
    expect((decision as any).block).toBe(true);
    expect((decision as any).blockReason).toContain("fail-closed");
  });

  it("blocks unknown tool with empty derivedPaths (no candidates)", () => {
    expect(evaluate({ toolName: "future_tool", params: {}, derivedPaths: [] })).toEqual(
      FAIL_CLOSED,
    );
  });

  it("blocks when the matcher throws", () => {
    const throwing: DenyMatcher = {
      match: () => {
        throw new Error("boom");
      },
    };
    const broken = createFsGuardPolicy(throwing);
    const decision = broken.evaluate(
      { toolName: "read", params: { path: "/work/ok.txt" } } as any,
      ctx,
    );
    expect(decision).toMatchObject({ block: true });
    expect((decision as any).blockReason).toContain("fail-closed");
  });
});

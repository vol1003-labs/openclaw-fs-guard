import { describe, expect, it, vi } from "vitest";
import { register } from "./index.js";

function fakeApi(overrides: Record<string, unknown> = {}) {
  return {
    registrationMode: "full",
    pluginConfig: { denyPatterns: ["**/.env*"] },
    registerTrustedToolPolicy: vi.fn(),
    ...overrides,
  } as any;
}

describe("register", () => {
  it("registers one trusted tool policy with the declared id", () => {
    const api = fakeApi();
    register(api);
    expect(api.registerTrustedToolPolicy).toHaveBeenCalledTimes(1);
    const policy = api.registerTrustedToolPolicy.mock.calls[0]![0];
    expect(policy.id).toBe("fs-guard-path-deny");
    expect(typeof policy.evaluate).toBe("function");
  });

  it("registers a working policy (end-to-end deny)", () => {
    const api = fakeApi();
    register(api);
    const policy = api.registerTrustedToolPolicy.mock.calls[0]![0];
    const decision = policy.evaluate({ toolName: "read", params: { path: "/w/.env" } }, {} as any);
    expect(decision).toMatchObject({ block: true });
  });

  it("throws on invalid config and registers nothing", () => {
    const api = fakeApi({ pluginConfig: { denyPatterns: [] } });
    expect(() => register(api)).toThrow(/must not be empty/);
    expect(api.registerTrustedToolPolicy).not.toHaveBeenCalled();
  });

  it("throws on missing config", () => {
    const api = fakeApi({ pluginConfig: undefined });
    expect(() => register(api)).toThrow(/must be an object/);
  });

  it("is a no-op when registrationMode is not 'full'", () => {
    for (const mode of ["discovery", "cli-metadata"]) {
      const api = fakeApi({ registrationMode: mode, pluginConfig: undefined });
      expect(() => register(api)).not.toThrow();
      expect(api.registerTrustedToolPolicy).not.toHaveBeenCalled();
    }
  });
});

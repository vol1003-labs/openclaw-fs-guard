import { describe, expect, it } from "vitest";
import { resolveFsGuardConfig } from "./config.js";

describe("resolveFsGuardConfig", () => {
  it("accepts a valid config", () => {
    const config = resolveFsGuardConfig({ denyPatterns: ["**/.env*", "/proc/**"] });
    expect(config).toEqual({ denyPatterns: ["**/.env*", "/proc/**"] });
  });

  it("tolerates unknown extra keys", () => {
    const config = resolveFsGuardConfig({ denyPatterns: ["**/.ssh/**"], future: true });
    expect(config.denyPatterns).toEqual(["**/.ssh/**"]);
  });

  it("throws when config is undefined", () => {
    expect(() => resolveFsGuardConfig(undefined)).toThrow(/must be an object/);
  });

  it("throws when config is null", () => {
    expect(() => resolveFsGuardConfig(null)).toThrow(/must be an object/);
  });

  it("throws when denyPatterns is missing", () => {
    expect(() => resolveFsGuardConfig({})).toThrow(/denyPatterns must be an array/);
  });

  it("throws when denyPatterns is not an array", () => {
    expect(() => resolveFsGuardConfig({ denyPatterns: "**/.env*" })).toThrow(
      /denyPatterns must be an array/,
    );
  });

  it("throws when denyPatterns is empty", () => {
    expect(() => resolveFsGuardConfig({ denyPatterns: [] })).toThrow(/must not be empty/);
  });

  it("throws when an element is not a string", () => {
    expect(() => resolveFsGuardConfig({ denyPatterns: ["**/.env*", 42] })).toThrow(
      /denyPatterns\[1\] must be a non-empty string/,
    );
  });

  it("throws when an element is an empty string", () => {
    expect(() => resolveFsGuardConfig({ denyPatterns: [""] })).toThrow(
      /denyPatterns\[0\] must be a non-empty string/,
    );
  });

  it("throws when an element is whitespace only", () => {
    expect(() => resolveFsGuardConfig({ denyPatterns: ["   "] })).toThrow(
      /denyPatterns\[0\] must be a non-empty string/,
    );
  });
});

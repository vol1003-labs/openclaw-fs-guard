import path from "node:path";
import picomatch from "picomatch";

export type MatchResult =
  | { kind: "deny"; path: string; pattern: string }
  | { kind: "unresolvable"; path: string }
  | { kind: "clean" };

export type DenyMatcher = {
  match: (rawPath: unknown) => MatchResult;
};

const PICOMATCH_OPTIONS = { dot: true, nocase: true } as const;

export function compileDenyMatcher(patterns: readonly string[]): DenyMatcher {
  const compiled = patterns.map((pattern) => ({
    pattern,
    isMatch: picomatch(pattern, PICOMATCH_OPTIONS),
  }));
  return {
    match(rawPath: unknown): MatchResult {
      if (typeof rawPath !== "string" || rawPath.trim() === "" || rawPath.includes("\0")) {
        return { kind: "unresolvable", path: String(rawPath) };
      }
      const normalized = path.posix.normalize(rawPath.replaceAll("\\", "/"));
      for (const { pattern, isMatch } of compiled) {
        if (isMatch(normalized)) {
          return { kind: "deny", path: normalized, pattern };
        }
      }
      return { kind: "clean" };
    },
  };
}

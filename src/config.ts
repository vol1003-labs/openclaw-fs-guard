export type FsGuardConfig = {
  denyPatterns: string[];
};

export function resolveFsGuardConfig(raw: unknown): FsGuardConfig {
  if (raw === null || typeof raw !== "object") {
    throw new Error("fs-guard: plugin config must be an object with denyPatterns");
  }
  const denyPatterns = (raw as Record<string, unknown>).denyPatterns;
  if (!Array.isArray(denyPatterns)) {
    throw new Error("fs-guard: denyPatterns must be an array of glob pattern strings");
  }
  if (denyPatterns.length === 0) {
    throw new Error("fs-guard: denyPatterns must not be empty (no default patterns are bundled)");
  }
  const patterns: string[] = [];
  for (const [index, pattern] of denyPatterns.entries()) {
    if (typeof pattern !== "string" || pattern.trim() === "") {
      throw new Error(`fs-guard: denyPatterns[${index}] must be a non-empty string`);
    }
    patterns.push(pattern);
  }
  return { denyPatterns: patterns };
}

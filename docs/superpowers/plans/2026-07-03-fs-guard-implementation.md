# openclaw-fs-guard v0.1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship openclaw-fs-guard v0.1.0 — an OpenClaw plugin registering one trusted tool policy that denies fs tool calls whose target path matches operator-configured glob patterns — as a GitHub release tarball.

**Architecture:** Four small ESM/TS units: `src/config.ts` (shape validation, throws on bad config), `src/matcher.ts` (picomatch precompile + path normalization + match), `src/policy.ts` (evaluate: guard detection, path collection, fail-closed blocks), `index.ts` (plugin entry wiring). Spec: `docs/superpowers/specs/2026-07-03-fs-guard-design.md`.

**Tech Stack:** TypeScript (strict, NodeNext), picomatch, vitest, biome, GitHub Actions.

## Global Constraints

- Plugin id: `fs-guard`. Policy id: `fs-guard-path-deny` (must appear in `contracts.trustedToolPolicies`).
- Config: `{ "denyPatterns": string[] }` — required, non-empty, non-empty-string items. NO bundled default patterns anywhere in source.
- Fail-closed: unresolvable path / zero collected paths on a guarded call / any evaluate throw ⇒ `{ block: true, blockReason: ... }`.
- Never return an explicit allow; clean paths and non-guarded tools return `undefined`.
- picomatch options are exactly `{ dot: true, nocase: true }`.
- Release asset must be `openclaw-fs-guard-0.1.0.tgz` attached to tag `v0.1.0`.
- Node >= 20, `openclaw` 2026.6.10 devDependency / `>=2026.6.10` peerDependency.
- Do not mention any private infrastructure in any file — this is a public repo.
- All commits end with `Co-Authored-By:` trailer per session convention.

---

### Task 1: Project scaffolding

**Files:**
- Create: `package.json`, `tsconfig.json`, `tsconfig.build.json`, `biome.json`, `vitest.config.ts`, `.gitignore`, `LICENSE`, `openclaw.plugin.json`

**Interfaces:**
- Produces: build/test toolchain used by every later task (`npm run check|typecheck|test|build`); the plugin manifest with `contracts.trustedToolPolicies: ["fs-guard-path-deny"]` consumed by the host at install time.

Note: `npm run typecheck` does not pass until Task 2 creates the first TS file (tsc errors on zero inputs). Verification for this task is install + biome only.

- [ ] **Step 1: Write `package.json`**

```json
{
  "name": "openclaw-fs-guard",
  "version": "0.1.0",
  "description": "OpenClaw trusted tool policy that denies filesystem tool calls targeting paths matching configured deny glob patterns.",
  "license": "MIT",
  "type": "module",
  "repository": {
    "type": "git",
    "url": "https://github.com/vol1003-labs/openclaw-fs-guard"
  },
  "files": [
    "dist",
    "openclaw.plugin.json",
    "README.md",
    "LICENSE"
  ],
  "scripts": {
    "build": "tsc -p tsconfig.build.json",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "lint": "biome lint .",
    "format": "biome format --write .",
    "check": "biome check .",
    "check:fix": "biome check --write .",
    "test": "vitest run",
    "test:coverage": "vitest run --coverage",
    "prepack": "npm run build"
  },
  "dependencies": {
    "picomatch": "^4.0.2"
  },
  "peerDependencies": {
    "openclaw": ">=2026.6.10"
  },
  "devDependencies": {
    "@biomejs/biome": "^2.5.1",
    "@types/node": "^26.0.1",
    "@types/picomatch": "^4.0.2",
    "@vitest/coverage-v8": "^4.1.9",
    "openclaw": "2026.6.10",
    "typescript": "^6.0.3",
    "vitest": "^4.1.9"
  },
  "engines": {
    "node": ">=20"
  },
  "openclaw": {
    "extensions": ["./index.ts"],
    "runtimeExtensions": ["./dist/index.js"],
    "install": {
      "npmSpec": "openclaw-fs-guard",
      "defaultChoice": "npm",
      "minHostVersion": ">=2026.6.10"
    },
    "compat": {
      "pluginApi": ">=2026.6.10"
    },
    "build": {
      "openclawVersion": "2026.6.10",
      "bundledDist": false
    }
  }
}
```

- [ ] **Step 2: Write `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2023"],
    "types": ["node"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "verbatimModuleSyntax": true,
    "skipLibCheck": true,
    "declaration": true,
    "sourceMap": true,
    "outDir": "dist",
    "rootDir": "."
  },
  "include": ["index.ts", "src/**/*.ts"]
}
```

- [ ] **Step 3: Write `tsconfig.build.json`**

```json
{
  "extends": "./tsconfig.json",
  "exclude": ["src/**/*.test.ts", "vitest.config.ts", "index.test.ts"]
}
```

- [ ] **Step 4: Write `biome.json`**

```json
{
  "$schema": "https://biomejs.dev/schemas/2.5.1/schema.json",
  "vcs": {
    "enabled": true,
    "clientKind": "git",
    "useIgnoreFile": true
  },
  "files": {
    "ignoreUnknown": true
  },
  "formatter": {
    "enabled": true,
    "indentStyle": "space",
    "indentWidth": 2,
    "lineWidth": 100
  },
  "linter": {
    "enabled": true,
    "rules": {
      "preset": "recommended"
    }
  },
  "javascript": {
    "formatter": {
      "quoteStyle": "double",
      "semicolons": "always",
      "trailingCommas": "all"
    }
  },
  "assist": {
    "actions": {
      "source": {
        "organizeImports": "on"
      }
    }
  },
  "overrides": [
    {
      "includes": ["**/*.test.ts"],
      "linter": {
        "rules": {
          "suspicious": { "noExplicitAny": "off" },
          "style": { "noNonNullAssertion": "off" }
        }
      }
    }
  ]
}
```

- [ ] **Step 5: Write `vitest.config.ts`**

```typescript
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "text-summary", "html", "lcov"],
      reportsDirectory: "./coverage",
      include: ["src/**/*.ts", "index.ts"],
      exclude: ["**/*.test.ts", "**/*.d.ts"],
      all: true,
    },
  },
});
```

- [ ] **Step 6: Write `.gitignore`**

```
node_modules/
dist/
*.tsbuildinfo
coverage/
```

- [ ] **Step 7: Write `LICENSE`** (MIT, copyright `2026 vol1003-labs`)

```
MIT License

Copyright (c) 2026 vol1003-labs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 8: Write `openclaw.plugin.json`**

```json
{
  "id": "fs-guard",
  "name": "FS Guard",
  "description": "Denies filesystem tool calls targeting paths that match configured deny glob patterns.",
  "activation": { "onStartup": true },
  "contracts": { "trustedToolPolicies": ["fs-guard-path-deny"] },
  "configSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["denyPatterns"],
    "properties": {
      "denyPatterns": {
        "type": "array",
        "minItems": 1,
        "items": { "type": "string", "minLength": 1 }
      }
    }
  }
}
```

- [ ] **Step 9: Install and verify**

Run: `npm install`
Expected: succeeds, creates `package-lock.json`.

Run: `npm run check`
Expected: exit 0 (biome passes; JSON files formatted as written).

- [ ] **Step 10: Commit**

```bash
git add package.json package-lock.json tsconfig.json tsconfig.build.json biome.json vitest.config.ts .gitignore LICENSE openclaw.plugin.json
git commit -m "chore: scaffold TS/ESM plugin project

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Config validation (`src/config.ts`)

**Files:**
- Create: `src/config.ts`
- Test: `src/config.test.ts`

**Interfaces:**
- Consumes: nothing (pure function).
- Produces: `resolveFsGuardConfig(raw: unknown): FsGuardConfig` where `FsGuardConfig = { denyPatterns: string[] }`. Throws `Error` on invalid input. Used by Task 5 (`index.ts`).

- [ ] **Step 1: Write the failing test `src/config.test.ts`**

```typescript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/config.test.ts`
Expected: FAIL — cannot resolve `./config.js`.

- [ ] **Step 3: Write `src/config.ts`**

```typescript
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/config.test.ts`
Expected: PASS (10 tests).

- [ ] **Step 5: Typecheck and lint**

Run: `npm run typecheck && npm run check`
Expected: both exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/config.ts src/config.test.ts
git commit -m "feat: add denyPatterns config validation (throws on invalid config)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Deny matcher (`src/matcher.ts`)

**Files:**
- Create: `src/matcher.ts`
- Test: `src/matcher.test.ts`

**Interfaces:**
- Consumes: nothing project-internal; `picomatch`, `node:path`.
- Produces (used by Tasks 4 and 5):

```typescript
type MatchResult =
  | { kind: "deny"; path: string; pattern: string }
  | { kind: "unresolvable"; path: string }
  | { kind: "clean" };
type DenyMatcher = { match: (rawPath: unknown) => MatchResult };
function compileDenyMatcher(patterns: readonly string[]): DenyMatcher; // throws on compile failure
```

- [ ] **Step 1: Write the failing test `src/matcher.test.ts`**

The test pins the README's recommended pattern set — keep this list in sync with the README (Task 6).

```typescript
import { describe, expect, it } from "vitest";
import { compileDenyMatcher } from "./matcher.js";

const RECOMMENDED_PATTERNS = [
  "**/.env*",
  "**/*.pem",
  "**/*.key",
  "**/id_rsa*",
  "**/id_ed25519*",
  "**/id_ecdsa*",
  "**/credentials*.json",
  "**/.netrc",
  "**/.git-credentials",
  "**/*kubeconfig*",
  "**/serviceaccount/**",
  "/var/run/secrets/**",
  "/proc/**",
  "**/.ssh/**",
  "**/auth-profiles.json",
  "**/.npmrc",
];

const matcher = compileDenyMatcher(RECOMMENDED_PATTERNS);

function expectDeny(path: string, pattern: string) {
  expect(matcher.match(path)).toEqual({ kind: "deny", path: expect.any(String), pattern });
}

describe("compileDenyMatcher — hits", () => {
  it("denies .env files at any depth", () => {
    expectDeny("/work/.env", "**/.env*");
    expectDeny(".env", "**/.env*");
    expectDeny("/work/app/.env.local", "**/.env*");
  });

  it("denies key material", () => {
    expectDeny("/home/user/server.pem", "**/*.pem");
    expectDeny("certs/tls.key", "**/*.key");
    expectDeny("a/b/id_rsa.pub", "**/id_rsa*");
    expectDeny(".ssh2/id_ed25519", "**/id_ed25519*");
    expectDeny("id_ecdsa", "**/id_ecdsa*");
  });

  it("denies credential stores", () => {
    expectDeny("/home/u/credentials-prod.json", "**/credentials*.json");
    expectDeny("/home/u/.netrc", "**/.netrc");
    expectDeny("/home/u/.git-credentials", "**/.git-credentials");
    expectDeny("/home/u/auth-profiles.json", "**/auth-profiles.json");
    expectDeny("/home/u/.npmrc", "**/.npmrc");
  });

  it("denies kubernetes secrets surfaces", () => {
    expectDeny("kubeconfig.yaml", "**/*kubeconfig*");
    expectDeny("/etc/rancher/k3s-kubeconfig", "**/*kubeconfig*");
    expectDeny("/run/secrets/kubernetes.io/serviceaccount/token", "**/serviceaccount/**");
    expectDeny("/var/run/secrets/kubernetes.io/token", "/var/run/secrets/**");
  });

  it("denies /proc and .ssh trees", () => {
    expectDeny("/proc/1/environ", "/proc/**");
    expectDeny("/home/u/.ssh/config", "**/.ssh/**");
    expectDeny(".ssh/known_hosts", "**/.ssh/**");
  });
});

describe("compileDenyMatcher — normalization", () => {
  it("is case-insensitive", () => {
    expectDeny("/work/.ENV", "**/.env*");
    expectDeny("/home/u/ID_RSA", "**/id_rsa*");
  });

  it("resolves traversal segments lexically", () => {
    expectDeny("/work/project/../../home/u/.ssh/id_ed25519", "**/.ssh/**");
    expectDeny("foo/../.ssh/id_ed25519", "**/.ssh/**");
  });

  it("converts backslashes to forward slashes", () => {
    expectDeny("secrets\\.env", "**/.env*");
    expectDeny("C:\\Users\\u\\.ssh\\id_rsa", "**/.ssh/**");
  });
});

describe("compileDenyMatcher — clean paths", () => {
  it("passes ordinary files", () => {
    expect(matcher.match("README.md")).toEqual({ kind: "clean" });
    expect(matcher.match("/work/src/env.ts")).toEqual({ kind: "clean" });
    expect(matcher.match("/work/key-value.txt")).toEqual({ kind: "clean" });
    expect(matcher.match("/work/environment.md")).toEqual({ kind: "clean" });
  });
});

describe("compileDenyMatcher — unresolvable input", () => {
  it("flags empty and whitespace strings", () => {
    expect(matcher.match("").kind).toBe("unresolvable");
    expect(matcher.match("   ").kind).toBe("unresolvable");
  });

  it("flags strings containing NUL", () => {
    expect(matcher.match("/work/.e\0nv").kind).toBe("unresolvable");
  });

  it("flags non-string input", () => {
    expect(matcher.match(42).kind).toBe("unresolvable");
    expect(matcher.match(undefined).kind).toBe("unresolvable");
    expect(matcher.match({ path: "/x" }).kind).toBe("unresolvable");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/matcher.test.ts`
Expected: FAIL — cannot resolve `./matcher.js`.

- [ ] **Step 3: Write `src/matcher.ts`**

```typescript
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/matcher.test.ts`
Expected: PASS. If any recommended-pattern assertion fails (picomatch semantics differ from expectation), FIX THE PATTERN EXPECTATION ONLY after confirming with a standalone picomatch check — never weaken normalization or options.

- [ ] **Step 5: Typecheck and lint**

Run: `npm run typecheck && npm run check`
Expected: both exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/matcher.ts src/matcher.test.ts
git commit -m "feat: add picomatch deny matcher with lexical path normalization

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Trusted tool policy (`src/policy.ts`)

**Files:**
- Create: `src/policy.ts`
- Test: `src/policy.test.ts`

**Interfaces:**
- Consumes: `DenyMatcher`, `MatchResult` from `./matcher.js` (Task 3); `PluginTrustedToolPolicyRegistration` type from `openclaw/plugin-sdk/plugin-entry`.
- Produces (used by Task 5): `POLICY_ID = "fs-guard-path-deny"` and `createFsGuardPolicy(matcher: DenyMatcher): PluginTrustedToolPolicyRegistration`.

- [ ] **Step 1: Write the failing test `src/policy.test.ts`**

```typescript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/policy.test.ts`
Expected: FAIL — cannot resolve `./policy.js`.

- [ ] **Step 3: Write `src/policy.ts`**

```typescript
import type { PluginTrustedToolPolicyRegistration } from "openclaw/plugin-sdk/plugin-entry";
import type { DenyMatcher } from "./matcher.js";

export const POLICY_ID = "fs-guard-path-deny";

const FS_TOOL_NAMES: ReadonlySet<string> = new Set(["read", "write", "edit", "apply_patch"]);

const FAIL_CLOSED_DECISION = {
  block: true,
  blockReason: "fs-guard: could not determine target path (fail-closed)",
} as const;

type ToolCallEvent = Parameters<PluginTrustedToolPolicyRegistration["evaluate"]>[0];

export function createFsGuardPolicy(matcher: DenyMatcher): PluginTrustedToolPolicyRegistration {
  return {
    id: POLICY_ID,
    description:
      "Denies filesystem tool calls whose target path matches configured deny glob patterns (fail-closed).",
    evaluate: (event) => {
      try {
        return evaluateEvent(event, matcher);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          block: true,
          blockReason: `fs-guard: policy evaluation failed (fail-closed): ${message}`,
        };
      }
    },
  };
}

function evaluateEvent(event: ToolCallEvent, matcher: DenyMatcher) {
  const guarded = FS_TOOL_NAMES.has(event.toolName) || event.derivedPaths !== undefined;
  if (!guarded) {
    return undefined;
  }

  const candidates: unknown[] = [];
  if (event.params.path !== undefined) {
    candidates.push(event.params.path);
  }
  for (const derived of event.derivedPaths ?? []) {
    candidates.push(derived);
  }

  if (candidates.length === 0) {
    return FAIL_CLOSED_DECISION;
  }

  for (const candidate of candidates) {
    const result = matcher.match(candidate);
    if (result.kind === "deny") {
      return {
        block: true,
        blockReason: `fs-guard: ${result.path} matches deny pattern ${result.pattern}`,
      };
    }
    if (result.kind === "unresolvable") {
      return FAIL_CLOSED_DECISION;
    }
  }
  return undefined;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/policy.test.ts`
Expected: PASS.

- [ ] **Step 5: Typecheck and lint**

Run: `npm run typecheck && npm run check`
Expected: both exit 0. If the `PluginTrustedToolPolicyRegistration` import path fails, check `node_modules/openclaw/package.json` exports for the `plugin-entry` subpath and confirm with `npx tsc --noEmit` — do not fall back to `any`.

- [ ] **Step 6: Commit**

```bash
git add src/policy.ts src/policy.test.ts
git commit -m "feat: add fail-closed trusted tool policy for fs path denial

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Plugin entry (`index.ts`) and pack verification

**Files:**
- Create: `index.ts`
- Test: `index.test.ts`

**Interfaces:**
- Consumes: `resolveFsGuardConfig` (Task 2), `compileDenyMatcher` (Task 3), `createFsGuardPolicy` (Task 4); `definePluginEntry`, `OpenClawPluginApi`, `OpenClawPluginDefinition` from `openclaw/plugin-sdk/plugin-entry`.
- Produces: default-exported plugin entry with id `fs-guard`; named export `register(api)` for tests.

- [ ] **Step 1: Write the failing test `index.test.ts`**

```typescript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run index.test.ts`
Expected: FAIL — cannot resolve `./index.js`.

- [ ] **Step 3: Write `index.ts`**

```typescript
import {
  definePluginEntry,
  type OpenClawPluginApi,
  type OpenClawPluginDefinition,
} from "openclaw/plugin-sdk/plugin-entry";
import { resolveFsGuardConfig } from "./src/config.js";
import { compileDenyMatcher } from "./src/matcher.js";
import { createFsGuardPolicy } from "./src/policy.js";

export function register(api: OpenClawPluginApi): void {
  if (api.registrationMode !== "full") return;
  const config = resolveFsGuardConfig(api.pluginConfig);
  const matcher = compileDenyMatcher(config.denyPatterns);
  api.registerTrustedToolPolicy(createFsGuardPolicy(matcher));
}

const pluginEntry: OpenClawPluginDefinition = definePluginEntry({
  id: "fs-guard",
  name: "FS Guard",
  description:
    "Denies filesystem tool calls targeting paths that match configured deny glob patterns.",
  register,
});

export default pluginEntry;
```

- [ ] **Step 4: Run the full suite**

Run: `npm test`
Expected: all test files pass (config, matcher, policy, index).

- [ ] **Step 5: Build and verify the packed tarball**

Run: `npm run build && npm pack --dry-run 2>&1 | tail -30`
Expected: filename `openclaw-fs-guard-0.1.0.tgz`; contents include `dist/index.js`, `dist/src/config.js`, `dist/src/matcher.js`, `dist/src/policy.js`, `openclaw.plugin.json`, `LICENSE` (README joins in Task 6). No `*.test.*` files in the tarball.

- [ ] **Step 6: Typecheck, lint, commit**

Run: `npm run typecheck && npm run check`
Expected: exit 0.

```bash
git add index.ts index.test.ts
git commit -m "feat: wire plugin entry registering fs-guard-path-deny policy

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: README and CHANGELOG

**Files:**
- Create: `README.md`, `CHANGELOG.md`

**Interfaces:**
- Consumes: recommended pattern list — MUST be byte-identical to `RECOMMENDED_PATTERNS` in `src/matcher.test.ts` (Task 3).
- Produces: `CHANGELOG.md` with a `## [0.1.0]` section — the release workflow (Task 7) extracts notes from it and fails if absent.

- [ ] **Step 1: Write `README.md`**

````markdown
# openclaw-fs-guard

An [OpenClaw](https://openclaw.ai) plugin that deterministically **denies
filesystem tool calls** (`read`, `write`, `edit`, `apply_patch`) whose target
path matches operator-configured glob patterns. It registers a single
host-trusted tool policy (`fs-guard-path-deny`) that runs before ordinary
`before_tool_call` hooks.

It is a *path-shape* guard: it inspects only the path a tool is about to
touch, never file contents. Use it as one layer in a defense-in-depth setup.

## Behavior

- Both reads and writes to matching paths are blocked, with a `blockReason`
  naming the path and pattern.
- **Fail-closed:** if the target path cannot be determined (e.g.
  `apply_patch` without host-derived path hints, a missing or non-string
  `path` param) or policy evaluation fails, the call is blocked.
- Paths are normalized before matching: backslashes become `/`, `..`/`.`
  segments are resolved lexically, and matching is case-insensitive
  (`.ENV` is treated like `.env`). Patterns are matched with
  [picomatch](https://github.com/micromatch/picomatch) using
  `{ dot: true, nocase: true }`.
- Any tool call carrying host-derived path hints (`derivedPaths`) is also
  evaluated, even if it is not one of the four fs tools.
- Tools and paths that are not denied receive **no decision** — the plugin
  never overrides other policies or hooks with an explicit allow.

## Install

Not published to npm. Install from the GitHub release tarball:

```bash
openclaw plugins install https://github.com/vol1003-labs/openclaw-fs-guard/releases/download/v0.1.0/openclaw-fs-guard-0.1.0.tgz
```

## Configuration

`denyPatterns` is **required and must be non-empty**. No patterns are
bundled: the deny list in your gateway config is the complete, auditable
source of truth. The plugin refuses to load (and the gateway fails closed)
if the config is missing or invalid.

Recommended baseline:

```json
{
  "plugins": {
    "entries": {
      "fs-guard": {
        "enabled": true,
        "config": {
          "denyPatterns": [
            "**/.env*",
            "**/*.pem",
            "**/*.key",
            "**/id_rsa*",
            "**/id_ed25519*",
            "**/id_ecdsa*",
            "**/credentials*.json",
            "**/.netrc",
            "**/.git-credentials",
            "**/*kubeconfig*",
            "**/serviceaccount/**",
            "/var/run/secrets/**",
            "/proc/**",
            "**/.ssh/**",
            "**/auth-profiles.json",
            "**/.npmrc"
          ]
        }
      }
    }
  }
}
```

## Limits — read this

- **Path shape only.** File contents are never inspected. A secret in
  `notes.txt` is not detected.
- **Lexical, gateway-side.** Symlinks are not resolved; a symlink at an
  innocent path pointing at `.ssh/id_rsa` is not caught by this layer.
- **`exec` is not guarded.** Shell commands can be rewritten in unbounded
  ways; a lexical guard there would only provide a false sense of security.
  Contain `exec` with an actual sandbox (containers, gVisor, seccomp).
- Host-derived path hints for envelope tools may over-approximate; this can
  cause a false deny, never a false allow.

## Development

```bash
npm install
npm test            # vitest
npm run typecheck
npm run check       # biome
npm run build
```

## License

[MIT](LICENSE)
````

- [ ] **Step 2: Write `CHANGELOG.md`**

```markdown
# Changelog

## [0.1.0] - 2026-07-03

### Added

- Initial release.
- `fs-guard-path-deny` trusted tool policy: denies `read`, `write`, `edit`,
  and `apply_patch` calls whose target path matches configured
  `denyPatterns` globs (picomatch, `dot` + `nocase`), plus any tool call
  carrying host-derived path hints.
- Fail-closed behavior for unresolvable paths, missing path hints, and
  policy evaluation errors.
- Required, non-empty `denyPatterns` config — no bundled defaults; invalid
  config fails plugin load.
```

- [ ] **Step 3: Verify pattern list consistency**

Run: `node -e "
const readme = require('fs').readFileSync('README.md','utf8');
const test = require('fs').readFileSync('src/matcher.test.ts','utf8');
const fromTest = [...test.matchAll(/^  \"([^\"]+)\",$/gm)].map(m => m[1]);
const missing = fromTest.filter(p => !readme.includes(JSON.stringify(p)));
if (fromTest.length === 0 || missing.length) { console.error('MISMATCH', {count: fromTest.length, missing}); process.exit(1); }
console.log('OK', fromTest.length, 'patterns');
"`
Expected: `OK 16 patterns`.

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: add README and CHANGELOG for v0.1.0

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: GitHub Actions (CI + release) and push

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`

**Interfaces:**
- Consumes: npm scripts from Task 1; `CHANGELOG.md` `## [0.1.0]` section from Task 6.
- Produces: CI on push/PR; release workflow that attaches `openclaw-fs-guard-<version>.tgz` to `v*` tag releases (consumed by Task 8).

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  ci:
    name: Lint, Test, Build
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v7

      - name: Setup Node.js
        uses: actions/setup-node@v6
        with:
          node-version: 20
          cache: npm

      - name: Cache node_modules
        id: node-modules
        uses: actions/cache@v6
        with:
          path: node_modules
          key: node-modules-${{ runner.os }}-node20-${{ hashFiles('package-lock.json') }}

      - name: Install dependencies
        if: steps.node-modules.outputs.cache-hit != 'true'
        run: npm ci

      - name: Static checks (Biome)
        run: npm run check

      - name: Typecheck
        run: npm run typecheck

      - name: Unit tests
        run: npm test

      - name: Build
        run: npm run build
```

- [ ] **Step 2: Write `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false

jobs:
  release:
    name: Build, verify, and publish GitHub Release
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v7

      - name: Setup Node.js
        uses: actions/setup-node@v6
        with:
          node-version: 20
          cache: npm

      - name: Cache node_modules
        id: node-modules
        uses: actions/cache@v6
        with:
          path: node_modules
          key: node-modules-${{ runner.os }}-node20-${{ hashFiles('package-lock.json') }}

      - name: Install dependencies
        if: steps.node-modules.outputs.cache-hit != 'true'
        run: npm ci

      - name: Static checks (Biome)
        run: npm run check

      - name: Typecheck
        run: npm run typecheck

      - name: Unit tests
        run: npm test

      - name: Build
        run: npm run build

      - name: Pack tarball
        id: pack
        run: |
          file="$(npm pack --silent)"
          echo "file=$file" >> "$GITHUB_OUTPUT"
          echo "packed asset: $file"

      - name: Resolve version from tag
        id: version
        run: |
          tag="${GITHUB_REF_NAME}"
          version="${tag#v}"
          echo "tag=$tag" >> "$GITHUB_OUTPUT"
          echo "version=$version" >> "$GITHUB_OUTPUT"
          if [[ "$tag" == *-* ]]; then
            echo "prerelease=true" >> "$GITHUB_OUTPUT"
          else
            echo "prerelease=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Verify package.json version matches tag
        run: |
          pkg_version="$(node -p "require('./package.json').version")"
          expected="${{ steps.version.outputs.version }}"
          if [[ "$pkg_version" != "$expected" ]]; then
            echo "::error::package.json version ($pkg_version) does not match tag version ($expected)"
            exit 1
          fi

      - name: Extract release notes from CHANGELOG
        run: |
          version="${{ steps.version.outputs.version }}"
          awk -v ver="$version" '
            $0 ~ "^## \\[" ver "\\]" { flag = 1; next }
            flag && /^## / { exit }
            flag && /^\[[^][]+\]: / { exit }
            flag { print }
          ' CHANGELOG.md > release-notes.md
          if ! grep -q '[^[:space:]]' release-notes.md; then
            echo "::error::No CHANGELOG.md section found for version $version"
            exit 1
          fi
          echo "----- release notes -----"
          cat release-notes.md

      - name: Create GitHub Release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          tag="${{ steps.version.outputs.tag }}"
          args=(--title "$tag" --notes-file release-notes.md --verify-tag)
          if [[ "${{ steps.version.outputs.prerelease }}" == "true" ]]; then
            args+=(--prerelease)
          else
            args+=(--latest)
          fi
          gh release create "$tag" "${{ steps.pack.outputs.file }}" "${args[@]}"
```

- [ ] **Step 3: Commit and push main**

```bash
git add .github
git commit -m "ci: add CI and tag-driven GitHub release workflows

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git remote -v   # confirm origin = github.com/vol1003-labs/openclaw-fs-guard; if absent: git remote add origin git@github.com:vol1003-labs/openclaw-fs-guard.git
git push -u origin main
```

- [ ] **Step 4: Verify CI is green**

Run: `gh run watch --repo vol1003-labs/openclaw-fs-guard $(gh run list --repo vol1003-labs/openclaw-fs-guard --limit 1 --json databaseId -q '.[0].databaseId') --exit-status`
Expected: exit 0 (CI workflow passes). If it fails, read the failing step log with `gh run view --log-failed`, fix, commit, push, re-verify.

---

### Task 8: Release v0.1.0

**Files:** none (tag + release verification only)

**Interfaces:**
- Consumes: release workflow (Task 7).
- Produces: public asset at `https://github.com/vol1003-labs/openclaw-fs-guard/releases/download/v0.1.0/openclaw-fs-guard-0.1.0.tgz` — the URL other systems depend on.

- [ ] **Step 1: Confirm main is green and clean**

Run: `git status --short && git log origin/main..main --oneline`
Expected: empty output for both (no uncommitted changes, nothing unpushed).

- [ ] **Step 2: Tag and push**

```bash
git tag v0.1.0
git push origin v0.1.0
```

- [ ] **Step 3: Watch the release workflow**

Run: `gh run watch --repo vol1003-labs/openclaw-fs-guard $(gh run list --repo vol1003-labs/openclaw-fs-guard --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId') --exit-status`
Expected: exit 0.

- [ ] **Step 4: Verify the contract URL resolves**

Run: `curl -fsSLI -o /dev/null -w "%{http_code} %{url_effective}\n" https://github.com/vol1003-labs/openclaw-fs-guard/releases/download/v0.1.0/openclaw-fs-guard-0.1.0.tgz`
Expected: `200 ...` (after redirects).

- [ ] **Step 5: Smoke-test the tarball contents**

Run: `cd "$(mktemp -d)" && curl -fsSLO https://github.com/vol1003-labs/openclaw-fs-guard/releases/download/v0.1.0/openclaw-fs-guard-0.1.0.tgz && tar -tzf openclaw-fs-guard-0.1.0.tgz | sort`
Expected: listing includes `package/openclaw.plugin.json`, `package/dist/index.js`, `package/dist/src/config.js`, `package/dist/src/matcher.js`, `package/dist/src/policy.js`, `package/README.md`, `package/LICENSE`; no test files.

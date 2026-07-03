# openclaw-fs-guard v0.1.0 — Design

## Purpose

An OpenClaw gateway plugin that deterministically denies filesystem tool
calls whose target path matches operator-configured glob patterns. It is a
path-shape guard (pathform approach): it inspects only the *path* a tool is
about to touch, never file contents. Intended as one layer in a
defense-in-depth setup, not a complete sandbox.

## Public contract (fixed)

- Plugin id: `fs-guard`
- Distribution: GitHub release tarball
  `https://github.com/vol1003-labs/openclaw-fs-guard/releases/download/v0.1.0/openclaw-fs-guard-0.1.0.tgz`
  (no npm publish; installed via `openclaw plugins install`)
- Plugin config: `{ "denyPatterns": string[] }` — **required, non-empty**.
  No patterns are bundled; the operator supplies the full deny list. A
  recommended pattern set is documented in the README as a copyable example.
- Registers exactly one trusted tool policy via
  `api.registerTrustedToolPolicy(...)`, with policy id `fs-guard-path-deny`
  declared in `contracts.trustedToolPolicies` (undeclared ids are rejected by
  the host).
- Guarded tools: the `group:fs` tools `read`, `write`, `edit`,
  `apply_patch`. Additionally, any tool call carrying `event.derivedPaths`
  is evaluated (host produced path hints ⇒ possible fs access).
- Both reads and writes are denied. Denials return a `blockReason`.
- **Fail-closed**: unresolvable path, pattern-match error, or unexpected
  input ⇒ deny. (The host core additionally converts a throwing trusted
  policy into a block; this plugin's own try/catch is a second layer.)

## Decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Glob engine | `picomatch` (runtime dependency) | Battle-tested edge cases; a hand-rolled matcher bug = bypass. Compiled once at registration with `{ dot: true, nocase: true }`. |
| Path normalization | `\` → `/`, then `path.posix.normalize`, case-insensitive matching | Gateway-side lexical check; symlink resolution is impossible here. `foo/../.ssh/x` normalizes to `.ssh/x` and is caught. Relative paths are matched as-is (cwd unknown) and covered by `**/` patterns. |
| Target selection | 4 fs tool names OR presence of `event.derivedPaths` | Future fs-shaped tools that ship derivedPaths get guarded automatically. |
| Default patterns | None bundled | Operator-supplied config is the single source of truth — auditable by reading gateway config alone. README documents a recommended set. |
| Invalid / empty config | Throw at `register` ⇒ plugin load fails | Silent no-guard operation is fail-open; a deploy-time crash is detectable and safe. |
| Content scanning | Out of scope | Inputs are structured path params (`params.path`, `derivedPaths`), never free text, so pathform false positives (e.g. `.key` as object access in code) cannot occur. |

## Architecture

Four small units (TS/ESM, ~250–350 lines total):

### `src/config.ts`
`resolveFsGuardConfig(raw: unknown): FsGuardConfig`
Validates shape only: `denyPatterns` must be a non-empty array of non-empty
strings. Throws `Error` with a specific message otherwise. Tolerant of
unknown extra keys (schema enforcement is the manifest's job). No picomatch
here.

### `src/matcher.ts`
`compileDenyMatcher(patterns: string[]): DenyMatcher`
Precompiles every pattern with picomatch `{ dot: true, nocase: true }`;
compile failure throws (⇒ startup failure).

`DenyMatcher.match(rawPath: string): MatchResult`
Normalizes (`\`→`/`, `path.posix.normalize`) then tests all patterns.
Returns the first matching pattern, `null` for clean paths, or an
`unresolvable` deny signal for invalid input (empty string, NUL, non-string
at runtime) — expressed as a return value, not a throw.

### `src/policy.ts`
`createFsGuardPolicy(matcher: DenyMatcher): PluginTrustedToolPolicyRegistration`

`evaluate(event, ctx)` flow:
1. Guarded? `toolName ∈ {read, write, edit, apply_patch}` or
   `event.derivedPaths !== undefined`. Not guarded ⇒ return `undefined`
   (no decision — never emits an explicit allow, so lower-tier hooks keep
   their say).
2. Collect paths: `params.path` when it is a string, plus every element of
   `derivedPaths`. `apply_patch` relies on `derivedPaths`.
3. Zero paths collected for a guarded call ⇒
   `{ block: true, blockReason: "fs-guard: could not determine target path (fail-closed)" }`.
4. Any path matching ⇒
   `{ block: true, blockReason: "fs-guard: <path> matches deny pattern <pattern>" }`.
5. All paths clean ⇒ `undefined`.
6. The whole body is wrapped in try/catch; any throw ⇒ block
   (doubles the host's own fail-closed conversion).

Note: `derivedPaths` may over-approximate for malformed envelopes. That can
cause a false *deny*, never a false allow — accepted by design.

### `index.ts` (~30 lines)
`definePluginEntry({ id: "fs-guard", ... })`. `register(api)`:
return early unless `registrationMode === "full"`; validate config; compile
matcher; `api.registerTrustedToolPolicy(createFsGuardPolicy(matcher))`.

### `openclaw.plugin.json`
`id: "fs-guard"`, `activation.onStartup: true`,
`contracts: { trustedToolPolicies: ["fs-guard-path-deny"] }`,
`configSchema`: object, `additionalProperties: false`, required
`denyPatterns` — array, `minItems: 1`, items string `minLength: 1`.

### `package.json`
Follows the sandbox-backend conventions: `type: module`, `openclaw`
2026.6.10 as devDependency + `>=2026.6.10` peerDependency,
`dependencies: { picomatch }`, `files: [dist, openclaw.plugin.json,
README.md, LICENSE]`, `prepack: npm run build`, biome + vitest scripts,
`openclaw` install metadata block.

## Recommended pattern set (README example, not bundled)

```
**/.env*  **/*.pem  **/*.key  **/id_rsa*  **/id_ed25519*  **/id_ecdsa*
**/credentials*.json  **/.netrc  **/.git-credentials  **/*kubeconfig*
**/serviceaccount/**  /var/run/secrets/**  /proc/**  **/.ssh/**
**/auth-profiles.json  **/.npmrc
```

## Testing (vitest, pure functions — no fakes needed except a recorded `api`)

- `config.test.ts`: valid config; throw on missing / non-array / empty
  array / non-string element / empty-string element; unknown keys tolerated.
- `matcher.test.ts`: pins the recommended 16-pattern set and covers hits
  (`/work/.env`, `.env.local`, `id_rsa.pub`, `/var/run/secrets/...`,
  `/proc/1/environ`, `.ssh/config`, `kubeconfig.yaml`), case-insensitivity
  (`.ENV`, `ID_RSA`), traversal (`foo/../.ssh/id_ed25519`), backslashes
  (`secrets\.env`), clean paths (`README.md`, `src/env.ts`,
  `key-value.txt`), invalid input (empty string ⇒ deny signal).
- `policy.test.ts`: block/pass for each of the 4 tools; non-fs tool ⇒ no
  decision; unknown tool with `derivedPaths` ⇒ evaluated; `apply_patch`
  without `derivedPaths` ⇒ fail-closed; non-string `params.path` ⇒
  fail-closed; matcher that throws (fake) ⇒ block; `blockReason` wording.
- `index.test.ts`: fake `api` recording `registerTrustedToolPolicy` —
  successful registration; invalid config throws; non-`full`
  registrationMode is a no-op.

## CI / Release

- `ci.yml`: push/PR ⇒ biome check, typecheck, vitest.
- `release.yml`: `v*` tag ⇒ build ⇒ `npm pack` ⇒ attach tgz as GitHub
  release asset (`npm pack` default naming `openclaw-fs-guard-<version>.tgz`
  matches the contract URL).
- License: MIT.

## README requirements

- What it does: trusted-policy path glob deny for fs tools, fail-closed.
- Install via GitHub release tgz + `openclaw plugins install`.
- Config example = recommended pattern set, with an explicit note that
  nothing is bundled and `denyPatterns` is required.
- Documented limits: path shape only (no content inspection); lexical
  gateway-side check (no symlink resolution); does not guard `exec` — use
  as one layer of defense in depth.

## Out of scope

- Content-based secret detection.
- Guarding `exec` or other non-fs tools (beyond derivedPaths opportunism).
- Allow-list semantics, per-agent overrides, pattern removal mechanisms.

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
  `{ dot: true, nocase: true }`. Paths with leading/trailing whitespace
  are treated as unresolvable and blocked (fail-closed). Runs of leading
  slashes are collapsed to a single slash before matching. Relative paths
  that escape upward after normalization (a leading `..` segment) are
  blocked (fail-closed).
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

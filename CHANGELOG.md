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

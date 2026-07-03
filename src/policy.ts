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
  const guarded =
    FS_TOOL_NAMES.has(event.toolName.toLowerCase()) || event.derivedPaths !== undefined;
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

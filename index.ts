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

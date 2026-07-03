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
    // **/id_ed25519* (index 4) is checked before **/.ssh/** (index 13)
    expectDeny("/work/project/../../home/u/.ssh/id_ed25519", "**/id_ed25519*");
    expectDeny("foo/../.ssh/id_ed25519", "**/id_ed25519*");
  });

  it("converts backslashes to forward slashes", () => {
    expectDeny("secrets\\.env", "**/.env*");
    // **/id_rsa* (index 3) is checked before **/.ssh/** (index 13)
    expectDeny("C:\\Users\\u\\.ssh\\id_rsa", "**/id_rsa*");
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

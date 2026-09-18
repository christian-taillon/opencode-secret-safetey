import assert from "node:assert/strict"
import test from "node:test"

import {
  createSecretRegistry,
  isProtectedPath,
  isSensitiveEnvName,
  shouldStripEnv,
} from "../src/policy.js"

test("blocks common protected files", () => {
  assert.equal(isProtectedPath(".env"), true)
  assert.equal(isProtectedPath("config/.env.production"), true)
  assert.equal(isProtectedPath("C:\\project\\.env.local"), true)
  assert.equal(isProtectedPath("certs/client.pem"), true)
  assert.equal(isProtectedPath("certs/client.key"), true)
  assert.equal(isProtectedPath("config/credentials.json"), true)
})

test("allows ordinary files and .env.example", () => {
  assert.equal(isProtectedPath(".env.example"), false)
  assert.equal(isProtectedPath("README.md"), false)
  assert.equal(isProtectedPath("config.json"), false)
})

test("supports exact extra deny file names and path suffixes", () => {
  assert.equal(isProtectedPath("/home/user/.npmrc", [".npmrc"]), true)
  assert.equal(isProtectedPath("/repo/config/private/secrets.json", ["private/secrets.json"]), true)
  assert.equal(isProtectedPath("/repo/public/secrets.json", ["private/secrets.json"]), false)
})

test("identifies credential-like environment variable names", () => {
  assert.equal(isSensitiveEnvName("OPENAI_API_KEY"), true)
  assert.equal(isSensitiveEnvName("GITHUB_TOKEN"), true)
  assert.equal(isSensitiveEnvName("AWS_SECRET_ACCESS_KEY"), true)
  assert.equal(isSensitiveEnvName("DATABASE_URL"), true)
  assert.equal(isSensitiveEnvName("PATH"), false)
  assert.equal(isSensitiveEnvName("HOME"), false)
})

test("allowEnv overrides the default matcher and denyEnv adds exact names", () => {
  assert.equal(shouldStripEnv("GITHUB_TOKEN", { allowEnv: ["GITHUB_TOKEN"] }), false)
  assert.equal(shouldStripEnv("CUSTOM_VALUE", { denyEnv: ["CUSTOM_VALUE"] }), true)
  assert.equal(shouldStripEnv("PATH", {}), false)
})

test("denyEnv wins when a name appears in both lists", () => {
  assert.equal(
    shouldStripEnv("GITHUB_TOKEN", {
      allowEnv: ["GITHUB_TOKEN"],
      denyEnv: ["GITHUB_TOKEN"],
    }),
    true,
  )
})

test("redacts exact registered secret values recursively", () => {
  const registry = createSecretRegistry()
  registry.add("GITHUB_TOKEN", "ghp_0123456789")

  const result = registry.redact({
    output: "token=ghp_0123456789",
    nested: ["safe", { value: "ghp_0123456789" }],
  })

  assert.deepEqual(result, {
    output: "token=[REDACTED:GITHUB_TOKEN]",
    nested: ["safe", { value: "[REDACTED:GITHUB_TOKEN]" }],
  })
})

test("ignores short values to avoid broad accidental redaction", () => {
  const registry = createSecretRegistry()
  registry.add("PASSWORD", "short")
  assert.equal(registry.redact("short output"), "short output")
})

const SECRET_ENV_NAME =
  /(^|_)(API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_?KEY|DATABASE_URL|DATABASE_URI|CONNECTION_STRING)($|_)/i

const DEFAULT_PROTECTED_BASENAMES = new Set(["credentials.json"])
const DEFAULT_PROTECTED_EXTENSIONS = [".pem", ".key"]
const MIN_SECRET_LENGTH = 8

function stringList(value) {
  if (!Array.isArray(value)) return []
  return value.filter((item) => typeof item === "string" && item.length > 0)
}

function normalizePath(value) {
  return value.replaceAll("\\", "/").replace(/\/{2,}/g, "/")
}

function pathBasename(value) {
  const normalized = normalizePath(value)
  return normalized.slice(normalized.lastIndexOf("/") + 1)
}

function matchesConfiguredFile(path, rule) {
  const normalizedPath = normalizePath(path).toLowerCase()
  const normalizedRule = normalizePath(rule).toLowerCase()

  if (normalizedRule.includes("/")) {
    return normalizedPath === normalizedRule || normalizedPath.endsWith(`/${normalizedRule}`)
  }

  return pathBasename(normalizedPath) === normalizedRule
}

export function isProtectedPath(value, extraDenyFiles = []) {
  if (typeof value !== "string" || value.length === 0) return false

  for (const rule of stringList(extraDenyFiles)) {
    if (matchesConfiguredFile(value, rule)) return true
  }

  const basename = pathBasename(value).toLowerCase()

  if (basename === ".env.example") return false
  if (basename === ".env" || basename.startsWith(".env.")) return true
  if (DEFAULT_PROTECTED_BASENAMES.has(basename)) return true

  return DEFAULT_PROTECTED_EXTENSIONS.some((extension) => basename.endsWith(extension))
}

export function isSensitiveEnvName(name) {
  return typeof name === "string" && SECRET_ENV_NAME.test(name)
}

export function shouldStripEnv(name, options = {}) {
  const allow = new Set(stringList(options.allowEnv))
  const deny = new Set(stringList(options.denyEnv))

  if (deny.has(name)) return true
  if (allow.has(name)) return false
  return isSensitiveEnvName(name)
}

export function createSecretRegistry() {
  const secrets = new Map()

  function add(name, value) {
    if (typeof name !== "string" || typeof value !== "string") return
    if (value.length < MIN_SECRET_LENGTH) return
    secrets.set(name, value)
  }

  function replacements() {
    return [...secrets.entries()]
      .map(([name, value]) => ({ name, value }))
      .sort((left, right) => right.value.length - left.value.length)
  }

  function redactString(text) {
    let output = text

    for (const { name, value } of replacements()) {
      if (output.includes(value)) {
        output = output.split(value).join(`[REDACTED:${name}]`)
      }
    }

    return output
  }

  function redact(value, seen = new WeakMap()) {
    if (typeof value === "string") return redactString(value)
    if (value === null || typeof value !== "object") return value

    if (seen.has(value)) return seen.get(value)

    if (Array.isArray(value)) {
      const output = []
      seen.set(value, output)
      for (const item of value) output.push(redact(item, seen))
      return output
    }

    const output = {}
    seen.set(value, output)
    for (const [key, item] of Object.entries(value)) {
      output[key] = redact(item, seen)
    }
    return output
  }

  return { add, redact }
}

export function listOption(value) {
  return stringList(value)
}

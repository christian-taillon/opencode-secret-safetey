import { Plugin } from "@opencode/plugin"
import {
  createSecretRegistry,
  isProtectedPath,
  isSensitiveEnvName,
  listOption,
  shouldStripEnv,
} from "./policy.js"

export default Plugin.define({
  id: "opencode.secret-safetey",

  async setup(ctx) {
    const allowEnv = listOption(ctx.options?.allowEnv)
    const denyEnv = listOption(ctx.options?.denyEnv)
    const denyFiles = listOption(ctx.options?.denyFiles)
    const configuredEnv = new Set([...allowEnv, ...denyEnv])
    const registry = createSecretRegistry()
    const registrations = []

    for (const [name, value] of Object.entries(process.env)) {
      if (isSensitiveEnvName(name) || configuredEnv.has(name)) {
        registry.add(name, value)
      }
    }

    registrations.push(
      await ctx.permission.hook("evaluate", async (event) => {
        if (event.action !== "read") return
        if (!event.resources.some((resource) => isProtectedPath(resource, denyFiles))) return

        event.effect = "deny"
        event.message = "Secret Safety blocks reads of protected credential files."
      }),
    )

    registrations.push(
      await ctx.shell.hook("create.before", async (event) => {
        for (const [name, value] of Object.entries(event.env)) {
          if (isSensitiveEnvName(name) || configuredEnv.has(name)) {
            registry.add(name, value)
          }

          if (shouldStripEnv(name, { allowEnv, denyEnv })) {
            delete event.env[name]
          }
        }
      }),
    )

    registrations.push(
      await ctx.tool.hook("execute.after", async (event) => {
        if (event.status !== "completed") return
        event.result = registry.redact(event.result)
      }),
    )

    return async () => {
      for (const registration of [...registrations].reverse()) {
        try {
          await registration.dispose()
        } catch {
          // OpenCode also owns registration cleanup.
        }
      }
    }
  },
})

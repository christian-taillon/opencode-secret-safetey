# opencode-secret-safetey

Small, auditable secret guardrails for OpenCode v2.

Version 0.1.0 targets OpenCode 2.0.7 and pins `@opencode/plugin` to `2.0.7`.

This plugin intentionally does only three things:

1. Denies OpenCode `read` permission requests for a small set of common credential files.
2. Removes credential-like environment variables before OpenCode starts shell processes.
3. Redacts exact known secret values from completed tool results before they continue through OpenCode.

It does not use an LLM, parse shell commands, scan for secret-looking text, rewrite chat history, or claim to be a sandbox.

## Default protections

Direct reads are denied for:

- `.env`
- `.env.*`, except `.env.example`
- `*.pem`
- `*.key`
- `credentials.json`

Shell environments remove names matching common credential patterns such as:

- `*_API_KEY`
- `*_TOKEN`
- `*_SECRET`
- `*_PASSWORD`
- `*_CREDENTIAL` / `*_CREDENTIALS`
- `*_PRIVATE_KEY`
- `*DATABASE_URL`
- `*DATABASE_URI`
- `*CONNECTION_STRING`

Known secret values of at least 8 characters are remembered in memory and replaced in completed tool results with markers such as `[REDACTED:GITHUB_TOKEN]`.

## Install

Clone or pull the repository and install its one runtime dependency:

```sh
git clone git@github.com:christian-taillon/opencode-secret-safetey.git
cd opencode-secret-safetey
npm install
npm test
```

If you already cloned it:

```sh
git pull
npm install
npm test
```

Reference the local package from your OpenCode v2 `opencode.jsonc`. An absolute path is the least ambiguous:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "/home/you/github/opencode-secret-safetey"
    }
  ]
}
```

Restart the OpenCode service after adding or changing the local package:

```sh
opencode service restart
```

## Options

Options are intentionally small and exact-match based:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "/home/you/github/opencode-secret-safetey",
      "options": {
        "allowEnv": ["MY_REQUIRED_TOKEN"],
        "denyEnv": ["CUSTOM_CREDENTIAL"],
        "denyFiles": [".npmrc", "private/secrets.json"]
      }
    }
  ]
}
```

- `allowEnv`: exact environment variable names that remain available to shell processes even if they match the default credential-name rules. Their values remain eligible for output redaction.
- `denyEnv`: exact additional environment variable names to remove. A deny wins if the same name appears in both lists.
- `denyFiles`: exact additional basenames or path suffixes to deny through the OpenCode `read` permission action.

## Quick manual checks

After loading the plugin, try these from an OpenCode session in a disposable test project:

```text
Read .env
```

Expected: the read permission is denied.

If the OpenCode service process has a disposable variable such as:

```sh
export TEST_API_KEY='secret-safety-test-12345'
```

then ask OpenCode to run:

```sh
printf '%s\n' "$TEST_API_KEY"
```

Expected: the shell receives no `TEST_API_KEY` value.

To exercise exact-value output redaction separately, configure that variable in `allowEnv`. The shell may then use it, but a completed tool result containing the exact value should return `[REDACTED:TEST_API_KEY]`.

Use a disposable fake credential for testing, never a real secret.

## Security boundary

This plugin is designed to reduce accidental secret exposure to models. It is not a sandbox.

OpenCode shell commands still run with the authority of the host user. The plugin deliberately does not parse arbitrary shell commands, so agent-controlled shell code may still access files that the host account can access through mechanisms outside OpenCode's `read` permission.

Secrets that must be inaccessible to agent-controlled code require an OS, container, VM, or separate-account boundary.

The plugin also deliberately avoids heuristic content detection. Output redaction only catches exact values learned from protected environment variables. This keeps behavior predictable and minimizes false positives.

## Design

The security-sensitive implementation is intentionally small:

- `src/policy.js`: pure filename, environment-name, and exact-value redaction logic.
- `src/index.js`: OpenCode v2 hook registration.
- `test/policy.test.js`: deterministic policy tests.

The adapter uses the OpenCode 2.0.7 Promise plugin contracts:

- `ctx.permission.hook("evaluate", ...)`
- `ctx.shell.hook("create.before", ...)`
- `ctx.tool.hook("execute.after", ...)`

## Test

```sh
npm test
npm run check
```

The test suite covers:

- protected and allowed filenames
- Windows-style paths
- custom deny filenames and path suffixes
- default environment-name matching
- allow and deny overrides
- exact-value recursive redaction
- short-value redaction avoidance

GitHub Actions runs the same checks on pushes and pull requests.

## License

MIT

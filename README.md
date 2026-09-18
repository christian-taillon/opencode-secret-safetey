# opencode-secret-safetey

Small, auditable secret guardrails for OpenCode v2.

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

## Install from Git

OpenCode v2 supports Git package plugins directly:

```bash
opencode plugin add git+ssh://git@github.com/christian-taillon/opencode-secret-safetey.git#main
opencode service restart
```

Then verify that OpenCode sees the plugin:

```bash
opencode plugin list
```

## Run from a local clone

Install dependencies and run the tests:

```bash
npm install
npm test
```

Then add the clone to `opencode.jsonc` using an absolute path:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    "/absolute/path/to/opencode-secret-safetey"
  ]
}
```

Restart OpenCode after changing an unwatched local dependency:

```bash
opencode service restart
```

## Options

Options are intentionally small and exact-match based.

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "git+ssh://git@github.com/christian-taillon/opencode-secret-safetey.git#main",
      "options": {
        "allowEnv": ["MY_REQUIRED_TOKEN"],
        "denyEnv": ["CUSTOM_CREDENTIAL"],
        "denyFiles": [".npmrc", "private/secrets.json"]
      }
    }
  ]
}
```

- `allowEnv`: exact environment variable names that should remain available to shell processes even if they match the default credential-name rules. Their values are still eligible for output redaction.
- `denyEnv`: exact additional environment variable names to remove. A deny wins if the same name appears in both lists.
- `denyFiles`: exact additional basenames or path suffixes to deny through the OpenCode `read` permission action.

## Security boundary

This plugin is designed to reduce accidental secret exposure to models. It is not a sandbox.

In particular, OpenCode shell commands run with the authority of the host user. This plugin deliberately does not parse arbitrary shell commands, so a shell command can still access files that the host user can access. Protect secrets that must be inaccessible to agent-controlled code with OS, container, VM, or separate-account boundaries.

The plugin also does not use heuristic content detection. Output redaction only catches exact values that it has learned from protected environment variables. This keeps the implementation predictable and minimizes false positives.

## Design

The security-sensitive implementation is split into two small files:

- `src/policy.js`: pure matching and redaction logic.
- `src/index.js`: OpenCode v2 hook registration.

The plugin uses current OpenCode v2 primitives:

- `ctx.permission.hook("evaluate", ...)`
- `ctx.shell.hook("create.before", ...)`
- `ctx.tool.hook("execute.after", ...)`

## Test behavior

The test suite covers:

- protected and allowed filenames
- Windows-style paths
- default environment-name matching
- allow and deny overrides
- exact-value recursive redaction
- short-value redaction avoidance

Run:

```bash
npm test
```

## License

MIT

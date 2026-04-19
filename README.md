# claude-redact-hook

> Automatically redact API keys, passwords, and secrets from Claude Code prompts before they reach Anthropic's servers.

A [`UserPromptSubmit`](https://docs.anthropic.com/en/docs/claude-code/hooks) hook for [Claude Code](https://claude.ai/code) that scans everything you type or paste and strips sensitive data **on your machine** before it's sent to the cloud.

No dependencies. Pure Python. Works on Windows, macOS, and Linux.

---

## Why

When you paste a config file, `.env`, log output, or connection string into Claude Code, secrets inside it go directly to Anthropic's API. This hook intercepts every prompt submission and redacts secrets in-place before they leave your machine.

**Secrets are replaced with labelled placeholders** so Claude still understands the structure:

```
Before: DATABASE_URL=postgres://admin:MyS3cretP4ss@db.prod.example.com/app
After:  DATABASE_URL=postgres://[USER]:[PASSWORD_REDACTED]@db.prod.example.com/app

Before: GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234
After:  GITHUB_TOKEN=[GITHUB_PAT_REDACTED]
```

---

## Features

- **221 secret types** sourced from [gitleaks](https://github.com/gitleaks/gitleaks) — the industry-standard secret scanner
- **Auto-updates** patterns every 24 hours from gitleaks' live ruleset
- **Zero dependencies** — stdlib Python only, no `pip install` needed
- **Windows-native** — works with `python` (not `python3` or bash shebang)
- **Fast** — cached patterns, typically <10ms overhead per prompt
- **Graceful degradation** — falls back to cached patterns if network is unavailable

---

## What gets redacted

| Category | Services / Types |
|---|---|
| **AI / LLM** | Anthropic (Claude), OpenAI, Cohere, HuggingFace, Perplexity |
| **Cloud** | AWS (AKIA/ASIA/ABIA/ACCA), GCP, Azure AD, DigitalOcean, Fly.io |
| **Source control** | GitHub (PAT, fine-grained, app, OAuth tokens), GitLab (all token types) |
| **Payments** | Stripe, Plaid, Square, Shopify, PayPal, Braintree |
| **Messaging** | Slack (bot/user/app/webhook), Twilio, SendGrid, Mailchimp, Mailgun, Telegram |
| **Infra / DevOps** | Cloudflare, Heroku, Netlify, Databricks, HashiCorp Vault, Terraform Cloud |
| **Observability** | Datadog, New Relic, Grafana, Sentry, Dynatrace |
| **Dev tools** | npm tokens, PyPI tokens, Postman, Snyk, Linear, Doppler, Notion |
| **Databases** | Connection strings with embedded passwords (Postgres, MySQL, MongoDB, Redis, etc.) |
| **Auth** | JWT tokens, Bearer/Basic auth headers, password assignments |
| **Other** | Private keys (PEM), credit card numbers, 150+ more via gitleaks |

---

## Requirements

- Python 3.7+
- [Claude Code](https://claude.ai/code) CLI

---

## Installation

### 1. Download the script

Place `redact_sensitive.py` somewhere permanent. Next to your Claude settings file is convenient:

```
# Windows
C:\Users\<YOU>\.claude\redact_sensitive.py

# macOS / Linux
~/.claude/redact_sensitive.py
```

### 2. Add the hook to `~/.claude/settings.json`

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python C:/Users/<YOU>/.claude/redact_sensitive.py",
            "timeout": 10,
            "statusMessage": "Scanning for sensitive data..."
          }
        ]
      }
    ]
  }
}
```

> **Windows:** Use forward slashes in the path.  
> **macOS / Linux:** Replace `python` with `python3`.

### 3. Reload Claude Code

Open `/hooks` in Claude Code or restart it. The hook is now active.

---

## How it works

1. Patterns are fetched from [`gitleaks/gitleaks`](https://github.com/gitleaks/gitleaks) on first run and cached locally in `.redact_cache.json`
2. The cache refreshes automatically every 24 hours
3. On each prompt submission, the hook reads your prompt via stdin, applies all patterns, and outputs the cleaned prompt as JSON
4. If nothing is redacted, the hook produces no output and the prompt passes through unchanged
5. If the network is unavailable, the last cached patterns are used silently

---

## Running the tests

```bash
python -m unittest tests/test_redact.py -v
```

83 tests covering:
- **EXTRA_PATTERNS** — PEM keys (RSA/EC/DSA/OpenSSH/PGP), connection strings, auth headers, credit cards, env var secrets
- **Gitleaks patterns** — 30+ sampled across AI/cloud/payments/messaging/infra categories, split into standalone (prefix-anchored, specific label verified) and keyword-context (secret gone regardless of label) variants
- **TOML parser** — path-only rules excluded, plaid-api-token cross-rule contamination bug, triple-quoted regexes with embedded quotes
- **Go → Python regex conversion** — POSIX classes, `(?-i:...)` removal, mid-pattern `(?i)` hoisting
- **Cache** — fresh hit (no network call), stale + successful fetch (new patterns returned), stale + network failure (fallback), no cache + no network (empty)
- **Hook I/O contract** — stdin JSON → stdout JSON or no output, surrounding text preserved, double-redaction prevention

---

## Updating patterns manually

Delete `.redact_cache.json` next to the script to force an immediate refresh on the next prompt.

---

## False positives

The hook favours recall over precision — it may occasionally redact values that look like secrets but aren't (e.g. a random 36-char alphanumeric string matching a token pattern). If a redaction breaks your prompt, rephrase or shorten the value to avoid the pattern.

---

## Comparison to alternatives

| Tool | Approach | Windows | Redacts prompts | Auto-updates |
|---|---|---|---|---|
| **claude-redact-hook** (this) | `UserPromptSubmit` hook | ✅ | ✅ | ✅ (gitleaks) |
| [nopeek](https://github.com/spences10/nopeek) | `PreToolUse` + env vars | ⚠️ | ❌ (tool outputs only) | ❌ |
| [redact-mcp](https://github.com/r3352/redact-mcp) | MCP server | ⚠️ | ❌ (tool outputs only) | ❌ |
| Manual `.env` management | — | ✅ | ❌ | ❌ |

---

## Related

- [Claude Code hooks reference](https://docs.anthropic.com/en/docs/claude-code/hooks)
- [gitleaks](https://github.com/gitleaks/gitleaks) — the secret scanning tool this project sources patterns from
- [Feature request: PreApiCall hook](https://github.com/anthropics/claude-code/issues/39882) — upstream issue for native payload redaction

---

## License

MIT

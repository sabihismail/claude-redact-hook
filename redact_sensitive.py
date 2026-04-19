"""
Claude Code UserPromptSubmit hook — redacts secrets before prompts reach the cloud.
Patterns auto-loaded from gitleaks (https://github.com/gitleaks/gitleaks).

GitHub: https://github.com/sabihismail/claude-redact-hook
"""

import sys
import json
import re
import os
import time
import urllib.request

# ── Config ────────────────────────────────────────────────────────────────────
GITLEAKS_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".redact_cache.json")
CACHE_TTL = 86400  # 24 hours
FETCH_TIMEOUT = 3  # seconds

# ── Extra patterns not in gitleaks ────────────────────────────────────────────
# (id, pattern, replacement)
EXTRA_PATTERNS = [
    # Private keys — covers RSA, EC, DSA, PGP, OpenSSH formats
    (
        "private-key-pem",
        r"-----BEGIN (?:(?:EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
        r"-----END (?:(?:EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY(?: BLOCK)?-----",
        "[PRIVATE_KEY_REDACTED]",
    ),
    # Database / broker connection strings with embedded passwords
    (
        "connection-string",
        r"(?i)(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis(?:ql)?|mssql|sqlserver|amqp|rabbitmq|clickhouse)"
        r"://[^:@\s]+:[^@\s\"']+@",
        r"\1://[USER]:[PASSWORD_REDACTED]@",
    ),
    # Authorization headers
    (
        "auth-header",
        r"(?i)(Authorization\s*:\s*(?:Bearer|Token|Basic)\s+)[a-zA-Z0-9+/=_\-\.]{8,}",
        r"\1[REDACTED]",
    ),
    # password/passwd/pwd/secret assignments in configs
    (
        "password-assignment",
        r"(?i)((?:password|passwd|pwd|secret)\s*[=:]\s*)[^\s\n\"'<>{}\[\]]{6,}",
        r"\1[REDACTED]",
    ),
    # Credit card numbers (Visa, MC, Amex, Discover)
    (
        "credit-card",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "[CARD_NUMBER_REDACTED]",
    ),
    # AWS AppSync GraphQL API key
    (
        "aws-appsync-key",
        r"\bda2-[a-z0-9]{26}\b",
        "[AWS_APPSYNC_KEY_REDACTED]",
    ),
    # AWS MWS key
    (
        "aws-mws-key",
        r"\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "[AWS_MWS_KEY_REDACTED]",
    ),
    # Adafruit IO key
    (
        "adafruit-io-key",
        r"\baio_[a-zA-Z0-9]{28}\b",
        "[ADAFRUIT_IO_KEY_REDACTED]",
    ),
    # Apify API key
    (
        "apify-api-key",
        r"\bapify_api_[a-zA-Z0-9\-]{36}\b",
        "[APIFY_API_KEY_REDACTED]",
    ),
    # Cloudinary URL with credentials
    (
        "cloudinary-url",
        r"(?i)cloudinary://[a-z0-9]+:[a-z0-9_\-]+@[a-z0-9]+",
        "[CLOUDINARY_URL_REDACTED]",
    ),
    # Generic high-entropy env var values (KEY=, TOKEN=, SECRET=, API_KEY=)
    # Catches .env file lines not caught by specific patterns above
    (
        "env-var-secret",
        r"(?i)(?:^|\n)((?:[A-Z_]{3,50}(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH))\s*=\s*)[^\s\n\"']{12,}",
        r"\1[REDACTED]",
    ),
]

# ── TOML fetch & parse ────────────────────────────────────────────────────────

def fetch_toml():
    try:
        req = urllib.request.Request(GITLEAKS_URL, headers={"User-Agent": "claude-redact-hook/1.0"})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
            return r.read().decode("utf-8")
    except Exception:
        return None


def parse_toml(toml_text):
    """
    Extract (id, regex_string) pairs from gitleaks TOML.
    Splits by [[rules]] blocks first to avoid cross-rule contamination
    (rules with only a 'path' field and no 'regex' field would otherwise
    cause the parser to steal the next rule's regex).
    """
    results = []
    id_pat = re.compile(r'id\s*=\s*["\']([^"\']+)["\']')
    regex_pat = re.compile(r"regex\s*=\s*(?:'''(.*?)'''|\"([^\"]+)\")", re.DOTALL)

    for block in re.split(r"\[\[rules\]\]", toml_text):
        id_m = id_pat.search(block)
        regex_m = regex_pat.search(block)
        if id_m and regex_m:
            rule_id = id_m.group(1).strip()
            raw = (regex_m.group(1) or regex_m.group(2) or "").strip()
            if rule_id and raw:
                results.append((rule_id, raw))

    return results


# ── Go RE2 → Python re conversion ────────────────────────────────────────────

_POSIX = [
    ("[[:alnum:]]",  "[a-zA-Z0-9]"),
    ("[[:alpha:]]",  "[a-zA-Z]"),
    ("[[:digit:]]",  "[0-9]"),
    ("[[:word:]]",   r"\w"),
    ("[[:space:]]",  r"\s"),
    ("[[:upper:]]",  "[A-Z]"),
    ("[[:lower:]]",  "[a-z]"),
    ("[[:xdigit:]]", "[0-9a-fA-F]"),
    ("[[:print:]]",  r"[\x20-\x7e]"),
    ("[[:ascii:]]",  r"[\x00-\x7f]"),
    ("[[:blank:]]",  r"[ \t]"),
    ("[[:cntrl:]]",  r"[\x00-\x1f\x7f]"),
    ("[[:graph:]]",  r"[\x21-\x7e]"),
    ("[[:punct:]]",  r"[^\w\s]"),
]


def go_to_python(raw):
    for posix, py in _POSIX:
        raw = raw.replace(posix, py)
    # (?-i:...) — inline flag-off unsupported in Python re; degrade to (?:...)
    # Slight false-positive risk accepted (redaction tool, FP << FN)
    raw = re.sub(r"\(\?-i:", "(?:", raw)
    # (?i) mid-pattern — Python 3.11+ rejects global flags not at position 0;
    # move to front so the whole pattern becomes case-insensitive.
    if "(?i)" in raw and not raw.startswith("(?i)"):
        raw = "(?i)" + raw.replace("(?i)", "")
    return raw


def compile_patterns(raw_patterns):
    compiled = []
    for rule_id, raw in raw_patterns:
        try:
            compiled.append((rule_id, re.compile(go_to_python(raw))))
        except re.error:
            pass
    return compiled


# ── Cache ─────────────────────────────────────────────────────────────────────

def load_cache():
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def save_cache(patterns):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump({"ts": time.time(), "patterns": patterns}, f)
    except Exception:
        pass


def get_raw_patterns():
    cache = load_cache()
    if cache and time.time() - cache.get("ts", 0) < CACHE_TTL:
        return cache["patterns"]

    toml = fetch_toml()
    if toml:
        patterns = parse_toml(toml)
        if patterns:
            save_cache(patterns)
            return patterns

    # Fall back to stale cache if network failed
    if cache and cache.get("patterns"):
        return cache["patterns"]

    return []


# ── Redaction ─────────────────────────────────────────────────────────────────

def make_label(rule_id):
    return f"[{rule_id.upper().replace('-', '_')}_REDACTED]"


def redact(text, compiled):
    for rule_id, regex in compiled:
        label = make_label(rule_id)
        if regex.groups >= 1:
            def replacer(m, lbl=label):
                if m.lastindex and m.lastindex >= 1:
                    s, e = m.span(1)
                    fs = m.start(0)
                    full = m.group(0)
                    return full[: s - fs] + lbl + full[e - fs :]
                return lbl
            text = regex.sub(replacer, text)
        else:
            text = regex.sub(label, text)

    for _, pattern, replacement in EXTRA_PATTERNS:
        text = re.sub(pattern, replacement, text)

    return text


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    data = json.load(sys.stdin)
    prompt = data.get("prompt", "")
    compiled = compile_patterns(get_raw_patterns())
    redacted = redact(prompt, compiled)
    if redacted != prompt:
        print(json.dumps({"prompt": redacted}))


if __name__ == "__main__":
    main()

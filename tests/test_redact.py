"""
Tests for redact_sensitive.py

Covers:
  - Core redaction logic (unit)
  - All EXTRA_PATTERNS
  - Key gitleaks-sourced patterns (sampled across categories)
  - Parser correctness (TOML → patterns)
  - Cache behaviour (fresh, stale, network failure)
  - Hook I/O contract (stdin JSON → stdout JSON or no output)
  - Edge cases: empty prompt, no secrets, already-redacted text, multi-secret
"""

import io
import json
import os
import re
import sys
import time
import types
import unittest
from unittest.mock import MagicMock, patch

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import redact_sensitive as rs


# ── Helpers ───────────────────────────────────────────────────────────────────

def run_hook(prompt: str) -> dict | None:
    """Simulate the hook: feed JSON on stdin, return parsed JSON output or None."""
    stdin_data = json.dumps({"prompt": prompt})
    captured = io.StringIO()
    with patch("sys.stdin", io.StringIO(stdin_data)), patch("sys.stdout", captured):
        rs.main()
    output = captured.getvalue().strip()
    return json.loads(output) if output else None


def assert_redacted(test: unittest.TestCase, prompt: str, label_fragment: str):
    """Assert the hook redacts the prompt and the label contains label_fragment."""
    result = run_hook(prompt)
    test.assertIsNotNone(result, f"Hook produced no output for: {prompt!r}")
    test.assertIn(label_fragment, result["prompt"])


def assert_secret_gone(test: unittest.TestCase, prompt: str, secret: str):
    """Assert the hook removes the secret value regardless of which label is used."""
    result = run_hook(prompt)
    test.assertIsNotNone(result, f"Hook produced no output for prompt containing: {secret!r}")
    test.assertNotIn(secret, result["prompt"])


def assert_not_redacted(test: unittest.TestCase, prompt: str):
    """Assert the hook leaves this prompt completely unchanged."""
    result = run_hook(prompt)
    test.assertIsNone(result, f"Hook unexpectedly redacted: {prompt!r}")


# ── EXTRA_PATTERNS ────────────────────────────────────────────────────────────

class TestExtraPatterns(unittest.TestCase):

    def test_pem_private_key(self):
        prompt = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        assert_redacted(self, prompt, "PRIVATE_KEY_REDACTED")

    def test_pem_ec_private_key(self):
        prompt = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----"
        assert_redacted(self, prompt, "PRIVATE_KEY_REDACTED")

    def test_pem_dsa_private_key(self):
        prompt = "-----BEGIN DSA PRIVATE KEY-----\nMIIBugIBAAK...\n-----END DSA PRIVATE KEY-----"
        assert_redacted(self, prompt, "PRIVATE_KEY_REDACTED")

    def test_connection_string_postgres(self):
        prompt = "DATABASE_URL=postgresql://alice:s3cr3tpassword@db.example.com:5432/mydb"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertIn("PASSWORD_REDACTED", result["prompt"])
        self.assertNotIn("s3cr3tpassword", result["prompt"])
        self.assertIn("postgresql://", result["prompt"])

    def test_connection_string_postgres_short(self):
        # postgres:// (without 'ql' suffix) is also a valid scheme
        prompt = "DATABASE_URL=postgres://alice:s3cr3tpassword@db.example.com/mydb"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertNotIn("s3cr3tpassword", result["prompt"])

    def test_connection_string_mongodb(self):
        # Note: passwords containing '@' are a known limitation — the pattern
        # stops at the first '@' in the password field.  Use passwords without '@'.
        prompt = "connect to mongodb+srv://user:MySecretPass123@cluster.mongodb.net/db"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertNotIn("MySecretPass123", result["prompt"])

    def test_connection_string_redis(self):
        prompt = "redis://default:topsecret@redis.example.com:6379"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertNotIn("topsecret", result["prompt"])

    def test_connection_string_mysql(self):
        prompt = "mysql://root:rootpass@localhost:3306/app"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertNotIn("rootpass", result["prompt"])

    def test_auth_header_bearer(self):
        prompt = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature"
        assert_redacted(self, prompt, "REDACTED")

    def test_auth_header_basic(self):
        prompt = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
        assert_redacted(self, prompt, "REDACTED")

    def test_password_assignment_equals(self):
        prompt = "password=MyS3cur3P@ss!"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertNotIn("MyS3cur3P@ss!", result["prompt"])

    def test_password_assignment_colon(self):
        prompt = "passwd: hunter2hunter2"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertNotIn("hunter2hunter2", result["prompt"])

    def test_credit_card_visa(self):
        prompt = "charge card 4111111111111111 for the order"
        assert_redacted(self, prompt, "CARD_NUMBER_REDACTED")

    def test_credit_card_mastercard(self):
        prompt = "card: 5500005555555559"
        assert_redacted(self, prompt, "CARD_NUMBER_REDACTED")

    def test_credit_card_amex(self):
        prompt = "amex: 378282246310005"
        assert_redacted(self, prompt, "CARD_NUMBER_REDACTED")

    def test_openssh_private_key(self):
        prompt = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=\n-----END OPENSSH PRIVATE KEY-----"
        assert_redacted(self, prompt, "PRIVATE_KEY_REDACTED")

    def test_pgp_private_key(self):
        prompt = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG\n-----END PGP PRIVATE KEY BLOCK-----"
        assert_redacted(self, prompt, "PRIVATE_KEY_REDACTED")

    def test_aws_appsync_key(self):
        # Standalone (no keyword context) — specific label fires
        assert_redacted(self, "da2-abcdefghijklmnopqrstuvwxyz", "AWS_APPSYNC_KEY_REDACTED")

    def test_aws_appsync_key_in_config(self):
        assert_secret_gone(self, "key=da2-abcdefghijklmnopqrstuvwxyz", "da2-abcdefghijklmnopqrstuvwxyz")

    def test_adafruit_io_key(self):
        # Standalone — specific label fires (28 chars after aio_)
        assert_redacted(self, "aio_ABCDEFGHIJKLMNOPQRSTUVWXabcd", "ADAFRUIT_IO_KEY_REDACTED")

    def test_adafruit_io_key_in_config(self):
        assert_secret_gone(self, "AIO_KEY=aio_ABCDEFGHIJKLMNOPQRSTUVWXabcd", "aio_ABCDEFGHIJKLMNOPQRSTUVWXabcd")

    def test_cloudinary_url(self):
        secret = "cloudinary://123456789012345:abcdefghijklmnopqrstuvwxyz@mycloud"
        assert_secret_gone(self, secret, "abcdefghijklmnopqrstuvwxyz")

    def test_env_var_secret_line(self):
        prompt = "MY_API_KEY=supersecretvalue1234567890"
        assert_secret_gone(self, prompt, "supersecretvalue1234567890")

    def test_env_var_token_line(self):
        prompt = "DEPLOY_TOKEN=longdeploytoken1234567890abc"
        assert_secret_gone(self, prompt, "longdeploytoken1234567890abc")


# ── Gitleaks-sourced patterns (sampled) ──────────────────────────────────────

class TestGitleaksPatterns(unittest.TestCase):

    # ── Prefix-anchored tokens: specific label guaranteed ────────────────────
    # These have unique prefixes so the specific pattern always fires first.

    def test_github_pat_standalone(self):
        # No keyword context — only the github-pat pattern can match
        token = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        assert_redacted(self, token, "GITHUB_PAT_REDACTED")

    def test_github_app_token_standalone(self):
        token = "ghs_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        assert_redacted(self, token, "GITHUB_APP_TOKEN_REDACTED")

    def test_github_fine_grained_pat(self):
        token = "github_pat_" + "A" * 82
        assert_redacted(self, token, "GITHUB_FINE_GRAINED_PAT_REDACTED")

    def test_gitlab_pat_standalone(self):
        token = "glpat-abcdefghijklmnopqrst"
        assert_redacted(self, token, "GITLAB_PAT_REDACTED")

    def test_aws_access_key_akia(self):
        # Standalone — no keyword to trigger generic pattern
        token = "AKIAIOSFODNN7EXAMPLE"
        assert_redacted(self, token, "AWS_ACCESS_TOKEN_REDACTED")

    def test_aws_access_key_asia(self):
        token = "ASIAIOSFODNN7EXAMPLE"
        assert_redacted(self, token, "AWS_ACCESS_TOKEN_REDACTED")

    def test_anthropic_api_key(self):
        key = "sk-ant-api03-" + "A" * 93 + "AA"
        assert_redacted(self, key, "ANTHROPIC_API_KEY_REDACTED")

    def test_google_gcp_api_key_standalone(self):
        token = "AIzaSy" + "D-9tSrke72I6e5KYGJ5aHPbsIgKsY1234"
        assert_redacted(self, token, "GCP_API_KEY_REDACTED")

    def test_npm_token_standalone(self):
        token = "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        assert_redacted(self, token, "NPM_ACCESS_TOKEN_REDACTED")

    def test_jwt_standalone(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert_redacted(self, token, "JWT_REDACTED")

    def test_huggingface_token_standalone(self):
        token = "hf_" + "abcdefghijklmnopqrstuvwxyzabcdefgh"
        assert_redacted(self, token, "HUGGINGFACE_ACCESS_TOKEN_REDACTED")

    def test_digitalocean_pat_standalone(self):
        token = "dop_v1_" + "a" * 64
        assert_redacted(self, token, "DIGITALOCEAN_PAT_REDACTED")

    def test_databricks_token_standalone(self):
        token = "dapi" + "a" * 32
        assert_redacted(self, token, "DATABRICKS_API_TOKEN_REDACTED")

    def test_doppler_token_standalone(self):
        token = "dp.pt." + "a" * 43
        assert_redacted(self, token, "DOPPLER_API_TOKEN_REDACTED")

    def test_linear_key_standalone(self):
        token = "lin_api_" + "a" * 40
        assert_redacted(self, token, "LINEAR_API_KEY_REDACTED")

    def test_slack_webhook_standalone(self):
        url = "https://hooks.slack.com" + "/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        assert_redacted(self, url, "SLACK_WEBHOOK_URL_REDACTED")

    # ── Keyword-context tokens: verify secret is gone (generic may fire) ─────
    # generic-api-key catches these when a keyword like STRIPE_SECRET= precedes them.
    # The secret is still redacted — we just don't enforce which label.

    def test_stripe_live_key_in_config(self):
        secret = "sk_live_" + "abcdefghijklmnopqrstuvwxyz123456"
        assert_secret_gone(self, f"STRIPE_SECRET={secret}", secret)

    def test_stripe_test_key_in_config(self):
        secret = "sk_test_" + "abcdefghijklmnopqrstuvwxyz123456"
        assert_secret_gone(self, f"STRIPE_SECRET={secret}", secret)

    def test_slack_bot_token_in_config(self):
        secret = "xoxb-" + "12345678901-12345678901-abcdefghijklmnopqrstuvwx"
        assert_secret_gone(self, f"slack_token={secret}", secret)

    def test_github_pat_in_config(self):
        secret = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        assert_secret_gone(self, f"GITHUB_TOKEN={secret}", secret)

    def test_gitlab_pat_in_config(self):
        secret = "glpat-" + "abcdefghijklmnopqrst"
        assert_secret_gone(self, f"GITLAB_TOKEN={secret}", secret)

    def test_sendgrid_key_with_context(self):
        secret = "SG." + "abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz1234567890123"
        assert_secret_gone(self, f"SENDGRID_API_KEY={secret}", secret)

    def test_mailchimp_key_with_context(self):
        secret = "abcdef1234567890" + "abcdef1234567890-us21"
        assert_secret_gone(self, f"MC_KEY={secret}", secret)

    def test_shopify_token(self):
        secret = "shpat_" + "abcdef1234567890abcdef1234567890"
        assert_secret_gone(self, f"SHOPIFY_TOKEN={secret}", secret)

    def test_telegram_bot_token(self):
        # Gitleaks telegram pattern requires "telegr" keyword context
        secret = "1234567890:AAFAbcDefGhIjKlMnOpQrStUvWxYz123456"
        assert_secret_gone(self, f"telegram_bot_token={secret}", secret)

    def test_twitch_token(self):
        secret = "twitch_abcdefghijklmnopqrstuvwxyz123456"
        assert_secret_gone(self, f"twitch client_secret={secret}", secret)

    def test_hashicorp_vault_service_token(self):
        # hvs. service tokens are 90+ base62 chars; gitleaks matches with keyword context
        secret = "hvs." + "A" * 90
        assert_secret_gone(self, f"VAULT_TOKEN={secret}", secret)

    def test_lowercase_env_var_caught_by_generic(self):
        # env-var-secret requires uppercase names, but gitleaks generic-api-key
        # catches lowercase 'api_key' assignments too — verify secret is gone either way
        secret = "secretvalue1234567890abcdef"
        assert_secret_gone(self, f"my_api_key={secret}", secret)


# ── Multiple secrets in one prompt ───────────────────────────────────────────

class TestMultipleSecrets(unittest.TestCase):

    def test_two_secrets_both_redacted(self):
        prompt = (
            "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
            "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        )
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result["prompt"])
        self.assertNotIn("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ", result["prompt"])

    def test_secret_in_multiline_config(self):
        prompt = (
            "[database]\n"
            "host = db.example.com\n"
            "port = 5432\n"
            "password=verysecretpassword123\n"
            "name = myapp\n"
        )
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertNotIn("verysecretpassword123", result["prompt"])
        self.assertIn("host = db.example.com", result["prompt"])

    def test_connection_string_and_api_key_together(self):
        prompt = (
            "DB=postgres://admin:dbpass123@db.example.com/mydb\n"
            "STRIPE_KEY=" + "sk_live_" + "abcdefghijklmnopqrstuvwxyz123456"
        )
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertNotIn("dbpass123", result["prompt"])
        self.assertNotIn("sk_live_abcdef", result["prompt"])


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):

    def test_empty_prompt_no_output(self):
        assert_not_redacted(self, "")

    def test_plain_text_no_output(self):
        assert_not_redacted(self, "please help me write a Python function to sort a list")

    def test_already_redacted_prompt_not_double_redacted(self):
        # A placeholder produced by a previous redaction pass must not be re-redacted
        prompt = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        redacted_once = result["prompt"]
        # Feed the already-redacted prompt back through — should produce no output
        result2 = run_hook(redacted_once)
        self.assertIsNone(result2, f"Double-redaction occurred: {result2}")

    def test_short_values_not_redacted(self):
        # "password=hi" is too short (< 6 chars) to trigger password pattern
        assert_not_redacted(self, "password=hi")

    def test_context_preserved_around_secret(self):
        prompt = "set GITHUB_TOKEN=" + "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234" + " in your env"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertIn("set GITHUB_TOKEN=", result["prompt"])
        self.assertIn("in your env", result["prompt"])

    def test_non_secret_github_url_not_redacted(self):
        assert_not_redacted(self, "see https://github.com/anthropics/claude-code for docs")

    def test_prompt_key_missing_from_input(self):
        # Input has no 'prompt' key — should not crash
        stdin_data = json.dumps({"message": "hello"})
        captured = io.StringIO()
        with patch("sys.stdin", io.StringIO(stdin_data)), patch("sys.stdout", captured):
            rs.main()
        self.assertEqual(captured.getvalue().strip(), "")

    def test_malformed_json_does_not_crash(self):
        # Non-JSON stdin must be silently ignored (fail-open)
        captured = io.StringIO()
        with patch("sys.stdin", io.StringIO("not json {")), patch("sys.stdout", captured):
            rs.main()  # must not raise
        self.assertEqual(captured.getvalue().strip(), "")

    def test_env_var_newline_preserved(self):
        # Redacting an env var must not eat the preceding newline
        prompt = "host=db.example.com\nMY_API_KEY=supersecretvalue1234567890"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertIn("\n", result["prompt"], "newline between lines must be preserved")
        self.assertIn("host=db.example.com", result["prompt"])
        self.assertNotIn("supersecretvalue1234567890", result["prompt"])


# ── TOML parser ───────────────────────────────────────────────────────────────

class TestTomlParser(unittest.TestCase):

    def test_basic_parse(self):
        toml = '''
[[rules]]
id = "my-service-token"
description = "A token"
regex = \'\'\'mytoken-[a-z0-9]{32}\'\'\'
keywords = ["mytoken"]
'''
        results = rs.parse_toml(toml)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], "my-service-token")
        self.assertEqual(results[0][1], "mytoken-[a-z0-9]{32}")

    def test_path_only_rule_excluded(self):
        """Rules with only a 'path' field (no 'regex') should be skipped."""
        toml = '''
[[rules]]
id = "pkcs12-file"
description = "Found a PKCS12 file"
path = \'\'\'(?i)(?:^|\\/).[^\\/]+\\.p(?:12|fx)$\'\'\'

[[rules]]
id = "real-token"
description = "A real token"
regex = \'\'\'real-[a-z0-9]{16}\'\'\'
'''
        results = rs.parse_toml(toml)
        ids = [r[0] for r in results]
        self.assertNotIn("pkcs12-file", ids)
        self.assertIn("real-token", ids)

    def test_path_only_does_not_steal_next_regex(self):
        """The plaid-api-token bug: path-only rule must not consume next rule's regex."""
        toml = '''
[[rules]]
id = "path-only-rule"
path = \'\'\'something\\.p12$\'\'\'

[[rules]]
id = "plaid-api-token"
regex = \'\'\'(?i)plaid.*access-[a-z]+-[a-f0-9-]{36}\'\'\'
'''
        results = rs.parse_toml(toml)
        ids = [r[0] for r in results]
        self.assertNotIn("path-only-rule", ids)
        self.assertIn("plaid-api-token", ids)
        plaid = next(r for r in results if r[0] == "plaid-api-token")
        self.assertIn("plaid", plaid[1])

    def test_triple_quoted_with_single_quotes_inside(self):
        """Regex containing single quotes inside triple quotes parses correctly."""
        toml = """
[[rules]]
id = "tricky"
regex = '''(?i)[\\w.-]{0,50}?[\\s'"]{0,3}([a-z0-9]{32})(?:[\\x60'"\\s;]|$)'''
"""
        results = rs.parse_toml(toml)
        self.assertEqual(len(results), 1)
        self.assertIn("tricky", results[0][0])

    def test_multiple_rules_all_parsed(self):
        toml = "\n".join([
            f"[[rules]]\nid = \"rule-{i}\"\nregex = '''token-{i}-[a-z]{{8}}'''"
            for i in range(10)
        ])
        results = rs.parse_toml(toml)
        self.assertEqual(len(results), 10)

    def test_id_inside_regex_not_confused_with_rule_id(self):
        """A regex that contains 'id = ...' text must not corrupt the parsed rule id."""
        toml = """
[[rules]]
id = "real-rule"
regex = '''(?i)(?:client_id = "[a-z]+"|token-[a-z]{8})'''
"""
        results = rs.parse_toml(toml)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], "real-rule")


# ── Go regex converter ────────────────────────────────────────────────────────

class TestGoToPython(unittest.TestCase):

    def test_posix_alnum(self):
        self.assertEqual(rs.go_to_python("[[:alnum:]]"), "[a-zA-Z0-9]")

    def test_posix_alpha(self):
        self.assertEqual(rs.go_to_python("[[:alpha:]]"), "[a-zA-Z]")

    def test_posix_digit(self):
        self.assertEqual(rs.go_to_python("[[:digit:]]"), "[0-9]")

    def test_posix_xdigit(self):
        self.assertEqual(rs.go_to_python("[[:xdigit:]]"), "[0-9a-fA-F]")

    def test_inline_flag_off_removed(self):
        result = rs.go_to_python(r"(?i)foo(?-i:BAR)baz")
        self.assertNotIn("(?-i:", result)
        self.assertIn("(?:", result)

    def test_mid_pattern_i_flag_moved_to_front(self):
        # Python 3.11+ rejects (?i) anywhere except position 0
        raw = r"foo(?i)bar"
        result = rs.go_to_python(raw)
        self.assertTrue(result.startswith("(?i)"), f"(?i) not at front: {result!r}")
        self.assertNotIn("foo(?i)", result)
        re.compile(result)  # must compile without error

    def test_converted_pattern_compiles(self):
        raw = r"(?i)[\w.-]{0,50}?(?:alnum[[:alnum:]]{4})(?-i:LITERAL)"
        converted = rs.go_to_python(raw)
        try:
            re.compile(converted)
        except re.error as e:
            self.fail(f"Converted pattern failed to compile: {e}")

    # ── POSIX classes in combined character classes ───────────────────────────

    def test_posix_combined_alnum_with_extra_chars(self):
        # [[:alnum:]_-] must become [a-zA-Z0-9_-], not [a-zA-Z0-9]_-]
        converted = rs.go_to_python("[[:alnum:]_-]")
        self.assertEqual(converted, "[a-zA-Z0-9_-]")
        re.compile(converted)

    def test_posix_combined_two_classes(self):
        converted = rs.go_to_python("[[:alpha:][:digit:]]")
        self.assertNotIn("[[", converted)
        re.compile(converted)
        self.assertIsNotNone(re.match(converted, "a"))
        self.assertIsNotNone(re.match(converted, "5"))

    def test_posix_word_inside_combined(self):
        converted = rs.go_to_python(r"[[:word:]\-]+")
        re.compile(converted)  # must not raise

    # ── Flag hoisting doesn't touch named groups ──────────────────────────────

    def test_named_group_not_stripped_by_flag_hoist(self):
        raw = r"(?i)(?P<token>[a-z]{32})"
        converted = rs.go_to_python(raw)
        self.assertIn("(?P<token>", converted)
        m = re.match(converted, "abcdefghijklmnopqrstuvwxyzabcdef")
        self.assertIsNotNone(m)
        self.assertIsNotNone(m.group("token"))

    def test_backreference_not_stripped(self):
        raw = r"(?i)(?P<q>['\"]).*?(?P=q)"
        converted = rs.go_to_python(raw)
        self.assertIn("(?P=q)", converted)
        re.compile(converted)

    # ── Unicode property escapes ──────────────────────────────────────────────

    def test_unicode_prop_L_converted(self):
        result = rs.go_to_python(r"\p{L}+")
        self.assertNotIn(r"\p{", result)
        re.compile(result)

    def test_unicode_prop_Lu_converted(self):
        result = rs.go_to_python(r"\p{Lu}+")
        self.assertEqual(result, "[A-Z]+")

    def test_unicode_prop_Ll_converted(self):
        result = rs.go_to_python(r"\p{Ll}+")
        self.assertEqual(result, "[a-z]+")

    def test_unicode_prop_N_converted(self):
        result = rs.go_to_python(r"\p{N}+")
        self.assertEqual(result, "[0-9]+")

    def test_unicode_prop_Nd_converted(self):
        result = rs.go_to_python(r"\p{Nd}+")
        self.assertEqual(result, "[0-9]+")

    def test_unicode_prop_Xwd_converted(self):
        result = rs.go_to_python(r"\p{Xwd}+")
        self.assertIn(r"\w", result)
        re.compile(result)

    def test_unicode_prop_negated_L_converted(self):
        result = rs.go_to_python(r"\P{L}+")
        self.assertNotIn(r"\P{", result)
        re.compile(result)

    def test_unicode_prop_catchall_unknown_converted(self):
        result = rs.go_to_python(r"\p{Sc}+")
        self.assertNotIn(r"\p{", result)
        re.compile(result)

    def test_unicode_prop_combined_pattern_compiles(self):
        raw = r"(?i)\p{L}[\p{L}\p{N}_]{2,30}"
        converted = rs.go_to_python(raw)
        self.assertNotIn(r"\p{", converted)
        re.compile(converted)

    def test_unicode_prop_inside_char_class_no_double_bracket(self):
        # [\p{L}] must not become [[a-zA-Z]] (double bracket breaks char class)
        converted = rs.go_to_python(r"[\p{L}]")
        self.assertNotIn("[[", converted, f"Double bracket in: {converted!r}")
        re.compile(converted)

    def test_unicode_prop_combined_with_literal_in_class(self):
        # [\p{L}_-] must compile and not close the class prematurely
        converted = rs.go_to_python(r"[\p{L}_\-]+")
        self.assertNotIn("[[", converted)
        compiled = re.compile(converted)
        self.assertIsNotNone(compiled.match("hello_world"))


# ── compile_patterns error visibility ────────────────────────────────────────

class TestCompilePatterns(unittest.TestCase):

    def test_valid_patterns_compiled(self):
        compiled = rs.compile_patterns([("good-rule", r"token-[a-z]{8}")])
        self.assertEqual(len(compiled), 1)
        self.assertEqual(compiled[0][0], "good-rule")

    def test_invalid_pattern_logged_to_stderr(self):
        import io as _io
        stderr_capture = _io.StringIO()
        with patch("sys.stderr", stderr_capture):
            compiled = rs.compile_patterns([("bad-rule", r"[invalid")])
        self.assertEqual(len(compiled), 0)
        err = stderr_capture.getvalue()
        self.assertIn("bad-rule", err)
        self.assertIn("redact-hook", err)

    def test_mixed_valid_invalid_only_valid_compiled(self):
        import io as _io
        stderr_capture = _io.StringIO()
        patterns = [("good", r"token-[a-z]{8}"), ("bad", r"[invalid"), ("also-good", r"\d{4}")]
        with patch("sys.stderr", stderr_capture):
            compiled = rs.compile_patterns(patterns)
        self.assertEqual(len(compiled), 2)
        self.assertEqual(compiled[0][0], "good")
        self.assertEqual(compiled[1][0], "also-good")
        self.assertIn("bad", stderr_capture.getvalue())


# ── Cache behaviour ───────────────────────────────────────────────────────────

class TestCache(unittest.TestCase):

    def setUp(self):
        self._orig_cache = rs.CACHE_FILE
        rs.CACHE_FILE = rs.CACHE_FILE + ".test"

    def tearDown(self):
        if os.path.exists(rs.CACHE_FILE):
            os.remove(rs.CACHE_FILE)
        rs.CACHE_FILE = self._orig_cache

    def _write_cache(self, patterns, age_seconds=0):
        data = {"ts": time.time() - age_seconds, "patterns": patterns}
        with open(rs.CACHE_FILE, "w") as f:
            json.dump(data, f)

    def test_fresh_cache_used_without_network(self):
        self._write_cache([["test-rule", "mytoken-[a-z]{8}"]], age_seconds=100)
        with patch.object(rs, "fetch_toml", side_effect=AssertionError("should not fetch")):
            patterns = rs.get_raw_patterns()
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0][0], "test-rule")

    def test_stale_cache_triggers_fresh_fetch(self):
        # When cache is expired and network succeeds, new patterns are returned
        # and cache is updated — old patterns are not used.
        self._write_cache([["old-rule", "old-[a-z]{8}"]], age_seconds=rs.CACHE_TTL + 1)
        fake_toml = "[[rules]]\nid = \"new-rule\"\nregex = '''new-[a-z]{8}'''"
        with patch.object(rs, "fetch_toml", return_value=fake_toml):
            patterns = rs.get_raw_patterns()
        self.assertEqual(patterns[0][0], "new-rule")

    def test_network_failure_falls_back_to_stale_cache(self):
        self._write_cache([["stale-rule", "stale-[a-z]{8}"]], age_seconds=rs.CACHE_TTL + 1)
        with patch.object(rs, "fetch_toml", return_value=None):
            patterns = rs.get_raw_patterns()
        self.assertEqual(patterns[0][0], "stale-rule")

    def test_no_cache_no_network_returns_empty(self):
        with patch.object(rs, "fetch_toml", return_value=None):
            patterns = rs.get_raw_patterns()
        self.assertEqual(patterns, [])

    def test_successful_fetch_saves_cache(self):
        fake_toml = "[[rules]]\nid = \"fetched-rule\"\nregex = '''fetched-[a-z]{8}'''"
        with patch.object(rs, "fetch_toml", return_value=fake_toml):
            rs.get_raw_patterns()
        self.assertTrue(os.path.exists(rs.CACHE_FILE))
        with open(rs.CACHE_FILE) as f:
            cache = json.load(f)
        self.assertEqual(cache["patterns"][0][0], "fetched-rule")


# ── Hook I/O contract ─────────────────────────────────────────────────────────

class TestHookIO(unittest.TestCase):

    def test_no_secrets_produces_no_output(self):
        result = run_hook("just a normal message with no secrets")
        self.assertIsNone(result)

    def test_secret_produces_valid_json(self):
        result = run_hook("AKIAIOSFODNN7EXAMPLE")
        self.assertIsNotNone(result)
        self.assertIn("prompt", result)
        self.assertIsInstance(result["prompt"], str)

    def test_output_prompt_does_not_contain_original_secret(self):
        secret = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        result = run_hook(f"token={secret}")
        self.assertIsNotNone(result)
        self.assertNotIn(secret, result["prompt"])

    def test_surrounding_text_preserved(self):
        prompt = "please help me understand why AKIAIOSFODNN7EXAMPLE is bad"
        result = run_hook(prompt)
        self.assertIsNotNone(result)
        self.assertIn("please help me understand why", result["prompt"])
        self.assertIn("is bad", result["prompt"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

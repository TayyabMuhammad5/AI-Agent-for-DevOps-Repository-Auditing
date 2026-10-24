
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Tuple
from urllib.parse import urlparse

REDACTION_TOKEN = "<REDACTED_SECRET>"

# Placeholder values and YAML/config keywords that are NOT real secrets
SAFE_PLACEHOLDER_PATTERNS = re.compile(
    r"^(?:"
    r"none|null|true|false|yes|no|on|off|read|write|admin|write-all|read-all|"
    r"changeme|change_me|replace_me|todo|tbd|xxx+|"
    r"your[_-]?[a-z0-9_-]*|example[_-]?[a-z0-9_-]*|sample[_-]?[a-z0-9_-]*|"
    r"dummy[_-]?[a-z0-9_-]*|placeholder[_-]?[a-z0-9_-]*|insert[_-]?[a-z0-9_-]*|"
    r"<[^>]+>|\$\{\{[\s\S]*?\}\}|\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\}|"
    r"\*+|\.+|<redacted_secret>"
    r")$",
    re.IGNORECASE,
)

# Non-secret configuration/YAML keys that contain words like 'token' or 'credentials'
NON_SECRET_KEY_NAMES = {
    "id-token",
    "id_token",
    "persist-credentials",
    "persist_credentials",
    "allow-credentials",
    "allow_credentials",
    "withcredentials",
    "with_credentials",
    "max_tokens",
    "max-tokens",
    "completion_tokens",
    "prompt_tokens",
    "total_tokens",
    "token_type",
    "token-type",
    "token_url",
    "token-url",
    "token_endpoint",
    "csrf_token",
}

# 1. High-confidence token format patterns
TOKEN_PATTERNS = [
    # Private key blocks (PEM / OpenSSH)
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
    ),
    # GitHub tokens (classic PAT, fine-grained PAT, OAuth, App)
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    # OpenAI / Anthropic / Groq / Perplexity keys
    re.compile(r"\bsk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgsk_[A-Za-z0-9_-]{16,}\b"),
    # AWS Access Key ID
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    # Google API Key
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    # Slack tokens & webhooks
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"
    ),
    # Stripe API keys
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\b"),
    # SendGrid / Twilio / NPM / PyPI tokens
    re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}\b"),
    # JSON Web Tokens (JWT)
    re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    ),
]

# 2. URI embedded credentials: scheme://user:password@host
URI_CREDENTIAL_PATTERN = re.compile(
    r"((?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss|amqp|amqps|http|https|ftp)://[^:\s/@\"']+:)"
    r"([^@\s\"']+)"
    r"(@[^\s\"']+)",
    re.IGNORECASE,
)

# 3. Authorization / Bearer headers with literal secrets
BEARER_PATTERN = re.compile(
    r"((?:Authorization|Bearer)\s*[:=]\s*[\"']?(?:Bearer\s+|Basic\s+|Token\s+)?)"
    r"([A-Za-z0-9._~+/=-]{8,})"
    r"([\"']?)",
    re.IGNORECASE,
)

# 4. Key-value or variable assignments in Python, JS, YAML, JSON, .env, INI, TOML
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<prefix>"
    r"\b(?P<key>[A-Za-z0-9_.-]*?(?:"
    r"password|passwd|pwd|secret|api_key|apikey|access_key|secret_key|private_key|"
    r"auth_token|access_token|refresh_token|client_secret|db_pass|db_password|"
    r"jwt_secret|signing_key|encryption_key|webhook_secret|master_key|service_key|"
    r"aws_secret_access_key|github_token|slack_token|stripe_key|openai_api_key|"
    r"groq_api_key|anthropic_api_key|credentials?|token"
    r")[A-Za-z0-9_.-]*)"
    r"\s*(?::=|[:=])\s*"
    r")"
    r"(?P<quote>[\"']?)"
    r"(?P<value>\$\{\{[^\n]*?\}\}|[^\"'\s,;})\]#]+)"
    r"(?P=quote)",
    re.IGNORECASE,
)


def is_safe_placeholder(value: str) -> bool:
    """Return True if a matched value is clearly a placeholder, keyword, or dynamic expression."""
    cleaned = value.strip().strip("\"'")
    if not cleaned or len(cleaned) < 3:
        return True
    if "${{" in cleaned or "}}" in cleaned or cleaned.startswith("${"):
        return True
    if SAFE_PLACEHOLDER_PATTERNS.match(cleaned):
        return True
    lower = cleaned.lower()
    if any(
        lower.startswith(prefix)
        for prefix in (
            "os.environ",
            "os.getenv",
            "env.",
            "process.env",
            "settings.",
            "config.",
            "secrets.",
            "github.",
            "inputs.",
            "vars.",
            "matrix.",
            "steps.",
            "needs.",
            "runner.",
            "vault.",
            "aws_",
            "http://",
            "https://",
        )
    ):
        return True
    if lower in {
        "bearer",
        "basic",
        "string",
        "str",
        "int",
        "bool",
        "boolean",
        "required",
        "optional",
        "default",
        "env",
        "environment",
        "read",
        "write",
        "none",
        "true",
        "false",
    }:
        return True
    return False


def _replace_sensitive_assignment(match: re.Match) -> str:
    key = (match.group("key") or "").strip().lower()
    if key in NON_SECRET_KEY_NAMES:
        return match.group(0)
    prefix = match.group("prefix")
    quote = match.group("quote") or ""
    value = match.group("value")
    if is_safe_placeholder(value):
        return match.group(0)
    return f"{prefix}{quote}{REDACTION_TOKEN}{quote}"


def _replace_uri_credential(match: re.Match) -> str:
    prefix, password, suffix = match.group(1), match.group(2), match.group(3)
    if is_safe_placeholder(password):
        return match.group(0)
    return f"{prefix}{REDACTION_TOKEN}{suffix}"


def _replace_bearer(match: re.Match) -> str:
    prefix, token, suffix = match.group(1), match.group(2), match.group(3)
    if is_safe_placeholder(token):
        return match.group(0)
    return f"{prefix}{REDACTION_TOKEN}{suffix}"


def redact_secrets(text: str | None) -> str:
    """Mask any secret, credential, or token literal in text with <REDACTED_SECRET>."""
    if not text:
        return ""
    redacted = str(text)
    for pattern in TOKEN_PATTERNS:
        redacted = pattern.sub(REDACTION_TOKEN, redacted)
    redacted = URI_CREDENTIAL_PATTERN.sub(_replace_uri_credential, redacted)
    redacted = BEARER_PATTERN.sub(_replace_bearer, redacted)
    redacted = SENSITIVE_ASSIGNMENT_PATTERN.sub(
        _replace_sensitive_assignment, redacted
    )
    return redacted


def validate_repo_target(repo_target: str) -> Tuple[str, bool]:
    """Validate repository URL or local directory path.

    Returns:
        (normalized_target, is_remote_url)
    Raises:
        ValueError: If target is invalid or uses unsafe Git protocols/options.
    """
    if not repo_target or not isinstance(repo_target, str):
        raise ValueError("Repository target must be a non-empty string.")

    cleaned = repo_target.strip()
    if cleaned.startswith("-"):
        raise ValueError(
            "Invalid repository URL: cannot start with '-' (argument injection protection)."
        )

    local_path = Path(cleaned)
    if local_path.exists() and local_path.is_dir():
        return str(local_path.resolve()), False

    parsed = urlparse(cleaned)
    if parsed.scheme not in ("https", "http"):
        raise ValueError(
            f"Unsupported or unsafe repository URL scheme '{parsed.scheme}'. "
            "Provide a public HTTPS GitHub repository URL (e.g., https://github.com/owner/repo)."
        )

    if parsed.hostname not in ("github.com", "www.github.com"):
        raise ValueError(
            f"Unsupported repository host '{parsed.hostname}'. Only public github.com repositories are supported."
        )

    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(path_parts) < 2:
        raise ValueError(
            f"Invalid GitHub repository URL '{cleaned}'. Expected format: https://github.com/<owner>/<repo>"
        )

    owner, repo = path_parts[0], path_parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]

    safe_name_re = re.compile(r"^[A-Za-z0-9_.-]+$")
    if not safe_name_re.match(owner) or not safe_name_re.match(repo):
        raise ValueError(
            f"Invalid GitHub owner or repository name in '{cleaned}'."
        )

    normalized_url = f"https://github.com/{owner}/{repo}"
    return normalized_url, True


def resolve_safe_repo_path(repo_root: Path, relative_path: str) -> Path:
    """Resolve a path inside repo_root and block path traversal or external symlinks."""
    if not relative_path or relative_path.strip() in ("", "."):
        return repo_root.resolve()

    root_resolved = repo_root.resolve()
    candidate = (root_resolved / relative_path.lstrip("/\\")).resolve()

    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise PermissionError(
            f"Path traversal blocked: '{relative_path}' resolves outside repository root."
        ) from exc

    current = root_resolved
    for part in Path(relative_path.lstrip("/\\")).parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise PermissionError(
                f"Parent directory traversal ('..') is not allowed: '{relative_path}'"
            )
        current = current / part
        if current.is_symlink():
            target = current.resolve()
            try:
                target.relative_to(root_resolved)
            except ValueError as exc:
                raise PermissionError(
                    f"External symlink blocked: '{relative_path}' points outside repository root."
                ) from exc

    return candidate
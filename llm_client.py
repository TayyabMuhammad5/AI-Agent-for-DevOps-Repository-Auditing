
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

from security import redact_secrets

# Active 128k-context Groq text/reasoning models (each has its own independent 8,000+ TPM bucket)
GROQ_FALLBACK_MODELS = [
    "openai/gpt-oss-20b",
    "openai/gpt-oss-120b",
    "qwen/qwen3.8-27b",
]


class LLMError(RuntimeError):
    """Raised when the LLM provider call fails unrecoverably."""


class LLMClient:
    """Lightweight, framework-free LLM client for the DevOps Auditing Agent."""

    def __init__(
        self,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 60,
    ) -> None:
        self.timeout = timeout
        self.provider, self.api_key, self.model, self.base_url = (
            self._resolve_credentials(provider, api_key, model, base_url)
        )

    @staticmethod
    def _resolve_credentials(
        provider: Optional[str],
        api_key: Optional[str],
        model: Optional[str],
        base_url: Optional[str],
    ) -> tuple[str, str, str, str]:
        """Detect API key and endpoint from arguments or environment variables."""
        env_provider = (provider or os.getenv("LLM_PROVIDER", "")).strip().lower()
        custom_base = (base_url or os.getenv("LLM_BASE_URL", "")).strip()
        custom_model = (model or os.getenv("LLM_MODEL", "")).strip()

        groq_key = os.getenv("GROQ_API_KEY", "").strip()
        gemini_key = (
            os.getenv("GEMINI_API_KEY", "").strip()
            or os.getenv("GOOGLE_API_KEY", "").strip()
        )
        openai_key = os.getenv("OPENAI_API_KEY", "").strip()
        openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        generic_key = (api_key or os.getenv("LLM_API_KEY", "")).strip()

        # 1. Explicit or auto-detected Groq (Default Free Provider)
        if env_provider == "groq" or (not env_provider and groq_key):
            key = generic_key or groq_key
            if not key:
                raise LLMError(
                    "GROQ_API_KEY is not set. Get a free API key at https://console.groq.com "
                    "and set GROQ_API_KEY in your .env file or environment."
                )
            env_groq_model = os.getenv("GROQ_MODEL", "").strip()
            if env_groq_model in (
                "llama-3.3-70b-versatile",
                "lama-3.3-70b-versatile",
                "llama3-70b-8192",
                "llama-3.1-70b-versatile",
                "llama-3.1-8b-instant",
                "",
            ):
                env_groq_model = "openai/gpt-oss-120b"
            return (
                "groq",
                key,
                custom_model or env_groq_model,
                custom_base or "https://api.groq.com/openai/v1/chat/completions",
            )

        # 2. Google Gemini Free Tier (OpenAI-compatible endpoint)
        if env_provider == "gemini" or (not env_provider and gemini_key):
            key = generic_key or gemini_key
            return (
                "gemini",
                key,
                custom_model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
                custom_base
                or "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            )

        # 3. OpenAI
        if env_provider == "openai" or (not env_provider and openai_key):
            key = generic_key or openai_key
            return (
                "openai",
                key,
                custom_model or os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                custom_base or "https://api.openai.com/v1/chat/completions",
            )

        # 4. OpenRouter
        if env_provider == "openrouter" or (not env_provider and openrouter_key):
            key = generic_key or openrouter_key
            return (
                "openrouter",
                key,
                custom_model or "openai/gpt-oss-120b:free",
                custom_base or "https://openrouter.ai/api/v1/chat/completions",
            )

        # 5. Generic key provided
        if generic_key:
            inferred_provider = "groq" if generic_key.startswith("gsk_") else "openai"
            default_url = (
                "https://api.groq.com/openai/v1/chat/completions"
                if inferred_provider == "groq"
                else "https://api.openai.com/v1/chat/completions"
            )
            default_mod = (
                "openai/gpt-oss-120b"
                if inferred_provider == "groq"
                else "gpt-4o-mini"
            )
            return (
                inferred_provider,
                generic_key,
                custom_model or default_mod,
                custom_base or default_url,
            )

        raise LLMError(
            "No LLM API key found in environment. Please set GROQ_API_KEY (free at https://console.groq.com), "
            "GEMINI_API_KEY, or OPENAI_API_KEY in your environment or .env file."
        )

    @staticmethod
    def _supports_strict_json_mode(model: str) -> bool:
        """Return False for reasoning models that emit <think> tags or reject response_format=json_object."""
        lower = model.lower()
        if any(
            prefix in lower
            for prefix in ("gpt-oss", "qwen", "deepseek", "r1", "qwq", "o1", "o3")
        ):
            return False
        return True

    def complete(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 1536,
        json_mode: bool = True,
    ) -> str:
        """Send chat completion request with model failover and TPM cooldown recovery."""
        models_to_try: List[str] = [self.model]
        if self.provider == "groq":
            for fallback in GROQ_FALLBACK_MODELS:
                if fallback not in models_to_try:
                    models_to_try.append(fallback)

        last_error: Optional[Exception] = None

        # Up to 2 passes across the candidate model pool (with a brief TPM cooldown before pass 2)
        for pass_num in range(2):
            if pass_num == 1:
                # Wait briefly for Groq's rolling 60-second TPM window to replenish
                time.sleep(8.0)

            for candidate_model in models_to_try:
                use_json_mode = json_mode and self._supports_strict_json_mode(
                    candidate_model
                )
                try:
                    return self._send_request(
                        messages=messages,
                        model=candidate_model,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        json_mode=use_json_mode,
                    )
                except LLMError as exc:
                    last_error = exc
                    err_str = str(exc).lower()

                    if use_json_mode and (
                        "response_format" in err_str
                        or "json_validate_failed" in err_str
                        or "json_object" in err_str
                        or "400" in err_str
                    ):
                        try:
                            return self._send_request(
                                messages=messages,
                                model=candidate_model,
                                temperature=temperature,
                                max_tokens=max_tokens,
                                json_mode=False,
                            )
                        except LLMError as inner_exc:
                            last_error = inner_exc
                            err_str = str(inner_exc).lower()

                    # If single-request message payload exceeds model/TPM limit (413 or context_length_exceeded),
                    # raise immediately on pass 0 so agent_core can compact the messages before retrying!
                    if pass_num == 0 and any(
                        token in err_str
                        for token in (
                            "413",
                            "payload too large",
                            "request too large",
                            "reduce the length",
                            "reduce your message size",
                            "maximum context length",
                            "context_length_exceeded",
                        )
                    ):
                        raise

                    # Otherwise try the next model in the pool
                    continue

        raise LLMError(
            f"LLM completion failed ({self.provider}/{self.model}): {redact_secrets(str(last_error))}"
        )

    def _send_request(
        self,
        messages: List[Dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> str:
        """Execute completion via official Groq SDK (with max_retries=0 for instant failover) or HTTPS."""
        if self.provider == "groq" and self.base_url.startswith("https://api.groq.com"):
            try:
                from groq import Groq  # type: ignore

                client = Groq(api_key=self.api_key, timeout=self.timeout, max_retries=0)
                kwargs: Dict[str, Any] = {
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
                if json_mode:
                    kwargs["response_format"] = {"type": "json_object"}
                resp = client.chat.completions.create(**kwargs)
                content = resp.choices[0].message.content
                if not content:
                    raise LLMError("Empty response content from Groq SDK.")
                return content
            except ImportError:
                pass
            except Exception as exc:
                raise LLMError(redact_secrets(str(exc))) from exc

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        body_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "devops-repo-auditor/1.0",
        }

        req = urllib.request.Request(
            self.base_url,
            data=body_bytes,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_resp = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            raise LLMError(
                f"HTTP {exc.code} from {self.provider}: {redact_secrets(err_body or str(exc))}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMError(
                f"Network error contacting {self.provider}: {redact_secrets(str(exc))}"
            ) from exc

        try:
            parsed = json.loads(raw_resp)
            content = parsed["choices"][0]["message"]["content"]
            if not content:
                raise LLMError("LLM returned empty message content.")
            return str(content)
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise LLMError(
                f"Malformed response from {self.provider}: {redact_secrets(raw_resp[:300])}"
            ) from exc
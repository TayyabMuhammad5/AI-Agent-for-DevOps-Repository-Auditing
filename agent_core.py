from __future__ import annotations

import json
import logging
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from llm_client import LLMClient, LLMError
from prompts import SYSTEM_PROMPT
from security import REDACTION_TOKEN, redact_secrets
from tools import RepositorySandbox, RepositoryToolkit

logger = logging.getLogger("devops_audit_agent")

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}

# Strict character budget across all messages (~3,200 tokens) so prompt + completion
# ALWAYS stays under Groq's 8,000 TPM free-tier single-request limit.
MAX_TOTAL_PROMPT_CHARS = 12500

CATEGORY_NORMALIZATION = {
    "repository_hygiene": "repository_hygiene",
    "repo_hygiene": "repository_hygiene",
    "hygiene": "repository_hygiene",
    "repository hygiene": "repository_hygiene",
    "dependency_management": "dependency_management",
    "dependencies": "dependency_management",
    "dependency management": "dependency_management",
    "code_quality": "code_quality",
    "code quality": "code_quality",
    "quality": "code_quality",
    "linting": "code_quality",
    "testing": "testing",
    "tests": "testing",
    "test": "testing",
    "github_actions_ci": "github_actions_ci",
    "github_actions": "github_actions_ci",
    "github actions / ci": "github_actions_ci",
    "github actions": "github_actions_ci",
    "ci": "github_actions_ci",
    "ci_cd": "github_actions_ci",
    "ci/cd": "github_actions_ci",
    "security": "security",
    "sec": "security",
    "configuration": "configuration",
    "config": "configuration",
    "collaboration": "collaboration",
    "collab": "collaboration",
    "build_and_release": "build_and_release",
    "build and release": "build_and_release",
    "build": "build_and_release",
    "release": "build_and_release",
}

RULE_PREFIX_BY_CATEGORY = {
    "repository_hygiene": "HYG",
    "dependency_management": "DEP",
    "code_quality": "QUAL",
    "testing": "TEST",
    "github_actions_ci": "CI",
    "security": "SEC",
    "configuration": "CFG",
    "collaboration": "COLLAB",
    "build_and_release": "BUILD",
}


def extract_json_object(raw_text: str) -> Dict[str, Any]:
    """Robustly parse a JSON object from LLM text output (handling <think> tags and code fences)."""
    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", raw_text, flags=re.IGNORECASE).strip()
    fence_match = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", cleaned)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            parsed = json.loads(cleaned[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError as exc:
            raise ValueError(f"Failed to parse JSON from LLM output: {exc}") from exc

    raise ValueError("LLM response did not contain a valid JSON object.")


def _extract_tool_name_and_args(tc: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Extract tool name and arguments dict across Format A and OpenAI function-call schemas."""
    if "function" in tc and isinstance(tc["function"], dict):
        fn = tc["function"]
        t_name = str(fn.get("name") or "").strip()
        raw_args = fn.get("arguments") or {}
    else:
        t_name = str(tc.get("name") or tc.get("tool") or tc.get("tool_name") or "").strip()
        raw_args = tc.get("arguments") if "arguments" in tc else (tc.get("args") or tc.get("parameters") or {})

    if isinstance(raw_args, str):
        try:
            raw_args = json.loads(raw_args)
        except json.JSONDecodeError:
            raw_args = {}
    if not isinstance(raw_args, dict):
        raw_args = {}
    return t_name, raw_args


def normalize_and_validate_violations(
    raw_violations: List[Any],
    repo_root: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Validate, normalize, deduplicate, and sanitize reported violations to match Section 5 contract."""
    if not isinstance(raw_violations, list):
        return []

    valid_violations: List[Dict[str, Any]] = []
    seen_keys: Set[Tuple[str, Optional[str], Optional[int | str]]] = set()
    category_counters: Dict[str, int] = {}

    for item in raw_violations:
        if not isinstance(item, dict):
            continue

        raw_cat = str(item.get("category") or "code_quality").strip().lower()
        category = CATEGORY_NORMALIZATION.get(raw_cat, raw_cat.replace(" ", "_"))

        raw_sev = str(item.get("severity") or "medium").strip().lower()
        if raw_sev not in ALLOWED_SEVERITIES:
            raw_sev = "medium"

        raw_file = item.get("file")
        file_val: Optional[str] = None
        if raw_file is not None and str(raw_file).strip().lower() not in (
            "",
            "null",
            "none",
            "n/a",
            ".",
        ):
            cleaned_file = str(raw_file).strip().lstrip("/\\")
            file_val = cleaned_file

        raw_line = item.get("line")
        line_val: Optional[int] = None
        if raw_line is not None and not isinstance(raw_line, bool):
            try:
                parsed_line = int(raw_line)
                if parsed_line > 0:
                    line_val = parsed_line
            except (ValueError, TypeError):
                line_val = None

        description = redact_secrets(str(item.get("description") or "").strip())
        evidence = redact_secrets(str(item.get("evidence") or "").strip())
        recommendation = redact_secrets(str(item.get("recommendation") or "").strip())

        if not description or not evidence or not recommendation:
            continue

        # Enforce Section 4 Evidence Rule:
        # 1. Never infer remote branch protection settings from repository files alone
        combined_lower = f"{description} {evidence}".lower()
        if "branch protection" in combined_lower and file_val is None:
            continue

        # 2. Do not flag .env.example / .env.sample / .env.template as exposed secrets
        if (
            file_val
            and Path(file_val).name.lower()
            in (".env.example", ".env.sample", ".env.template", ".env.dist", ".env.local.example")
            and category == "security"
            and REDACTION_TOKEN not in evidence
        ):
            continue

        raw_rule_id = str(item.get("rule_id") or "").strip().upper()
        prefix = RULE_PREFIX_BY_CATEGORY.get(category, "DEVOPS")
        category_counters[prefix] = category_counters.get(prefix, 0) + 1
        if not re.match(r"^[A-Z]+-\d{3}$", raw_rule_id):
            rule_id = f"{prefix}-{category_counters[prefix]:03d}"
        else:
            rule_id = raw_rule_id

        dedup_key = (
            category,
            file_val,
            rule_id if file_val else (line_val or description.lower()[:40]),
        )
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        valid_violations.append(
            {
                "rule_id": rule_id,
                "category": category,
                "severity": raw_sev,
                "file": file_val,
                "line": line_val,
                "description": description,
                "evidence": evidence,
                "recommendation": recommendation,
            }
        )

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    valid_violations.sort(
        key=lambda v: (
            severity_rank.get(v["severity"], 4),
            v["file"] or "~",
            v["line"] or 0,
            v["rule_id"],
        )
    )
    return valid_violations


class DevOpsAuditAgent:
    """Autonomous LLM-driven DevOps Repository Auditing Agent."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        max_steps: int = 8,
        verbose: bool = True,
    ) -> None:
        self.llm = llm_client or LLMClient()
        self.max_steps = max(3, int(max_steps))
        self.verbose = verbose
        self.tool_trace: List[Dict[str, Any]] = []

    def _log(self, msg: str) -> None:
        if self.verbose:
            logger.info(redact_secrets(msg))

    @staticmethod
    def _enforce_prompt_budget(
        messages: List[Dict[str, str]],
        max_total_chars: int = MAX_TOTAL_PROMPT_CHARS,
    ) -> None:
        """Compact older messages in-place so total characters never exceed Groq's 8,000 TPM budget."""
        # 1. Compact any user tool-observation message older than the latest message
        for i in range(2, len(messages) - 1):
            msg = messages[i]
            if msg.get("role") == "user" and len(msg.get("content", "")) > 900:
                msg["content"] = (
                    msg["content"][:800]
                    + "\n... [earlier tool output compacted for token budget]"
                )
            elif msg.get("role") == "assistant" and len(msg.get("content", "")) > 600:
                msg["content"] = msg["content"][:600]

        # 2. If total length across all messages still exceeds max_total_chars, trim latest user message
        total_chars = sum(len(m.get("content", "")) for m in messages)
        if total_chars > max_total_chars and len(messages) >= 3:
            excess = total_chars - max_total_chars
            last_msg = messages[-1]
            last_content = last_msg.get("content", "")
            if len(last_content) > excess + 1200:
                keep_len = max(1200, len(last_content) - excess - 200)
                last_msg["content"] = (
                    last_content[:keep_len]
                    + "\n... [truncated to fit 8,000 TPM budget]\n"
                    "Based on all observations gathered so far, either call at most 2 small tools or output \"action\": \"final_report\"."
                )

    def _complete_with_context_guard(self, messages: List[Dict[str, str]]) -> str:
        """Enforce token budget before calling LLM, and recover automatically from any 413/400 length error."""
        self._enforce_prompt_budget(messages, max_total_chars=MAX_TOTAL_PROMPT_CHARS)
        try:
            return self.llm.complete(messages=messages, temperature=0.0, json_mode=True)
        except LLMError as exc:
            err_lower = str(exc).lower()
            if any(
                t in err_lower
                for t in (
                    "413",
                    "payload too large",
                    "request too large",
                    "reduce the length",
                    "reduce your message size",
                    "context_length",
                    "rate_limit_exceeded",
                )
            ):
                self._log("[Token Budget Guard] Compacting message history and waiting 6s for TPM window...")
                self._enforce_prompt_budget(messages, max_total_chars=8000)
                # Drop middle turns if still needed, keeping system + initial prompt + last 2 messages
                if len(messages) > 4:
                    del messages[2 : len(messages) - 2]
                time.sleep(6.0)
                return self.llm.complete(messages=messages, temperature=0.0, json_mode=True)
            raise

    def audit_repository(self, repo_url: str) -> Dict[str, Any]:
        """Clone the target repository safely and run the Observe-Reason-Tool-Interpret-Report cycle."""
        with RepositorySandbox(repo_url) as repo_path:
            report_repo_name = (
                repo_url.strip()
                if repo_url.strip().startswith("http")
                else str(repo_url).strip()
            )
            return self.audit_local_path(
                repo_path=repo_path,
                repository_identifier=report_repo_name,
            )

    def audit_local_path(
        self,
        repo_path: Path,
        repository_identifier: str,
    ) -> Dict[str, Any]:
        """Run the explicit LLM agent loop against an already-prepared sandbox path."""
        toolkit = RepositoryToolkit(repo_path)
        self.tool_trace = []
        executed_calls: Dict[str, str] = {}

        messages: List[Dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Begin auditing repository: {repository_identifier}\n"
                    "IMPORTANT: You have NOT inspected any files yet. Do NOT guess repository contents from its name.\n"
                    "Your first response MUST use Format A (\"action\": \"call_tools\") to call list_files, git_status, and git_log."
                ),
            },
        ]

        raw_violations: List[Any] = []

        for step in range(1, self.max_steps + 1):
            self._log(f"[Step {step}/{self.max_steps}] Requesting LLM reasoning & tool selection...")
            raw_response = self._complete_with_context_guard(messages)

            try:
                decision = extract_json_object(raw_response)
            except ValueError as exc:
                self._log(f"[Step {step}] Malformed JSON from LLM ({exc}); requesting valid JSON retry.")
                messages.append({"role": "assistant", "content": raw_response[:500]})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your response was not valid JSON. Respond ONLY with a valid JSON object "
                            "matching Format A (action='call_tools') or Format B (action='final_report')."
                        ),
                    }
                )
                continue

            thought = redact_secrets(
                str(decision.get("thought") or decision.get("reasoning") or "")
            )
            action = str(decision.get("action") or "").strip().lower()
            if thought:
                self._log(f"[Step {step}] Reason: {thought}")

            if action == "final_report" or (
                "violations" in decision and "tool_calls" not in decision
            ):
                if len(executed_calls) < 2 and step < self.max_steps:
                    self._log(
                        f"[Step {step}] Agent attempted early final_report with <2 tool calls; prompting deeper inspection."
                    )
                    messages.append({"role": "assistant", "content": json.dumps(decision)})
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "You have not inspected enough repository evidence yet. "
                                "Select and execute inspection tools (such as list_files, git_status, "
                                "inspect_github_actions, run_ruff, run_pytest, search_code, read_file) "
                                "before generating the final report."
                            ),
                        }
                    )
                    continue

                raw_violations = decision.get("violations", [])
                self.tool_trace.append(
                    {
                        "step": step,
                        "thought": thought,
                        "action": "final_report",
                        "reported_violation_count": (
                            len(raw_violations) if isinstance(raw_violations, list) else 0
                        ),
                    }
                )
                break

            tool_calls = decision.get("tool_calls", [])
            if not isinstance(tool_calls, list) or not tool_calls:
                messages.append({"role": "assistant", "content": json.dumps(decision)})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Please specify non-empty 'tool_calls' with 'action': 'call_tools', "
                            "or conclude immediately with 'action': 'final_report' and 'violations': [...]."
                        ),
                    }
                )
                continue

            step_observations: List[Dict[str, Any]] = []
            new_tools_executed = 0

            for tc in tool_calls[:4]:
                if not isinstance(tc, dict):
                    continue
                t_name, t_args = _extract_tool_name_and_args(tc)
                if not t_name:
                    continue

                call_sig = f"{t_name}:{json.dumps(t_args, sort_keys=True)}"
                if call_sig in executed_calls:
                    self._log(f"[Step {step}] Re-using cached result for duplicate tool call: {t_name}({json.dumps(t_args)})")
                    step_observations.append(
                        {
                            "tool": t_name,
                            "arguments": t_args,
                            "cached_observation": executed_calls[call_sig][:800],
                        }
                    )
                    continue

                self._log(f"[Step {step}] Executing tool: {t_name}({json.dumps(t_args)})")
                result = toolkit.execute(t_name, t_args)
                new_tools_executed += 1

                # Cap individual tool result size to 2,000 chars so 4 tools stay well under 8,000 TPM
                serialized_res = json.dumps(result, ensure_ascii=False)
                if len(serialized_res) > 2000:
                    serialized_res = serialized_res[:2000] + "... [truncated]"
                executed_calls[call_sig] = serialized_res

                step_observations.append(
                    {
                        "tool": t_name,
                        "arguments": t_args,
                        "observation": serialized_res if isinstance(serialized_res, str) and serialized_res.endswith("[truncated]") else result,
                    }
                )

            self.tool_trace.append(
                {
                    "step": step,
                    "thought": thought,
                    "action": "call_tools",
                    "tool_calls": [
                        {"name": o["tool"], "arguments": o["arguments"]}
                        for o in step_observations
                    ],
                }
            )

            messages.append({"role": "assistant", "content": json.dumps(decision)[:900]})

            remaining = self.max_steps - step
            if (new_tools_executed == 0 and len(executed_calls) >= 3) or step >= 4:
                follow_up_instruction = (
                    "Interpret the tool observations above. If you already have sufficient evidence "
                    "across the repository, output your final JSON report now using Format B "
                    "(`\"action\": \"final_report\", \"violations\": [...]`). Otherwise call at most 2 remaining tools."
                )
            elif remaining <= 1:
                follow_up_instruction = (
                    "You have reached the final investigation step. Interpret all observations gathered "
                    "so far and output your final JSON report now using Format B (`\"action\": \"final_report\"`)."
                )
            else:
                follow_up_instruction = (
                    "Interpret the tool observations above. Call any remaining needed tools "
                    "(avoiding tools already called), or if you have sufficient evidence across "
                    "the repository, output `\"action\": \"final_report\"` with your `violations` list."
                )

            obs_text = json.dumps(step_observations, ensure_ascii=False)
            if len(obs_text) > 5500:
                obs_text = obs_text[:5500] + "... [truncated for context budget]"

            messages.append(
                {
                    "role": "user",
                    "content": f"Tool execution results:\n{obs_text}\n\n{follow_up_instruction}",
                }
            )
        else:
            self._log("[Final Step] Requesting final report synthesis from all gathered observations...")
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Synthesize all tool observations collected during the investigation and output "
                        "ONLY the final JSON report using Format B (`{\"thought\": \"...\", \"action\": \"final_report\", \"violations\": [...]}`). "
                        "Remember: never reproduce secret values, use null for inapplicable file/line, and only report evidence-backed violations."
                    ),
                }
            )
            raw_final = self._complete_with_context_guard(messages)
            final_obj = extract_json_object(raw_final)
            raw_violations = final_obj.get("violations", [])

        validated_violations = normalize_and_validate_violations(
            raw_violations, repo_root=repo_path
        )

        return {
            "repository": repository_identifier,
            "violations": validated_violations,
        }
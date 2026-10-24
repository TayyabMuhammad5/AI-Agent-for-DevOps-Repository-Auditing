#!/usr/bin/env python3


from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
from typing import List, Optional

from agent_core import DevOpsAuditAgent
from llm_client import LLMClient, LLMError
from security import redact_secrets, validate_repo_target


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description="Autonomous AI Agent for DevOps Repository Auditing (Assignment 2).",
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Public GitHub repository URL (e.g., https://github.com/owner/repo) or local repository path.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output path for the machine-readable JSON audit report (e.g., report.json).",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=10,
        help="Maximum LLM reasoning/tool-execution iterations (default: 10).",
    )
    parser.add_argument(
        "--provider",
        default=None,
        help="Optional LLM provider override ('groq', 'gemini', 'openai', 'openrouter'). Default: auto-detect (Groq preferred).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Optional LLM model override (default: llama-3.3-70b-versatile on Groq).",
    )
    parser.add_argument(
        "--trace-output",
        default=None,
        help="Optional file path to save the step-by-step tool-call trace JSON.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress logs on stderr.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="[%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    # 1. Validate repository target upfront
    try:
        validate_repo_target(args.repo)
    except ValueError as exc:
        sys.stderr.write(f"Fatal Error (Invalid Repository Target): {redact_secrets(str(exc))}\n")
        return 2

    # 2. Initialize LLM client
    try:
        llm_client = LLMClient(provider=args.provider, model=args.model)
    except LLMError as exc:
        sys.stderr.write(f"Fatal Error (LLM Configuration): {redact_secrets(str(exc))}\n")
        return 3

    # 3. Execute agent loop
    agent = DevOpsAuditAgent(
        llm_client=llm_client,
        max_steps=args.max_steps,
        verbose=not args.quiet,
    )

    try:
        report = agent.audit_repository(args.repo)
    except Exception as exc:
        sys.stderr.write(f"Fatal Error (Audit Execution Failed): {redact_secrets(str(exc))}\n")
        return 1

    # 4. Write JSON report atomically
    output_path = Path(args.output).resolve()
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        serialized_report = json.dumps(report, indent=2, ensure_ascii=False)
        # Final safety pass: ensure no secret literal is ever written to disk
        safe_report_str = redact_secrets(serialized_report)
        # Verify valid JSON before writing
        json.loads(safe_report_str)
        output_path.write_text(safe_report_str + "\n", encoding="utf-8")
    except Exception as exc:
        sys.stderr.write(f"Fatal Error (Report Write Failed): {redact_secrets(str(exc))}\n")
        return 4

    # 5. Optionally save tool trace if requested
    if args.trace_output:
        try:
            trace_path = Path(args.trace_output).resolve()
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            trace_payload = {
                "repository": report.get("repository"),
                "provider": llm_client.provider,
                "model": llm_client.model,
                "steps": agent.tool_trace,
            }
            trace_path.write_text(
                redact_secrets(json.dumps(trace_payload, indent=2)) + "\n",
                encoding="utf-8",
            )
        except Exception as exc:
            sys.stderr.write(f"Warning: Could not write trace output: {redact_secrets(str(exc))}\n")

    if not args.quiet:
        v_count = len(report.get("violations", []))
        sys.stderr.write(
            f"[COMPLETE] Audit finished for {report.get('repository')} "
            f"({v_count} violation(s) written to {args.output}).\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

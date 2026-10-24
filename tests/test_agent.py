"""Integration and behavior tests for the DevOpsAuditAgent loop and CLI contract."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_core import (
    ALLOWED_SEVERITIES,
    DevOpsAuditAgent,
    extract_json_object,
    normalize_and_validate_violations,
)
from security import REDACTION_TOKEN


class MockDynamicLLMClient:
    """Mock LLM client that simulates multi-step Observe -> Reason -> Tool -> Report decisions."""

    def __init__(self) -> None:
        self.provider = "mock"
        self.model = "mock-devops-auditor"
        self.call_count = 0

    def complete(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 4096,
        json_mode: bool = True,
    ) -> str:
        self.call_count += 1
        last_user_msg = messages[-1]["content"]

        # Step 1: Discover repository files and git status
        if self.call_count == 1:
            return json.dumps(
                {
                    "thought": "First, I will inspect the repository structure and git status to see what files, workflows, and configs exist.",
                    "action": "call_tools",
                    "tool_calls": [
                        {"name": "list_files", "arguments": {"directory": "."}},
                        {"name": "git_status", "arguments": {}},
                    ],
                }
            )

        # Step 2: Based on discovered files in the observation, select targeted follow-up tools
        if self.call_count == 2:
            self.assert_observation_present = "Tool execution results:" in last_user_msg
            return json.dumps(
                {
                    "thought": "I observed config.py, requirements.txt, and .github/workflows/ci.yml. Now I will inspect the workflow, read config.py and requirements.txt, and run static checks.",
                    "action": "call_tools",
                    "tool_calls": [
                        {"name": "read_file", "arguments": {"path": "config.py"}},
                        {"name": "read_file", "arguments": {"path": "requirements.txt"}},
                        {"name": "inspect_github_actions", "arguments": {}},
                        {"name": "run_ruff", "arguments": {}},
                        {"name": "run_pytest", "arguments": {}},
                    ],
                }
            )

        # Step 3: Interpret tool outputs and emit final report
        return json.dumps(
            {
                "thought": "All evidence has been gathered and verified across tools. Producing final report.",
                "action": "final_report",
                "violations": [
                    {
                        "rule_id": "SEC-001",
                        "category": "security",
                        "severity": "critical",
                        "file": "config.py",
                        "line": 2,
                        "description": "Hardcoded API credential in config.py",
                        "evidence": 'API_KEY = "sk-live-secret9999999999999999"',
                        "recommendation": "Use environment variables via os.getenv('API_KEY') or a secrets manager.",
                    },
                    {
                        "rule_id": "HYG-001",
                        "category": "repository_hygiene",
                        "severity": "medium",
                        "file": None,
                        "line": None,
                        "description": "Missing README documentation",
                        "evidence": "list_files() confirmed no README file exists in the repository root.",
                        "recommendation": "Add a README.md documenting setup, architecture, and execution instructions.",
                    },
                    # Duplicate violation that should be deduplicated automatically
                    {
                        "rule_id": "SEC-001",
                        "category": "security",
                        "severity": "critical",
                        "file": "config.py",
                        "line": 2,
                        "description": "Hardcoded API credential in config.py",
                        "evidence": "Duplicate entry",
                        "recommendation": "Use environment variables.",
                    },
                    # Prohibited inference about remote branch protection that must be filtered out
                    {
                        "rule_id": "COLLAB-099",
                        "category": "collaboration",
                        "severity": "low",
                        "file": None,
                        "line": None,
                        "description": "Remote branch protection not enabled on main branch",
                        "evidence": "Inferred from repository files alone",
                        "recommendation": "Enable branch protection in GitHub settings.",
                    },
                ],
            }
        )


class TestAgentLoopAndSchema(unittest.TestCase):
    """Test the explicit agent loop, tool selection trace, and JSON output contract."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="test_agent_loop_")
        self.repo_root = Path(self.temp_dir)
        subprocess.run(["git", "init"], cwd=str(self.repo_root), check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=str(self.repo_root),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Tester"],
            cwd=str(self.repo_root),
            check=True,
            capture_output=True,
        )
        (self.repo_root / "config.py").write_text(
            'import os\nAPI_KEY = "sk-live-secret9999999999999999"\n',
            encoding="utf-8",
        )
        (self.repo_root / "requirements.txt").write_text("requests\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.repo_root), check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=str(self.repo_root),
            check=True,
            capture_output=True,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_agent_executes_multi_step_tool_loop_and_sanitizes_report(self) -> None:
        mock_llm = MockDynamicLLMClient()
        agent = DevOpsAuditAgent(llm_client=mock_llm, max_steps=6, verbose=False)  # type: ignore[arg-type]

        report = agent.audit_local_path(
            repo_path=self.repo_root,
            repository_identifier="https://github.com/example/demo-project",
        )

        # Verify multi-turn tool selection occurred
        self.assertEqual(mock_llm.call_count, 3)
        self.assertEqual(len(agent.tool_trace), 3)
        self.assertEqual(agent.tool_trace[0]["action"], "call_tools")
        self.assertEqual(agent.tool_trace[1]["action"], "call_tools")
        self.assertEqual(agent.tool_trace[2]["action"], "final_report")

        # Verify output JSON schema contract (Section 5)
        self.assertEqual(set(report.keys()), {"repository", "violations"})
        self.assertEqual(report["repository"], "https://github.com/example/demo-project")

        violations = report["violations"]
        # Duplicate SEC-001 and prohibited remote branch protection claim must be filtered out
        self.assertEqual(len(violations), 2)

        required_fields = {
            "rule_id",
            "category",
            "severity",
            "file",
            "line",
            "description",
            "evidence",
            "recommendation",
        }
        for v in violations:
            self.assertEqual(set(v.keys()), required_fields)
            self.assertIn(v["severity"], ALLOWED_SEVERITIES)
            # Secret literal must NEVER appear in final report
            self.assertNotIn("sk-live-secret9999999999999999", json.dumps(v))

        # Verify SEC-001 has redacted token in evidence and integer line
        sec_v = next(v for v in violations if v["rule_id"] == "SEC-001")
        self.assertEqual(sec_v["file"], "config.py")
        self.assertEqual(sec_v["line"], 2)
        self.assertIn(REDACTION_TOKEN, sec_v["evidence"])

        # Verify HYG-001 uses None (JSON null) for inapplicable file/line
        hyg_v = next(v for v in violations if v["rule_id"] == "HYG-001")
        self.assertIsNone(hyg_v["file"])
        self.assertIsNone(hyg_v["line"])

    def test_extract_json_object_handles_markdown_fences(self) -> None:
        fenced = 'Here is my decision:\n```json\n{"thought": "ok", "action": "final_report", "violations": []}\n```'
        parsed = extract_json_object(fenced)
        self.assertEqual(parsed["action"], "final_report")

    def test_false_positive_filtering_on_env_example(self) -> None:
        raw = [
            {
                "rule_id": "SEC-002",
                "category": "security",
                "severity": "high",
                "file": ".env.example",
                "line": 1,
                "description": "API key placeholder in .env.example",
                "evidence": "GROQ_API_KEY=your_key_here",
                "recommendation": "Remove key",
            }
        ]
        cleaned = normalize_and_validate_violations(raw, repo_root=self.repo_root)
        self.assertEqual(len(cleaned), 0)


if __name__ == "__main__":
    unittest.main()

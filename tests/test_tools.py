"""Unit tests for inspection tools (tools.py) and safety guards (security.py)."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security import REDACTION_TOKEN, redact_secrets, resolve_safe_repo_path, validate_repo_target
from tools import (
    RepositoryToolkit,
    git_log,
    git_status,
    inspect_github_actions,
    list_files,
    read_file,
    run_pytest,
    run_ruff,
    search_code,
    set_active_repo,
)


class TestSecurityAndTools(unittest.TestCase):
    """Verify tool implementations, secret redaction, and sandbox safety."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="test_audit_repo_")
        self.repo_root = Path(self.temp_dir)
        self._init_sample_git_repo(self.repo_root)
        set_active_repo(self.repo_root)

    def tearDown(self) -> None:
        set_active_repo(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _init_sample_git_repo(self, root: Path) -> None:
        subprocess.run(["git", "init"], cwd=str(root), check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "dev@example.com"],
            cwd=str(root),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test Developer"],
            cwd=str(root),
            check=True,
            capture_output=True,
        )

        # Create config.py with a synthetic test secret and machine-specific path
        (root / "config.py").write_text(
            'import os\n'
            'import subprocess\n'
            'API_KEY = "sk-live-9876543210abcdef12345678"\n'
            'DATA_DIR = "/Users/johndoe/local_project/data"\n'
            'def run_cmd(cmd, items=[]):\n'
            '    try:\n'
            '        subprocess.run(cmd, shell=True)\n'
            '    except:\n'
            '        pass\n',
            encoding="utf-8",
        )

        # Create unpinned requirements.txt
        (root / "requirements.txt").write_text("flask\nrequests\n", encoding="utf-8")

        # Create tracked .env and .DS_Store (hygiene & security defects)
        (root / ".env").write_text("DB_PASSWORD=supersecretpassword123\n", encoding="utf-8")
        (root / ".DS_Store").write_text("junk", encoding="utf-8")

        # Create safe .env.example
        (root / ".env.example").write_text("DB_PASSWORD=your_password_here\n", encoding="utf-8")

        # Create GitHub Actions workflow with defects
        wf_dir = root / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        (wf_dir / "ci.yml").write_text(
            "name: CI\n"
            "on: [push]\n"
            "permissions: write-all\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@main\n"
            "      - name: Run tests\n"
            "        continue-on-error: true\n"
            "        run: pytest || true\n",
            encoding="utf-8",
        )

        # Create test file with empty test and deterministic failing test
        tests_dir = root / "tests"
        tests_dir.mkdir(exist_ok=True)
        (tests_dir / "test_app.py").write_text(
            "def test_empty():\n"
            "    pass\n\n"
            "def test_broken():\n"
            "    assert 1 == 2\n",
            encoding="utf-8",
        )

        subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "Initial commit"],
            cwd=str(root),
            check=True,
            capture_output=True,
        )

    def test_secret_redaction_never_exposes_values(self) -> None:
        raw_secret = "sk-live-9876543210abcdef12345678"
        text = f'API_KEY = "{raw_secret}"'
        redacted = redact_secrets(text)
        self.assertNotIn(raw_secret, redacted)
        self.assertIn(REDACTION_TOKEN, redacted)

        # Verify .env.example safe placeholders are NOT falsely flagged
        safe_line = "API_KEY=your_api_key_here"
        self.assertEqual(redact_secrets(safe_line), safe_line)

    def test_validate_repo_target(self) -> None:
        url, is_remote = validate_repo_target("https://github.com/example/demo-project.git")
        self.assertEqual(url, "https://github.com/example/demo-project")
        self.assertTrue(is_remote)

        with self.assertRaises(ValueError):
            validate_repo_target("--upload-pack=evil")

        with self.assertRaises(ValueError):
            validate_repo_target("file:///etc/passwd")

    def test_path_traversal_blocked(self) -> None:
        with self.assertRaises(PermissionError):
            resolve_safe_repo_path(self.repo_root, "../../etc/passwd")

        res = read_file("../../etc/passwd")
        self.assertIn("error", res)
        self.assertIn("traversal", res["error"].lower())

    def test_list_files_discovers_structure_and_suspicious_files(self) -> None:
        result = list_files()
        self.assertIn("config.py", result["files"])
        self.assertFalse(result["has_readme"])
        self.assertFalse(result["has_gitignore"])
        suspicious_names = [item["file"] for item in result["suspicious_tracked_files"]]
        self.assertIn(".env", suspicious_names)
        self.assertIn(".DS_Store", suspicious_names)
        self.assertNotIn(".env.example", suspicious_names)

    def test_read_file_redacts_secrets_and_detects_machine_paths(self) -> None:
        result = read_file("config.py")
        self.assertNotIn("sk-live-9876543210abcdef12345678", result["content"])
        self.assertIn(REDACTION_TOKEN, result["content"])
        self.assertIn(3, result["redacted_secret_lines"])
        self.assertEqual(len(result["machine_specific_path_lines"]), 1)
        self.assertEqual(result["machine_specific_path_lines"][0]["line"], 4)

    def test_search_code_finds_patterns_with_redaction(self) -> None:
        result = search_code("API_KEY|DB_PASSWORD")
        self.assertGreaterEqual(result["total_matches_returned"], 2)
        for m in result["matches"]:
            self.assertNotIn("sk-live-9876543210abcdef12345678", m["snippet"])
            self.assertNotIn("supersecretpassword123", m["snippet"])

    def test_git_log_and_git_status(self) -> None:
        log_res = git_log()
        self.assertEqual(log_res["commit_count_returned"], 1)
        self.assertEqual(log_res["commits"][0]["message"], "Initial commit")

        status_res = git_status()
        self.assertTrue(status_res["working_tree_clean"])
        tracked_bad = [f["file"] for f in status_res["tracked_suspicious_files"]]
        self.assertIn(".env", tracked_bad)

    def test_inspect_github_actions_detects_ci_flaws(self) -> None:
        res = inspect_github_actions()
        self.assertEqual(res["workflows_found"], 1)
        wf = res["workflows"][0]
        finding_types = {f["type"] for f in wf["findings"]}
        self.assertIn("broad_workflow_permissions", finding_types)
        self.assertIn("unpinned_github_action", finding_types)
        self.assertIn("continue_on_error_enabled", finding_types)
        self.assertIn("suppressed_step_failure", finding_types)
        self.assertIn("missing_pull_request_trigger", finding_types)

    def test_run_ruff_ast_static_analysis(self) -> None:
        res = run_ruff()
        codes = {issue["code"] for issue in res["ast_static_issues"]}
        self.assertIn("E722", codes)  # bare except
        self.assertIn("B006", codes)  # mutable default arg
        self.assertIn("S602", codes)  # subprocess shell=True

    def test_run_pytest_static_ast_analysis(self) -> None:
        res = run_pytest()
        self.assertEqual(res["total_test_files"], 1)
        self.assertEqual(res["python_test_functions_count"], 2)
        issues = {f["issue"] for f in res["findings"]}
        self.assertIn("empty_test_function", issues)
        self.assertIn("deterministic_failing_assertion", issues)

    def test_toolkit_dispatcher(self) -> None:
        toolkit = RepositoryToolkit(self.repo_root)
        res = toolkit.execute("list_files", {"directory": "."})
        self.assertIn("files", res)
        unknown = toolkit.execute("nonexistent_tool", {})
        self.assertIn("error", unknown)


if __name__ == "__main__":
    unittest.main()

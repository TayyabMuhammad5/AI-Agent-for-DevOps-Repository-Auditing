
from __future__ import annotations

import ast
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

from security import (
    REDACTION_TOKEN,
    is_safe_placeholder,
    redact_secrets,
    resolve_safe_repo_path,
    validate_repo_target,
)

# Global active repository path for direct function invocations (e.g., in unit tests)
_ACTIVE_REPO_PATH: Optional[Path] = None

# File patterns indicating tracked temporary, generated, cache, or secret artifacts
SUSPICIOUS_TRACKED_PATTERNS = [
    ("*.pyc", "Compiled Python bytecode file committed to repository"),
    ("*.pyo", "Compiled Python bytecode file committed to repository"),
    ("__pycache__/*", "Python __pycache__ directory tracked in version control"),
    (".pytest_cache/*", "Pytest cache directory tracked in version control"),
    (".ruff_cache/*", "Ruff cache directory tracked in version control"),
    (".mypy_cache/*", "Mypy cache directory tracked in version control"),
    (".DS_Store", "macOS Finder metadata file (.DS_Store) committed to repository"),
    ("Thumbs.db", "Windows thumbnail cache file committed to repository"),
    ("*.swp", "Vim swap file committed to repository"),
    ("*.swo", "Vim swap file committed to repository"),
    ("*~", "Editor backup file committed to repository"),
    (".env", "Environment file (.env) tracked in version control"),
    (".env.local", "Local environment file (.env.local) tracked in version control"),
    (".env.production", "Production environment file tracked in version control"),
    (".env.development", "Development environment file tracked in version control"),
    ("*.pem", "Private key / PEM certificate file tracked in version control"),
    ("*.key", "Private key file tracked in version control"),
    ("id_rsa", "SSH private key tracked in version control"),
    ("id_ed25519", "SSH private key tracked in version control"),
    ("*.log", "Log file committed to repository"),
    ("*.sqlite3", "Local SQLite database file committed to repository"),
    ("*.db", "Local database file committed to repository"),
    ("node_modules/*", "Node.js node_modules dependency directory tracked in git"),
    ("venv/*", "Python virtual environment (venv/) tracked in git"),
    (".venv/*", "Python virtual environment (.venv/) tracked in git"),
    ("env/*", "Virtual environment directory (env/) tracked in git"),
    ("dist/*", "Build distribution artifact directory (dist/) tracked in git"),
    ("build/*", "Build output directory (build/) tracked in git"),
    ("*.egg-info/*", "Python packaging metadata (.egg-info) tracked in git"),
    (".coverage", "Coverage data file (.coverage) tracked in git"),
    ("htmlcov/*", "HTML coverage report directory tracked in git"),
    (".idea/*", "JetBrains IDE workspace directory (.idea/) tracked in git"),
    (".vscode/settings.json", "Local VSCode machine settings tracked in git"),
]

# Machine-specific absolute path regex (for configuration / portability detection)
MACHINE_PATH_REGEX = re.compile(
    r"""(?:['"]|=|\s)(/Users/[A-Za-z0-9_.-]+/[^\s'":;]+|/home/[A-Za-z0-9_.-]+/[^\s'":;]+|[A-Za-z]:\\[\\A-Za-z0-9_.\s-]+)"""
)


def set_active_repo(repo_path: str | Path | None) -> None:
    """Set the default repository root for module-level tool calls."""
    global _ACTIVE_REPO_PATH
    _ACTIVE_REPO_PATH = Path(repo_path).resolve() if repo_path else None


def _get_repo_root(repo_path: str | Path | None = None) -> Path:
    """Resolve the active repository root directory."""
    if repo_path is not None:
        return Path(repo_path).resolve()
    if _ACTIVE_REPO_PATH is not None:
        return _ACTIVE_REPO_PATH
    return Path.cwd().resolve()


def _is_binary_file(file_path: Path) -> bool:
    """Heuristic check for binary files by reading the first 4KB."""
    try:
        with file_path.open("rb") as f:
            chunk = f.read(4096)
        return b"\x00" in chunk
    except OSError:
        return True


def _iter_repo_files(repo_root: Path, include_hidden: bool = True) -> List[Path]:
    """Return sorted list of files inside repo_root, excluding .git/ internals."""
    results: List[Path] = []
    for root, dirs, files in os.walk(repo_root, followlinks=False):
        # Always skip .git internal directory
        dirs[:] = sorted(
            d
            for d in dirs
            if d != ".git"
            and (include_hidden or not d.startswith("."))
            and not Path(root, d).is_symlink()
        )
        for fname in sorted(files):
            if not include_hidden and fname.startswith("."):
                continue
            fpath = Path(root) / fname
            if fpath.is_symlink():
                # Verify symlink doesn't escape repo root
                try:
                    fpath.resolve().relative_to(repo_root.resolve())
                except ValueError:
                    continue
            results.append(fpath)
    return results


def _match_suspicious_artifact(rel_path: str) -> Optional[str]:
    """Check if a relative path matches known temporary/generated/secret file patterns."""
    fname = os.path.basename(rel_path)
    # Allow explicit template/example env files
    if fname.lower() in (
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        "env.example",
    ):
        return None
    for pattern, reason in SUSPICIOUS_TRACKED_PATTERNS:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(fname, pattern):
            return reason
    return None


def list_files(
    directory: str = ".",
    include_hidden: bool = True,
    max_results: int = 120,
    repo_path: str | Path | None = None,
) -> Dict[str, Any]:
    """Discover repository files, structure, key DevOps artifacts, and suspicious tracked files."""
    repo_root = _get_repo_root(repo_path)
    try:
        target_dir = resolve_safe_repo_path(repo_root, directory)
    except PermissionError as exc:
        return {"error": str(exc), "files": []}

    if not target_dir.exists() or not target_dir.is_dir():
        return {
            "error": f"Directory '{directory}' does not exist in repository.",
            "files": [],
        }

    all_paths = _iter_repo_files(target_dir, include_hidden=include_hidden)
    rel_files: List[str] = []
    suspicious_files: List[Dict[str, str]] = []

    categories: Dict[str, List[str]] = {
        "documentation": [],
        "dependency_manifests": [],
        "lockfiles": [],
        "ci_workflows": [],
        "linter_and_formatter_configs": [],
        "test_files": [],
        "container_and_build": [],
        "environment_and_config": [],
    }

    for fpath in all_paths:
        rel = fpath.relative_to(repo_root).as_posix()
        rel_files.append(rel)
        lower_rel = rel.lower()
        base = os.path.basename(lower_rel)

        reason = _match_suspicious_artifact(rel)
        if reason:
            suspicious_files.append({"file": rel, "issue": reason})

        # Categorize key DevOps signals to help the LLM plan next tool calls
        if base.startswith(("readme", "contributing", "codeowners", "security", "changelog", "license")):
            categories["documentation"].append(rel)
        if base in (
            "requirements.txt",
            "requirements-dev.txt",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "pipfile",
            "environment.yml",
            "package.json",
            "go.mod",
            "cargo.toml",
            "pom.xml",
            "build.gradle",
            "gemfile",
            "composer.json",
        ) or re.match(r"^requirements[a-z0-9_-]*\.txt$", base):
            categories["dependency_manifests"].append(rel)
        if base in (
            "poetry.lock",
            "pipfile.lock",
            "uv.lock",
            "pdm.lock",
            "requirements.lock",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "go.sum",
            "cargo.lock",
            "gemfile.lock",
            "composer.lock",
        ):
            categories["lockfiles"].append(rel)
        if (
            lower_rel.startswith(".github/workflows/")
            or lower_rel.startswith(".circleci/")
            or base in (".gitlab-ci.yml", ".travis.yml", "jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml")
        ):
            categories["ci_workflows"].append(rel)
        if base in (
            "ruff.toml",
            ".ruff.toml",
            ".flake8",
            ".pylintrc",
            "mypy.ini",
            ".mypy.ini",
            ".prettierrc",
            ".prettierrc.json",
            ".eslintrc",
            ".eslintrc.js",
            ".eslintrc.json",
            "eslint.config.js",
            ".pre-commit-config.yaml",
            ".editorconfig",
            "tox.ini",
        ):
            categories["linter_and_formatter_configs"].append(rel)
        if (
            "test" in lower_rel.split("/")
            or "tests" in lower_rel.split("/")
            or base.startswith("test_")
            or base.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts", "_test.go"))
            or base in ("conftest.py", "pytest.ini")
        ):
            categories["test_files"].append(rel)
        if (
            base.startswith("dockerfile")
            or base in ("docker-compose.yml", "docker-compose.yaml", ".dockerignore", "makefile", "justfile", "goreleaser.yml", ".goreleaser.yml")
        ):
            categories["container_and_build"].append(rel)
        if (
            base.startswith(".env")
            or "config" in base
            or "settings" in base
            or base in (".gitignore", ".gitattributes")
        ):
            categories["environment_and_config"].append(rel)

    truncated = len(rel_files) > max_results
    return {
        "directory": directory,
        "total_files": len(rel_files),
        "truncated": truncated,
        "files": rel_files[:max_results],
        "has_gitignore": ".gitignore" in rel_files,
        "has_readme": any(
            os.path.basename(f).lower().startswith("readme") for f in rel_files
        ),
        "detected_categories": categories,
        "suspicious_tracked_files": suspicious_files,
    }


def read_file(
    path: str,
    start_line: int = 1,
    end_line: int = 100,
    repo_path: str | Path | None = None,
) -> Dict[str, Any]:
    """Read lines from a repository file with 1-indexed line numbers and secret redaction."""
    repo_root = _get_repo_root(repo_path)
    try:
        target_file = resolve_safe_repo_path(repo_root, path)
    except PermissionError as exc:
        return {"file": path, "error": str(exc)}

    if not target_file.exists():
        return {"file": path, "error": f"File '{path}' does not exist."}
    if target_file.is_dir():
        return {"file": path, "error": f"Path '{path}' is a directory, not a file."}

    try:
        size_bytes = target_file.stat().st_size
    except OSError as exc:
        return {"file": path, "error": f"Cannot stat file '{path}': {exc}"}

    if _is_binary_file(target_file):
        return {
            "file": path,
            "is_binary": True,
            "size_bytes": size_bytes,
            "error": "Binary file cannot be read as text.",
        }

    if size_bytes > 2 * 1024 * 1024:
        return {
            "file": path,
            "size_bytes": size_bytes,
            "error": "File exceeds 2MB safety limit for text inspection.",
        }

    try:
        raw_text = target_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"file": path, "error": f"Failed to read '{path}': {exc}"}

    lines = raw_text.splitlines()
    total_lines = len(lines)
    s_line = max(1, int(start_line))
    # Cap giant lockfiles to 40 lines to preserve LLM token budget
    if target_file.name.lower() in ("uv.lock", "poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "pipfile.lock"):
        end_line = min(int(end_line), s_line + 39)
    e_line = min(total_lines, max(s_line, int(end_line)))

    numbered_lines: List[str] = []
    redacted_secret_lines: List[int] = []
    machine_specific_path_lines: List[Dict[str, Any]] = []

    for idx in range(s_line, e_line + 1):
        orig_line = lines[idx - 1]
        safe_line = redact_secrets(orig_line)
        if safe_line != orig_line or REDACTION_TOKEN in safe_line:
            redacted_secret_lines.append(idx)
        m_path = MACHINE_PATH_REGEX.search(orig_line)
        if m_path:
            machine_specific_path_lines.append(
                {"line": idx, "matched_path": m_path.group(1)}
            )
        numbered_lines.append(f"{idx}: {safe_line}")

    return {
        "file": target_file.relative_to(repo_root).as_posix(),
        "total_lines": total_lines,
        "start_line": s_line,
        "end_line": e_line,
        "redacted_secret_lines": redacted_secret_lines,
        "machine_specific_path_lines": machine_specific_path_lines,
        "content": "\n".join(numbered_lines),
    }


def search_code(
    pattern: str,
    file_glob: Optional[str] = None,
    case_sensitive: bool = False,
    max_matches: int = 25,
    repo_path: str | Path | None = None,
) -> Dict[str, Any]:
    """Search repository files for a regex or text pattern with secret redaction."""
    repo_root = _get_repo_root(repo_path)
    if not pattern or not isinstance(pattern, str):
        return {"error": "Search pattern must be a non-empty string.", "matches": []}

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        regex = re.compile(pattern, flags)
    except re.error:
        regex = re.compile(re.escape(pattern), flags)

    matches: List[Dict[str, Any]] = []
    files_searched = 0

    for fpath in _iter_repo_files(repo_root, include_hidden=True):
        rel = fpath.relative_to(repo_root).as_posix()
        if file_glob and not (
            fnmatch.fnmatch(rel, file_glob)
            or fnmatch.fnmatch(os.path.basename(rel), file_glob)
        ):
            continue
        if _is_binary_file(fpath):
            continue
        try:
            if fpath.stat().st_size > 1024 * 1024:
                continue
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        files_searched += 1
        for line_num, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                redacted_line = redact_secrets(line.strip())
                had_secret = (redacted_line != line.strip()) or (
                    REDACTION_TOKEN in redacted_line
                )
                matches.append(
                    {
                        "file": rel,
                        "line": line_num,
                        "snippet": redacted_line[:240],
                        "secret_redacted": had_secret,
                    }
                )
                if len(matches) >= max_matches:
                    return {
                        "pattern": pattern,
                        "files_searched": files_searched,
                        "total_matches_returned": len(matches),
                        "truncated": True,
                        "matches": matches,
                    }

    return {
        "pattern": pattern,
        "files_searched": files_searched,
        "total_matches_returned": len(matches),
        "truncated": False,
        "matches": matches,
    }


def git_log(
    max_commits: int = 12,
    include_files: bool = True,
    repo_path: str | Path | None = None,
) -> Dict[str, Any]:
    """Inspect repository Git commit history and commit hygiene."""
    repo_root = _get_repo_root(repo_path)
    git_dir = repo_root / ".git"
    if not git_dir.exists():
        return {
            "error": "No .git directory found in repository root.",
            "commits": [],
        }

    limit = max(1, min(100, int(max_commits)))
    fmt = "%H%x1f%h%x1f%an%x1f%ad%x1f%s"
    cmd = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "log",
        f"-n{limit}",
        "--date=iso-strict",
        f"--pretty=format:{fmt}",
    ]
    if include_files:
        cmd.append("--name-status")

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return {"error": f"Failed to execute git log: {exc}", "commits": []}

    if proc.returncode != 0:
        return {
            "error": redact_secrets(proc.stderr.strip() or "git log failed"),
            "commits": [],
        }

    commits: List[Dict[str, Any]] = []
    current_commit: Optional[Dict[str, Any]] = None

    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "\x1f" in line:
            parts = line.split("\x1f")
            if len(parts) >= 5:
                current_commit = {
                    "commit": parts[0],
                    "short_commit": parts[1],
                    "author": redact_secrets(parts[2]),
                    "date": parts[3],
                    "message": redact_secrets(parts[4]),
                    "changed_files": [],
                }
                commits.append(current_commit)
        elif current_commit is not None and include_files:
            if len(current_commit["changed_files"]) < 8:
                current_commit["changed_files"].append(redact_secrets(line))

    # Summarize commit hygiene signals
    vague_messages = [
        c["short_commit"]
        for c in commits
        if len(c.get("message", "").strip()) <= 4
        or c.get("message", "").strip().lower()
        in ("wip", "fix", "update", "test", "commit", "changes", "asdf", ".")
    ]

    return {
        "commit_count_returned": len(commits),
        "vague_commit_messages": vague_messages,
        "commits": commits,
    }


def git_status(repo_path: str | Path | None = None) -> Dict[str, Any]:
    """Inspect working tree status, tracked artifacts, and .gitignore effectiveness."""
    repo_root = _get_repo_root(repo_path)
    git_dir = repo_root / ".git"
    if not git_dir.exists():
        return {"error": "No .git directory found in repository root."}

    try:
        status_proc = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "status", "--porcelain"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        ls_proc = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "ls-files"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return {"error": f"git status failed: {exc}"}

    tracked_files = [
        line.strip() for line in ls_proc.stdout.splitlines() if line.strip()
    ]
    tracked_suspicious: List[Dict[str, str]] = []
    for rel in tracked_files:
        reason = _match_suspicious_artifact(rel)
        if reason:
            tracked_suspicious.append({"file": rel, "issue": reason})

    # Inspect .gitignore if present
    gitignore_path = repo_root / ".gitignore"
    gitignore_info: Dict[str, Any] = {"exists": gitignore_path.exists()}
    if gitignore_path.exists():
        try:
            gi_lines = [
                ln.strip()
                for ln in gitignore_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            gitignore_info["non_empty_pattern_count"] = len(gi_lines)
            gitignore_info["patterns_sample"] = gi_lines[:40]
            gitignore_info["ignores_env"] = any(
                ".env" in p for p in gi_lines
            )
            gitignore_info["ignores_pycache_or_pyc"] = any(
                "__pycache__" in p or "*.pyc" in p or "*.py[cod]" in p
                for p in gi_lines
            )
            gitignore_info["ignores_venv"] = any(
                "venv" in p or ".venv" in p for p in gi_lines
            )
        except OSError:
            gitignore_info["error"] = "Could not read .gitignore"

    return {
        "working_tree_clean": status_proc.stdout.strip() == "",
        "uncommitted_changes": [
            redact_secrets(ln)
            for ln in status_proc.stdout.splitlines()
            if ln.strip()
        ],
        "total_tracked_files": len(tracked_files),
        "tracked_suspicious_files": tracked_suspicious,
        "gitignore_analysis": gitignore_info,
    }


def _find_line_number(lines: List[str], pattern: str, start_at: int = 1) -> Optional[int]:
    """Find the 1-indexed line number matching a regex pattern."""
    regex = re.compile(pattern, re.IGNORECASE)
    for idx in range(max(1, start_at), len(lines) + 1):
        if regex.search(lines[idx - 1]):
            return idx
    return None


def inspect_github_actions(
    workflow_file: Optional[str] = None,
    repo_path: str | Path | None = None,
) -> Dict[str, Any]:
    """Inspect .github/workflows YAML files for CI/CD, testing, trigger, and security issues."""
    repo_root = _get_repo_root(repo_path)
    workflows_dir = repo_root / ".github" / "workflows"

    if not workflows_dir.exists() or not workflows_dir.is_dir():
        return {
            "workflows_found": 0,
            "workflows": [],
            "note": "No .github/workflows directory exists in this repository.",
        }

    target_files: List[Path] = []
    if workflow_file:
        try:
            resolved = resolve_safe_repo_path(repo_root, workflow_file)
            if resolved.exists() and resolved.is_file():
                target_files.append(resolved)
        except PermissionError as exc:
            return {"error": str(exc), "workflows": []}
    else:
        for fpath in sorted(workflows_dir.iterdir()):
            if fpath.is_file() and fpath.suffix.lower() in (".yml", ".yaml"):
                target_files.append(fpath)

    workflow_reports: List[Dict[str, Any]] = []

    for wf_path in target_files:
        rel_path = wf_path.relative_to(repo_root).as_posix()
        try:
            raw_text = wf_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            workflow_reports.append({"file": rel_path, "error": str(exc)})
            continue

        lines = raw_text.splitlines()
        findings: List[Dict[str, Any]] = []

        # Parse YAML safely if PyYAML is available
        parsed: Any = None
        if yaml is not None:
            try:
                parsed = yaml.safe_load(raw_text)
            except Exception as exc:
                findings.append(
                    {
                        "type": "invalid_yaml",
                        "line": 1,
                        "detail": f"Workflow YAML syntax error: {exc}",
                    }
                )

        # Line-by-line static checks for reliable line numbers
        has_test_command = False
        has_lint_command = False
        has_permissions_block = False

        for line_no, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.match(r"^permissions\s*:", stripped):
                has_permissions_block = True
            if re.search(r"permissions\s*:\s*write-all", stripped, re.IGNORECASE) or re.search(
                r"contents\s*:\s*write", stripped, re.IGNORECASE
            ):
                findings.append(
                    {
                        "type": "broad_workflow_permissions",
                        "line": line_no,
                        "snippet": redact_secrets(stripped),
                        "detail": "Broad write permissions granted in workflow.",
                    }
                )

            if re.search(r"pull_request_target\s*:", stripped):
                findings.append(
                    {
                        "type": "unsafe_pull_request_target",
                        "line": line_no,
                        "snippet": redact_secrets(stripped),
                        "detail": "pull_request_target trigger runs in base repo context and is dangerous if untrusted PR code is checked out.",
                    }
                )

            # Check uses: action pinning
            uses_match = re.match(r"^-?\s*uses\s*:\s*([^\s#]+)", stripped)
            if uses_match:
                action_ref = uses_match.group(1).strip("\"'")
                if not action_ref.startswith("./") and "@" in action_ref:
                    _, ref_ver = action_ref.rsplit("@", 1)
                    if ref_ver.lower() in ("main", "master", "head", "latest", "dev"):
                        findings.append(
                            {
                                "type": "unpinned_github_action",
                                "line": line_no,
                                "snippet": redact_secrets(stripped),
                                "detail": f"GitHub Action '{action_ref}' is pinned to mutable branch/tag '{ref_ver}' instead of a release tag or commit SHA.",
                            }
                        )
                elif not action_ref.startswith("./") and "@" not in action_ref:
                    findings.append(
                        {
                            "type": "unversioned_github_action",
                            "line": line_no,
                            "snippet": redact_secrets(stripped),
                            "detail": f"GitHub Action '{action_ref}' has no version ref.",
                        }
                    )

            # Check continue-on-error: true
            if re.search(r"continue-on-error\s*:\s*true", stripped, re.IGNORECASE):
                findings.append(
                    {
                        "type": "continue_on_error_enabled",
                        "line": line_no,
                        "snippet": redact_secrets(stripped),
                        "detail": "continue-on-error: true allows failing validation/test steps to pass silently.",
                    }
                )

            # Check shell suppression of test/lint failures (|| true, || exit 0, --no-verify)
            if re.search(r"(\|\|\s*true\b|\|\|\s*exit\s+0\b|--no-verify\b)", stripped):
                findings.append(
                    {
                        "type": "suppressed_step_failure",
                        "line": line_no,
                        "snippet": redact_secrets(stripped),
                        "detail": "Command suppresses non-zero exit code (|| true / || exit 0 / --no-verify), bypassing CI failure gates.",
                    }
                )

            # Check untrusted GitHub context expression injection inside run:
            if re.search(
                r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|commits|head_commit|discussion)\.[^}]*(?:title|body|message|ref|label)",
                stripped,
                re.IGNORECASE,
            ) or re.search(r"\$\{\{\s*github\.head_ref\s*\}\}", stripped, re.IGNORECASE):
                findings.append(
                    {
                        "type": "workflow_script_injection",
                        "line": line_no,
                        "snippet": redact_secrets(stripped),
                        "detail": "Untrusted GitHub event context interpolated directly in workflow expression (command injection risk).",
                    }
                )

            # Detect test or lint execution in workflow
            if re.search(
                r"\b(pytest|unittest|nosetests|tox|npm\s+test|yarn\s+test|pnpm\s+test|go\s+test|cargo\s+test|mvn\s+test|gradle\s+test)\b",
                stripped,
            ):
                has_test_command = True
            if re.search(
                r"\b(ruff|flake8|black|isort|pylint|mypy|bandit|eslint|prettier|golangci-lint| clippy)\b",
                stripped,
            ):
                has_lint_command = True

            # Check hardcoded secrets in workflow lines
            redacted = redact_secrets(stripped)
            if redacted != stripped or REDACTION_TOKEN in redacted:
                findings.append(
                    {
                        "type": "hardcoded_secret_in_workflow",
                        "line": line_no,
                        "snippet": redacted,
                        "detail": "Hardcoded credential/token literal detected directly in workflow file instead of ${{ secrets.* }}.",
                    }
                )

        # Inspect trigger configuration from parsed YAML
        triggers_summary: Any = None
        if isinstance(parsed, dict):
            # In YAML 1.1, 'on' key can be parsed as boolean True
            on_block = parsed.get("on", parsed.get(True))
            triggers_summary = on_block
            if isinstance(on_block, dict):
                # Check if push/pull_request only triggers on non-standard or missing branches
                if "pull_request" not in on_block and "push" in on_block:
                    on_line = _find_line_number(lines, r"^['\"]?on['\"]?\s*:") or 1
                    findings.append(
                        {
                            "type": "missing_pull_request_trigger",
                            "line": on_line,
                            "detail": "Workflow triggers on push but does not run on pull_request events to gate incoming PRs.",
                        }
                    )
            elif isinstance(on_block, str) and on_block not in ("push", "pull_request"):
                on_line = _find_line_number(lines, r"^['\"]?on['\"]?\s*:") or 1
                findings.append(
                    {
                        "type": "missing_ci_push_pr_triggers",
                        "line": on_line,
                        "detail": f"Workflow only triggers on '{on_block}' and does not validate push or pull_request events.",
                    }
                )
            elif isinstance(on_block, list) and "pull_request" not in on_block:
                on_line = _find_line_number(lines, r"^['\"]?on['\"]?\s*:") or 1
                findings.append(
                    {
                        "type": "missing_pull_request_trigger",
                        "line": on_line,
                        "detail": f"Workflow triggers on {on_block} but omits 'pull_request' validation.",
                    }
                )

        if not has_permissions_block:
            findings.append(
                {
                    "type": "missing_explicit_permissions",
                    "line": 1,
                    "detail": "Workflow does not declare an explicit 'permissions:' block (least-privilege GITHUB_TOKEN permissions).",
                }
            )

        workflow_reports.append(
            {
                "file": rel_path,
                "triggers": triggers_summary,
                "has_test_execution": has_test_command,
                "has_lint_execution": has_lint_command,
                "has_explicit_permissions": has_permissions_block,
                "findings": findings,
            }
        )

    return {
        "workflows_found": len(workflow_reports),
        "workflows": workflow_reports,
    }


def _ast_inspect_python_file(file_path: Path, rel_path: str) -> List[Dict[str, Any]]:
    """Pure-Python AST static code quality & security inspection (never executes target code)."""
    issues: List[Dict[str, Any]] = []
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return issues

    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as exc:
        issues.append(
            {
                "file": rel_path,
                "line": exc.lineno or 1,
                "code": "SYNTAX-001",
                "category": "code_quality",
                "message": f"Python SyntaxError: {exc.msg}",
            }
        )
        return issues

    for node in ast.walk(tree):
        # 1. Bare except: handler
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(
                {
                    "file": rel_path,
                    "line": node.lineno,
                    "code": "E722",
                    "category": "code_quality",
                    "message": "Bare 'except:' catches BaseException/SystemExit/KeyboardInterrupt and hides failures.",
                }
            )
        # 2. Mutable default arguments & overly long functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defaults = list(node.args.defaults) + [
                d for d in node.args.kw_defaults if d is not None
            ]
            for d in defaults:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    issues.append(
                        {
                            "file": rel_path,
                            "line": node.lineno,
                            "code": "B006",
                            "category": "code_quality",
                            "message": f"Function '{node.name}' uses mutable default argument ({type(d).__name__}).",
                        }
                    )
            end_lineno = getattr(node, "end_lineno", None)
            if end_lineno and (end_lineno - node.lineno) > 120:
                issues.append(
                    {
                        "file": rel_path,
                        "line": node.lineno,
                        "code": "C901",
                        "category": "code_quality",
                        "message": f"Function '{node.name}' spans {end_lineno - node.lineno} lines (>120 lines), hurting maintainability.",
                    }
                )
        # 3. Dangerous calls: eval, exec, subprocess(..., shell=True), yaml.load, verify=False
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                prefix = (
                    node.func.value.id
                    if isinstance(node.func.value, ast.Name)
                    else ""
                )
                func_name = f"{prefix}.{node.func.attr}" if prefix else node.func.attr

            if func_name in ("eval", "exec"):
                issues.append(
                    {
                        "file": rel_path,
                        "line": node.lineno,
                        "code": "S307",
                        "category": "security",
                        "message": f"Use of dangerous dynamic execution builtin '{func_name}()'.",
                    }
                )
            if func_name.startswith("subprocess.") or func_name in ("Popen", "run", "call", "check_output", "check_call"):
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        issues.append(
                            {
                                "file": rel_path,
                                "line": node.lineno,
                                "code": "S602",
                                "category": "security",
                                "message": f"Subprocess call '{func_name}' with shell=True enables shell injection.",
                            }
                        )
            if func_name == "yaml.load":
                has_safe_loader = any(kw.arg == "Loader" for kw in node.keywords) or len(node.args) > 1
                if not has_safe_loader:
                    issues.append(
                        {
                            "file": rel_path,
                            "line": node.lineno,
                            "code": "S506",
                            "category": "security",
                            "message": "Unsafe yaml.load() without Loader=SafeLoader allows arbitrary code execution.",
                        }
                    )
            if func_name in ("pickle.loads", "pickle.load"):
                issues.append(
                    {
                        "file": rel_path,
                        "line": node.lineno,
                        "code": "S301",
                        "category": "security",
                        "message": f"Deserialization via '{func_name}()' on untrusted data can execute arbitrary code.",
                    }
                )
            for kw in node.keywords:
                if (
                    kw.arg == "verify"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                ):
                    issues.append(
                        {
                            "file": rel_path,
                            "line": node.lineno,
                            "code": "S501",
                            "category": "security",
                            "message": "TLS certificate verification explicitly disabled (verify=False).",
                        }
                    )

        # 4. Wildcard import (from x import *)
        if isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                issues.append(
                    {
                        "file": rel_path,
                        "line": node.lineno,
                        "code": "F403",
                        "category": "code_quality",
                        "message": f"Wildcard import 'from {node.module} import *' pollutes namespace and obscures undefined names.",
                    }
                )

    return issues


def run_ruff(
    target_path: str = ".",
    repo_path: str | Path | None = None,
) -> Dict[str, Any]:
    """Run static Python linting via Ruff (if installed) plus built-in AST static analysis."""
    repo_root = _get_repo_root(repo_path)
    try:
        resolved_target = resolve_safe_repo_path(repo_root, target_path)
    except PermissionError as exc:
        return {"error": str(exc), "issues": []}

    if not resolved_target.exists():
        return {"error": f"Target path '{target_path}' does not exist.", "issues": []}

    py_files: List[Path] = []
    if resolved_target.is_file() and resolved_target.suffix == ".py":
        py_files.append(resolved_target)
    elif resolved_target.is_dir():
        py_files = [
            p
            for p in _iter_repo_files(resolved_target, include_hidden=False)
            if p.suffix == ".py"
        ]

    ast_issues: List[Dict[str, Any]] = []
    for pyf in py_files:
        rel = pyf.relative_to(repo_root).as_posix()
        ast_issues.extend(_ast_inspect_python_file(pyf, rel))

    ruff_bin = shutil.which("ruff")
    ruff_diagnostics: List[Dict[str, Any]] = []
    ruff_executed = False

    if ruff_bin and py_files:
        try:
            proc = subprocess.run(
                [
                    ruff_bin,
                    "check",
                    "--output-format=json",
                    "--no-cache",
                    str(resolved_target),
                ],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            ruff_executed = True
            if proc.stdout.strip():
                raw_items = json.loads(proc.stdout)
                for item in raw_items[:60]:
                    filename = item.get("filename", "")
                    try:
                        rel_f = Path(filename).resolve().relative_to(repo_root).as_posix()
                    except ValueError:
                        rel_f = filename
                    loc = item.get("location", {}) or {}
                    ruff_diagnostics.append(
                        {
                            "file": rel_f,
                            "line": loc.get("row", 1),
                            "code": item.get("code", ""),
                            "message": redact_secrets(item.get("message", "")),
                        }
                    )
        except Exception:
            ruff_executed = False

    return {
        "python_files_analyzed": len(py_files),
        "ruff_binary_available": ruff_bin is not None,
        "ruff_cli_executed": ruff_executed,
        "ruff_diagnostics": ruff_diagnostics,
        "ast_static_issues": ast_issues[:60],
    }


def run_pytest(
    target_path: str = ".",
    repo_path: str | Path | None = None,
) -> Dict[str, Any]:
    """Perform safe static inspection of repository tests without executing untrusted code.

    Per Assignment 2 Section 9:
    'Do not modify targets or execute untrusted repository code without adequate isolation.'
    This tool statically parses test files via Python AST to detect missing tests, empty/placeholder
    tests, broken assertions (e.g., assert False / 1 == 2), and syntax errors safely.
    """
    repo_root = _get_repo_root(repo_path)
    try:
        resolved_target = resolve_safe_repo_path(repo_root, target_path)
    except PermissionError as exc:
        return {"error": str(exc)}

    if not resolved_target.exists():
        return {"error": f"Target path '{target_path}' does not exist."}

    all_files = _iter_repo_files(resolved_target, include_hidden=False)
    py_test_files: List[Path] = []
    other_test_files: List[str] = []

    for fpath in all_files:
        rel = fpath.relative_to(repo_root).as_posix()
        lower = rel.lower()
        base = os.path.basename(lower)
        parts = lower.split("/")

        is_test = (
            "test" in parts
            or "tests" in parts
            or "__tests__" in parts
            or base.startswith("test_")
            or base.endswith(
                (
                    "_test.py",
                    ".test.js",
                    ".spec.js",
                    ".test.ts",
                    ".spec.ts",
                    "_test.go",
                )
            )
        )
        if is_test:
            if fpath.suffix == ".py":
                py_test_files.append(fpath)
            else:
                other_test_files.append(rel)

    test_functions_count = 0
    findings: List[Dict[str, Any]] = []

    for tf in py_test_files:
        rel = tf.relative_to(repo_root).as_posix()
        try:
            source = tf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError as exc:
            findings.append(
                {
                    "file": rel,
                    "line": exc.lineno or 1,
                    "issue": "syntax_error_in_test",
                    "detail": f"Test file contains SyntaxError: {exc.msg}",
                }
            )
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                node.name.startswith("test_") or node.name == "test"
            ):
                test_functions_count += 1
                # Filter out docstring from body
                stmts = [
                    s
                    for s in node.body
                    if not (
                        isinstance(s, ast.Expr)
                        and isinstance(s.value, ast.Constant)
                        and isinstance(s.value.value, str)
                    )
                ]
                if not stmts or all(
                    isinstance(s, ast.Pass)
                    or (
                        isinstance(s, ast.Expr)
                        and isinstance(s.value, ast.Constant)
                        and s.value.value is Ellipsis
                    )
                    for s in stmts
                ):
                    findings.append(
                        {
                            "file": rel,
                            "line": node.lineno,
                            "issue": "empty_test_function",
                            "detail": f"Test function '{node.name}' has no body/assertions (only pass/...).",
                        }
                    )
                    continue

                # Check assertions inside test function
                assert_nodes = [
                    n for n in ast.walk(node) if isinstance(n, ast.Assert)
                ]
                call_names = []
                for n in ast.walk(node):
                    if isinstance(n, ast.Call):
                        if isinstance(n.func, ast.Attribute):
                            call_names.append(n.func.attr)
                        elif isinstance(n.func, ast.Name):
                            call_names.append(n.func.id)

                has_unittest_assert = any(
                    c.startswith("assert") or c in ("raises", "fail")
                    for c in call_names
                )

                if not assert_nodes and not has_unittest_assert:
                    findings.append(
                        {
                            "file": rel,
                            "line": node.lineno,
                            "issue": "test_without_assertions",
                            "detail": f"Test function '{node.name}' contains no assert statements or assertion helpers.",
                        }
                    )

                for an in assert_nodes:
                    # Detect trivial `assert True` or guaranteed failing `assert False`
                    if isinstance(an.test, ast.Constant):
                        if an.test.value is True:
                            findings.append(
                                {
                                    "file": rel,
                                    "line": an.lineno,
                                    "issue": "trivial_assert_true",
                                    "detail": f"Test '{node.name}' uses meaningless 'assert True'.",
                                }
                            )
                        elif an.test.value is False:
                            findings.append(
                                {
                                    "file": rel,
                                    "line": an.lineno,
                                    "issue": "failing_assert_false",
                                    "detail": f"Test '{node.name}' contains unconditional 'assert False'.",
                                }
                            )
                    # Detect deterministic failing constant comparison like `assert 1 == 2`
                    if (
                        isinstance(an.test, ast.Compare)
                        and len(an.test.ops) == 1
                        and isinstance(an.test.ops[0], ast.Eq)
                        and isinstance(an.test.left, ast.Constant)
                        and isinstance(an.test.comparators[0], ast.Constant)
                    ):
                        if an.test.left.value != an.test.comparators[0].value:
                            findings.append(
                                {
                                    "file": rel,
                                    "line": an.lineno,
                                    "issue": "deterministic_failing_assertion",
                                    "detail": (
                                        f"Test '{node.name}' contains failing constant assertion: "
                                        f"{an.test.left.value!r} == {an.test.comparators[0].value!r}."
                                    ),
                                }
                            )

    return {
        "execution_mode": "static_ast_safe_inspection (no untrusted code executed)",
        "python_test_files": [
            p.relative_to(repo_root).as_posix() for p in py_test_files
        ],
        "other_test_files": other_test_files,
        "total_test_files": len(py_test_files) + len(other_test_files),
        "python_test_functions_count": test_functions_count,
        "findings": findings,
    }


class RepositorySandbox:
    """Context manager that safely clones a public GitHub repository into a temporary sandbox."""

    def __init__(self, repo_target: str, timeout: int = 60) -> None:
        self.raw_target = repo_target
        self.normalized_target, self.is_remote = validate_repo_target(repo_target)
        self.timeout = timeout
        self._temp_dir: Optional[str] = None
        self.repo_path: Optional[Path] = None

    def __enter__(self) -> Path:
        if not self.is_remote:
            # Local directory mode: copy into temporary read-only workspace so original is untouched
            self._temp_dir = tempfile.mkdtemp(prefix="devops_audit_local_")
            dest = Path(self._temp_dir) / "repo"
            shutil.copytree(self.normalized_target, dest, symlinks=True)
            self.repo_path = dest.resolve()
            set_active_repo(self.repo_path)
            return self.repo_path

        self._temp_dir = tempfile.mkdtemp(prefix="devops_audit_clone_")
        dest = Path(self._temp_dir) / "repo"

        clone_cmd = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "advice.detachedHead=false",
            "clone",
            "--depth",
            "50",
            "--no-recurse-submodules",
            self.normalized_target,
            str(dest),
        ]

        try:
            proc = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                env={
                    **os.environ,
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_ASKPASS": "echo",
                },
            )
        except subprocess.TimeoutExpired as exc:
            self.cleanup()
            raise RuntimeError(
                f"Timed out cloning repository '{self.normalized_target}' after {self.timeout}s."
            ) from exc
        except OSError as exc:
            self.cleanup()
            raise RuntimeError(f"Failed to execute git clone: {exc}") from exc

        if proc.returncode != 0 or not dest.exists():
            err_msg = redact_secrets(proc.stderr.strip() or proc.stdout.strip())
            self.cleanup()
            raise RuntimeError(
                f"Failed to clone repository '{self.normalized_target}': {err_msg}"
            )

        self.repo_path = dest.resolve()
        set_active_repo(self.repo_path)
        return self.repo_path

    def cleanup(self) -> None:
        set_active_repo(None)
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        self._temp_dir = None

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()


class RepositoryToolkit:
    """Dispatcher binding the repository sandbox to LLM-callable inspection tools."""

    def __init__(self, repo_path: str | Path) -> None:
        self.repo_path = Path(repo_path).resolve()

    @staticmethod
    def tool_schemas() -> List[Dict[str, Any]]:
        """Return OpenAI/Groq-compatible function tool definitions for the LLM."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "list_files",
                    "description": (
                        "Discover files and directory structure in the repository, "
                        "categorize key DevOps config/test/CI files, and flag suspicious tracked files."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "directory": {
                                "type": "string",
                                "description": "Relative directory path to list (default '.').",
                            },
                            "include_hidden": {
                                "type": "boolean",
                                "description": "Include dotfiles such as .gitignore and .github/ (default true).",
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": (
                        "Read lines from a specific file in the repository with 1-indexed line numbers "
                        "and automatic secret value redaction."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Relative file path inside the repository (e.g. 'README.md', 'requirements.txt').",
                            },
                            "start_line": {
                                "type": "integer",
                                "description": "1-indexed start line (default 1).",
                            },
                            "end_line": {
                                "type": "integer",
                                "description": "1-indexed end line (default 250).",
                            },
                        },
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_code",
                    "description": (
                        "Search across repository files for a regex or text pattern (e.g., hardcoded credentials, "
                        "machine-specific paths, unsafe calls, debug flags, TODOs)."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {
                                "type": "string",
                                "description": "Regular expression or substring pattern to search for.",
                            },
                            "file_glob": {
                                "type": "string",
                                "description": "Optional filename glob filter such as '*.py' or '*.yml'.",
                            },
                            "case_sensitive": {
                                "type": "boolean",
                                "description": "Whether search is case-sensitive (default false).",
                            },
                        },
                        "required": ["pattern"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "git_log",
                    "description": "Inspect commit history, commit messages, authors, and modified files.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "max_commits": {
                                "type": "integer",
                                "description": "Maximum number of recent commits to inspect (default 25).",
                            },
                            "include_files": {
                                "type": "boolean",
                                "description": "Whether to include changed file names per commit (default true).",
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "git_status",
                    "description": "Inspect tracked temporary/generated/secret files and .gitignore coverage.",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "inspect_github_actions",
                    "description": (
                        "Inspect .github/workflows YAML files for trigger bugs, missing PR checks, "
                        "broad permissions, unpinned actions, continue-on-error, script injection, and test/lint execution."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "workflow_file": {
                                "type": "string",
                                "description": "Optional specific workflow file path. Omit to inspect all workflows.",
                            }
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_ruff",
                    "description": (
                        "Run static code quality and security analysis on Python files using Ruff and AST checks "
                        "(detects syntax errors, bare excepts, shell=True, eval/exec, unsafe yaml.load, verify=False)."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_path": {
                                "type": "string",
                                "description": "Relative file or directory path to analyze (default '.').",
                            }
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_pytest",
                    "description": (
                        "Safely inspect the repository's test suite via static AST analysis (counts tests, "
                        "identifies empty tests, missing assertions, or deterministic failing assertions without executing untrusted code)."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_path": {
                                "type": "string",
                                "description": "Relative path to inspect for tests (default '.').",
                            }
                        },
                        "required": [],
                    },
                },
            },
        ]

    def execute(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Dispatch a tool call safely and sanitize all output strings."""
        args = dict(arguments or {})
        args["repo_path"] = self.repo_path

        dispatch_map = {
            "list_files": list_files,
            "read_file": read_file,
            "search_code": search_code,
            "git_log": git_log,
            "git_status": git_status,
            "inspect_github_actions": inspect_github_actions,
            "run_ruff": run_ruff,
            "run_pytest": run_pytest,
        }

        if tool_name not in dispatch_map:
            return {"error": f"Unknown tool '{tool_name}'. Available tools: {list(dispatch_map.keys())}"}

        for k_alias in ("count", "n", "limit"):
            if k_alias in args and "max_commits" not in args:
                args["max_commits"] = args[k_alias]
        if "max_results" in args and "max_matches" not in args:
            args["max_matches"] = args["max_results"]
        if "file" in args and "path" not in args:
            args["path"] = args["file"]
        if "file_path" in args and "path" not in args:
            args["path"] = args["file_path"]
        if "query" in args and "pattern" not in args:
            args["pattern"] = args["query"]

        func = dispatch_map[tool_name]
        try:
            # Filter kwargs to accepted parameters of func
            valid_params = func.__code__.co_varnames[: func.__code__.co_argcount]
            filtered_args = {k: v for k, v in args.items() if k in valid_params}
            raw_result = func(**filtered_args)
            # Final defense-in-depth secret redaction pass over serialized result
            serialized = json.dumps(raw_result, ensure_ascii=False)
            return json.loads(redact_secrets(serialized))
        except Exception as exc:
            return {"error": f"Tool '{tool_name}' execution failed: {redact_secrets(str(exc))}"}
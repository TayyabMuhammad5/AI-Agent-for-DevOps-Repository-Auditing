# Autonomous AI Agent for DevOps Repository Auditing

**Course:** MLOps   
**Name:** Muhammad Tayyab  
**Roll No:** 23i-0738  
**Section:** B  
**Language:** Python 3.10+  
**Agent Architecture:** Explicit Python Reasoning & Tool Execution Loop (Zero Orchestration Frameworks)  
**Default LLM Provider:** Groq Free Tier (`openai/gpt-oss-120b` via `GROQ_API_KEY`, with automatic support for Gemini and OpenAI)

## 1. Overview

This repository contains an autonomous, LLM-powered **DevOps Repository Auditing Agent** that inspects public GitHub repositories, dynamically selects inspection tools based on iterative observations, identifies genuine software engineering and DevOps best-practice violations, and outputs a machine-readable JSON audit report with verifiable evidence and actionable remediation recommendations.

### Key Design Highlights

- **Explicit Agent Loop (`agent_core.py`):** Implements the full **Observe → Reason → Select Tool → Execute Tool → Interpret Results → Report** cycle directly in Python without LangChain, LangGraph, n8n, or any prebuilt agent framework.
- **Dynamic Multi-Turn Tool Selection:** The LLM starts by observing repository layout and Git hygiene, then chooses targeted follow-up tools (`read_file`, `search_code`, `inspect_github_actions`, `run_ruff`, `run_pytest`, `git_log`) based on what files and patterns actually exist in the repository.
- **High Precision & False-Positive Resistance:** Explicitly enforces the **Acceptable Alternatives Rule** (never flagging absent optional files when equivalent solutions exist) and the **No Remote Branch Protection Inference Rule** (never guessing remote GitHub branch settings from repository files alone).
- **Strict Safety & Secret Redaction (`security.py` & `tools.py`):**
  - Target repositories are cloned into an isolated temporary directory using shallow read-only Git flags (`git -c core.hooksPath=/dev/null -c protocol.file.allow=never clone --depth 50 --no-recurse-submodules`) so the target repository is never modified and malicious Git hooks cannot execute.
  - Untrusted code in target repositories is **never imported or executed dynamically** (`run_pytest()` and `run_ruff()` perform static AST and linter analysis).
  - Multi-stage secret redaction (`redact_secrets()`) replaces any API key, password, token, private key, or connection string credential with `<REDACTED_SECRET>` before tool outputs reach the LLM, stderr logs, or `report.json`.

## 2. Repository Structure

```text
.
├── agent.py                 # CLI entry point (python agent.py --repo <url> --output report.json)
├── agent_core.py            # Explicit Observe -> Reason -> Select Tool -> Execute -> Interpret -> Report loop
├── tools.py                 # Required and optional DevOps inspection tools + RepositorySandbox
├── llm_client.py            # Framework-free LLM client (Groq free tier default + Gemini/OpenAI support)
├── prompts.py               # System prompt, 9 DevOps inspection categories, and precision guardrails
├── security.py              # Secret redaction sanitizer, URL validator, and path-traversal blocker
├── requirements.txt         # Installable Python dependencies
├── pyproject.toml           # Project metadata, packaging, and pytest/ruff settings
├── .env.example             # Required environment variable template (no real credentials)
├── sample_report.json       # Authentic example JSON output produced by the agent
├── .github/workflows/ci.yml # CI workflow running Ruff and Pytest on push and pull_request
└── tests/
    ├── __init__.py
    ├── test_tools.py        # Unit tests for all inspection tools, sandbox isolation, and secret redaction
    └── test_agent.py        # Integration tests for the multi-step agent loop, deduplication, and JSON schema
```

## 3. Installation & Setup

### Step 1: Clone the Repository

```bash
git clone <your_public_github_repo_url>
cd <repo_directory>
```

### Step 2: Create a Virtual Environment & Install Dependencies

```bash
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
source .venv/Scripts/activate   # Windows Git Bash / UCRT64
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure API Credentials (100% Free Groq API Key or Evaluator Key)

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Set your API key in `.env` or export it directly in your shell:

- **Option A — Groq Free Tier (Default & Recommended, 100% Free):**
  1. Sign in at [https://console.groq.com/keys](https://console.groq.com/keys) and create a free API key.
  2. Set `GROQ_API_KEY` in `.env` or export it in your terminal:
     ```bash
     export GROQ_API_KEY="gsk_your_free_groq_key_here"
     ```
- **Option B — Evaluator-Supplied Credentials (Auto-Detected):**
  The LLM client in `llm_client.py` automatically detects whichever credential is provided in the environment:
  - `GROQ_API_KEY` (uses `openai/gpt-oss-120b` with automatic fallback to `openai/gpt-oss-20b` and `qwen/qwen3.8-27b` on rate limits)
  - `GEMINI_API_KEY` / `GOOGLE_API_KEY` (uses `gemini-2.5-flash` via Google's OpenAI-compatible endpoint)
  - `OPENAI_API_KEY` (uses `gpt-4o-mini`)
  - `OPENROUTER_API_KEY` (uses `openai/gpt-oss-120b:free`)

## 4. Execution Instructions

Run the agent unattended against any public GitHub repository URL:

```bash
python agent.py --repo https://github.com/example/demo-project --output report.json
```

### CLI Arguments Reference

| Argument | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--repo` | **Yes** | — | Public GitHub repository URL (`https://github.com/<owner>/<repo>`) or local repo path |
| `--output` | **Yes** | — | Output path for the JSON report (e.g., `report.json`) |
| `--max-steps` | No | `10` | Maximum LLM reasoning & tool-selection iterations |
| `--provider` | No | Auto-detect | Force a specific LLM provider (`groq`, `gemini`, `openai`, `openrouter`) |
| `--model` | No | Provider default | Override the model name (e.g., `openai/gpt-oss-120b`) |
| `--trace-output` | No | `None` | Save the step-by-step tool-call trace JSON to a separate file for inspection |
| `--quiet` | No | `False` | Suppress progress logs on `stderr` |

### Exit Codes

| Exit Code | Meaning |
| :--- | :--- |
| `0` | Inspection completed and valid JSON written to `--output` |
| `1` | Fatal runtime error during repository cloning or agent execution |
| `2` | Invalid or unsafe `--repo` URL/target |
| `3` | Missing or invalid LLM API credentials |
| `4` | File system error writing the output JSON report |

## 5. Agent Architecture & Control Flow

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                     CLI Entry Point (agent.py)                           │
│     python agent.py --repo <github_repository_url> --output report.json  │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                 RepositorySandbox (tools.py / security.py)               │
│  • Validates URL & blocks unsafe Git protocols / argument injection      │
│  • Clones shallow copy to temp dir with core.hooksPath=/dev/null         │
│  • Enforces read-only inspection & cleans up temp clone on exit          │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│               Explicit Agent Loop (DevOpsAuditAgent)                     │
│                                                                          │
│   ┌───────────┐    ┌───────────┐    ┌───────────────┐    ┌────────────┐  │
│   │  Observe  │───▶│  Reason   │───▶│  Select Tool  │───▶│Execute Tool│  │
│   └───────────┘    └───────────┘    └───────────────┘    └─────┬──────┘  │
│         ▲                                                      │         │
│         │                 ┌───────────────────┐                │         │
│         └─────────────────│ Interpret Results │◀───────────────┘         │
│                           └─────────┬─────────┘                          │
│                                     │ (When investigation complete)      │
│                                     ▼                                    │
│                     ┌───────────────────────────────┐                    │
│                     │ Validate, Deduplicate, Redact │                    │
│                     │   Secrets & Write report.json │                    │
│                     └───────────────────────────────┘                    │
└──────────────────────────────────────────────────────────────────────────┘
```

### Inspection Tools Implemented (`tools.py`)

| Tool | Category | Purpose & Safety Mechanism |
| :--- | :--- | :--- |
| `list_files(directory, include_hidden)` | **Required** | Discovers all repository files, categorizes CI/dependency/test/config files, and flags tracked temporary/cache/secret files (`.env`, `.DS_Store`, `__pycache__`, `*.pyc`, `node_modules`, `.venv`). |
| `read_file(path, start_line, end_line)` | **Required** | Reads source and configuration files with 1-indexed line numbers, path-traversal protection, machine-specific path detection, and automatic secret redaction (`<REDACTED_SECRET>`). |
| `search_code(pattern, file_glob)` | **Required** | Searches across repository files using regular expressions and returns matching file paths, exact 1-indexed line numbers, and secret-redacted snippets. |
| `git_log(max_commits, include_files)` | **Required** | Inspects commit history, authors, dates, commit message quality, and modified files per commit with Git hooks disabled. |
| `git_status()` | **Optional** | Checks working tree cleanliness, lists tracked files that violate `.gitignore` best practices, and evaluates `.gitignore` pattern coverage. |
| `inspect_github_actions(workflow_file)` | **Optional** | Parses `.github/workflows/*.yml` to detect missing PR triggers, `permissions: write-all`, missing `permissions:` blocks, `continue-on-error: true`, `\|\| true` failure suppression, unpinned `@main` actions, `pull_request_target` risks, and script injection. |
| `run_ruff(target_path)` | **Optional** | Executes Ruff static linter (if installed) plus a built-in Python `ast` static analyzer detecting syntax errors, bare `except:`, mutable default args, `subprocess(..., shell=True)`, `eval()`, `yaml.load()`, `pickle.loads()`, and `verify=False` without running target code. |
| `run_pytest(target_path)` | **Optional** | Performs static AST inspection of test files to count tests and detect empty tests (`pass`), missing assertions, trivial `assert True`, or deterministic failing assertions (`assert False`, `assert 1 == 2`) without executing untrusted repository code. |

## 6. DevOps Inspection Categories & Evidence Rules

The agent evaluates repositories across all 9 required DevOps categories:

1. **Repository Hygiene (`repository_hygiene`, `HYG-*`):** Missing/empty `README.md`, missing/incomplete `.gitignore`, tracked temporary/generated/cache files (`__pycache__`, `.DS_Store`, `.venv`, `*.pyc`, `*.log`, `*.sqlite3`).
2. **Dependency Management (`dependency_management`, `DEP-*`):** Unpinned dependencies in `requirements.txt` / `pyproject.toml`, conflicting dependency specifications across manifests, or missing required lockfiles.
3. **Code Quality (`code_quality`, `QUAL-*`):** Missing linting/formatting configuration, syntax errors, bare `except:` clauses, mutable default arguments, wildcard imports, and overly long functions.
4. **Testing (`testing`, `TEST-*`):** Missing test suite, deterministic failing assertions, empty test functions without assertions, or tests never executed in CI.
5. **GitHub Actions / CI (`github_actions_ci`, `CI-*`):** Missing CI workflows, missing `pull_request` triggers, `continue-on-error: true`, or shell failure suppression (`|| true`, `--no-verify`).
6. **Security (`security`, `SEC-*`):** Hardcoded credentials/tokens in code or workflows, tracked `.env` or private key files, `permissions: write-all`, unpinned GitHub Actions (`@main`), workflow script injection, `shell=True`, `eval()`, unsafe `yaml.load()`, and `verify=False`.
7. **Configuration (`configuration`, `CFG-*`):** Hardcoded machine-specific paths (`/Users/...`, `/home/...`, `C:\Users\...`), committed IDE settings, `DEBUG = True` in production config, or wildcard `ALLOWED_HOSTS`.
8. **Collaboration (`collaboration`, `COLLAB-*`):** Unsafe PR auto-merge workflows or poor commit hygiene.
9. **Build and Release (`build_and_release`, `BUILD-*`):** Unpinned `:latest` Docker base images, running containers as `root`, missing `.dockerignore` when copying workspace context, or risky release automation without build/test gates.

### Precision & Anti-False-Positive Safeguards

- **Acceptable Alternatives:** The agent checks whether equivalent tools exist before reporting a violation (e.g., `pyproject.toml` vs. `requirements.txt`; Ruff in CI vs. `.flake8`).
- **No Remote Branch Protection Inference:** Both the system prompt and `normalize_and_validate_violations()` filter out any speculative claims about remote GitHub branch protection settings.
- **Template Allowlisting:** `.env.example`, `.env.sample`, and `.env.template` files with placeholder values are recognized as best practices and never flagged as leaked secrets.

## 7. Output Contract

The generated report strictly adheres to the Assignment 2 Section 5 JSON schema:

```json
{
  "repository": "https://github.com/example/demo-project",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "critical",
      "file": "config.py",
      "line": 17,
      "description": "Hardcoded API credential",
      "evidence": "Credential assigned directly in source code",
      "recommendation": "Use a secrets manager or environment variable"
    }
  ]
}
```

- Every violation object contains all 8 required keys (`rule_id`, `category`, `severity`, `file`, `line`, `description`, `evidence`, `recommendation`).
- `severity` is strictly constrained to `"critical"`, `"high"`, `"medium"`, or `"low"`.
- `file` and `line` use JSON `null` when a violation applies at the repository or file level.
- If no violations are detected, `"violations": []` is returned.

## 8. Running Automated Tests & Linting

Run the unit and agent integration test suite using `pytest` or Python's built-in `unittest`:

```bash
# Run with pytest
pytest -v

# Or run with standard library unittest
python -m unittest discover -s tests -v
```

Run static code quality checks on this repository with Ruff:

```bash
ruff check .
```

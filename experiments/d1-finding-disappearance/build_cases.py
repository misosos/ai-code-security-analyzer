"""D1 scenario construction. Synthetic code only; nothing here is ever executed.

Each case is a tiny Git repository mutated in place from a ``base`` state to a
``cur`` state, plus a private copy of the trusted baseline rule file that some
cases mutate. The production ``rules/`` directory is only read.

The applied change of each case is the independent ground truth. Labels live in
``labels.json`` and were committed before any arm was run.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

RULE_FILE = "security-baseline.yml"
EVAL_RULE = "baseline.javascript-dynamic-eval"

HANDLER = """'use strict';

function parsePayload(input) {
  return eval(input);
}

function label(value) {
  return String(value);
}

module.exports = { parsePayload, label };
"""

# Control finding that no code change ever touches.
STABLE = """'use strict';

function compile(input) {
  return new Function(input);
}

module.exports = { compile };
"""

# Two byte-identical dangerous lines in one file (lines 4 and 8).
TWIN = """'use strict';

function parseFirst(input) {
  return eval(input);
}

function parseSecond(input) {
  return eval(input);
}

module.exports = { parseFirst, parseSecond };
"""

CASES = ("A", "B", "C", "Da", "Db", "E", "F", "G", "H", "Ia", "Ib", "J", "Ka", "Kb")


def _git(repo: Path, *args: str) -> str:
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(repo.parent),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    }
    done = subprocess.run(
        ["git", "-c", "user.name=d1", "-c", "user.email=d1@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
        cwd=repo, env=env, check=True, capture_output=True, text=True,
    )
    return done.stdout


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise RuntimeError(f"fixture edit precondition failed: {path.name}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def build_base(case: str, repo: Path, rules_dir: Path, production_rules: Path) -> str:
    """Create the base state and return its commit id."""
    if case not in CASES:
        raise ValueError(case)
    repo.mkdir(parents=True)
    rules_dir.mkdir(parents=True)
    shutil.copyfile(production_rules / RULE_FILE, rules_dir / RULE_FILE)
    _git(repo, "init", "-q", "-b", "main")
    _write(repo / "src" / "stable.js", STABLE)
    if case == "Da":
        _write(repo / "src" / "handler.js", TWIN)
    elif case == "Db":
        _write(repo / "src" / "a.js", HANDLER)
        _write(repo / "src" / "b.js", HANDLER)
    else:
        _write(repo / "src" / "handler.js", HANDLER)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return _git(repo, "rev-parse", "HEAD").strip()


def apply_change(case: str, repo: Path, rules_dir: Path) -> str:
    """Apply the case's change in place, commit repository changes, return commit id."""
    handler = repo / "src" / "handler.js"
    rules = rules_dir / RULE_FILE
    safe = "  return JSON.parse(input);\n"
    evasive = "  return globalThis.eval(input);\n"
    dangerous = "  return eval(input);\n"
    if case == "A":
        _replace_once(handler, dangerous, safe)
    elif case == "B":
        _replace_once(handler, "'use strict';\n", "'use strict';\n// reviewed in D1\n")
    elif case == "C":
        _git(repo, "mv", "src/handler.js", "src/payload-handler.js")
    elif case == "Da":
        _replace_once(handler, "function parseFirst(input) {\n  return eval(input);\n}\n\n", "")
        _replace_once(handler, "{ parseFirst, parseSecond }", "{ parseSecond }")
    elif case == "Db":
        (repo / "src" / "b.js").unlink()
    elif case == "E":
        _write(repo / ".semgrepignore", "src/handler.js\n")
    elif case == "F":
        _git(repo, "rm", "-q", "--cached", "src/handler.js")
        _write(repo / ".gitignore", "src/handler.js\n")
    elif case == "G":
        text = rules.read_text(encoding="utf-8")
        start = text.index(f"  - id: {EVAL_RULE}\n")
        end = text.index("  - id: baseline.react-dangerous-html\n")
        if not start < end:
            raise RuntimeError("rule fixture precondition failed")
        rules.write_text(text[:start] + text[end:], encoding="utf-8")
    elif case == "H":
        _replace_once(rules, "          - pattern: eval(...)\n", "")
        _replace_once(rules, "          - pattern: ($X, eval)(...)\n", "")
    elif case == "Ia":
        with handler.open("a", encoding="utf-8") as stream:
            stream.write("\nconst = ;\nfunction ( {\n")
    elif case == "Ib":
        with rules.open("a", encoding="utf-8") as stream:
            stream.write("\n  broken: [unclosed\n")
    elif case == "J":
        _replace_once(handler, dangerous, evasive)
    elif case == "Ka":
        _replace_once(handler, dangerous, safe)
        _write(repo / ".semgrepignore", "src/handler.js\n")
    elif case == "Kb":
        _replace_once(handler, dangerous, evasive)
        _write(repo / ".semgrepignore", "src/handler.js\n")
    else:
        raise ValueError(case)
    _git(repo, "add", "-A")
    # Rule-only cases leave the repository unchanged; keep one commit per state anyway.
    _git(repo, "commit", "-q", "--allow-empty", "-m", "cur")
    return _git(repo, "rev-parse", "HEAD").strip()

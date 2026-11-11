"""D2 scenario construction. Synthetic code only; nothing here is ever executed.

The dangerous-looking snippets below are inert SAST fixtures: they are written
to disk and read by Semgrep, never imported or run.

Each case is one scan of one tiny Git repository with a private copy of the
trusted baseline rule file. The production ``rules/`` directory is only read.
The way each case is constructed is the independent ground truth (labels.json).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

RULE_FILE = "security-baseline.yml"
EVAL_RULE = "baseline.javascript-dynamic-eval"

DANGEROUS = """'use strict';

function parsePayload(input) {
  return eval(input);
}

module.exports = { parsePayload };
"""

CLEAN = """'use strict';

function parsePayload(input) {
  return JSON.parse(input);
}

module.exports = { parsePayload };
"""

# Only dangerous code in the tree, inside a file that cannot be parsed cleanly.
BROKEN_DANGEROUS = """'use strict';

function parsePayload(input) {
  return eval(input);
}

const = ;
function ( {
"""

BROKEN_RULE = """
  - id: d2.broken-pattern
    languages: [javascript]
    severity: WARNING
    message: D2 fixture rule with a pattern that does not parse.
    pattern: "eval("
"""

SLOW_RULE = """
  - id: d2.slow-pattern
    languages: [javascript]
    severity: WARNING
    message: D2 fixture rule intended to exceed the per-file rule timeout.
    pattern: |
      $A = $F(...);
      ...
      $B = $G(...);
      ...
      $C = $H(...);
      ...
      $D = $I(...);
      ...
      $E($A, $B, $C, $D);
"""

CASES = ("A", "B", "Bs", "C", "Cd", "D", "E", "F1", "F2", "Gt", "Go",
         "H", "Hp", "Hm", "Hn", "I1", "I2", "J")


def _git(repo: Path, *args: str) -> None:
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(repo.parent),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    }
    subprocess.run(
        ["git", "-c", "user.name=d2", "-c", "user.email=d2@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
        cwd=repo, env=env, check=True, capture_output=True, text=True,
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build(case: str, root: Path, production_rules: Path) -> dict[str, Path]:
    """Create the case and return the repository, the scan target and the rules directory."""
    if case not in CASES:
        raise ValueError(case)
    repo, rules_dir = root / "repo", root / "rules"
    repo.mkdir(parents=True)
    rules_dir.mkdir(parents=True)
    rules = rules_dir / RULE_FILE
    shutil.copyfile(production_rules / RULE_FILE, rules)
    _git(repo, "init", "-q", "-b", "main")
    target = repo
    untracked: dict[str, str] = {}

    if case == "A":
        _write(repo / "src" / "found.js", DANGEROUS)
        _write(repo / "src" / "broken.js", CLEAN + "\nconst = ;\nfunction ( {\n")
    elif case == "B":
        _write(repo / "src" / "ok.js", CLEAN)
        _write(repo / "src" / "broken.js", BROKEN_DANGEROUS)
    elif case == "Bs":
        _write(repo / "src" / "ok.js", CLEAN)
        padding = "// generated bundle padding line used only to exceed the size limit\n" * 20_000
        _write(repo / "src" / "bundle.js", DANGEROUS + padding)
    elif case == "C":
        _write(repo / "src" / "ok.js", CLEAN)
        _write(repo / "src" / "legacy.js", DANGEROUS)
        _write(repo / ".semgrepignore", "src/legacy.js\n")
    elif case == "Cd":
        _write(repo / "src" / "ok.js", CLEAN)
        _write(repo / "tests" / "helpers" / "run.js", DANGEROUS)
    elif case == "D":
        _write(repo / "src" / "ok.js", CLEAN)
        _write(repo / ".gitignore", "src/generated.js\n")
        untracked["src/generated.js"] = DANGEROUS
    elif case == "E":
        _write(repo / "src" / "found.js", DANGEROUS)
        with rules.open("a", encoding="utf-8") as stream:
            stream.write("\n  broken: [unclosed\n")
    elif case == "F1":
        _write(repo / "src" / "found.js", DANGEROUS)
        with rules.open("a", encoding="utf-8") as stream:
            stream.write(BROKEN_RULE)
    elif case == "F2":
        _write(repo / "src" / "found.js", DANGEROUS)
        text = rules.read_text(encoding="utf-8")
        start = text.index(f"  - id: {EVAL_RULE}\n")
        end = text.index("  - id: baseline.react-dangerous-html\n")
        rules.write_text(text[:start] + text[end:], encoding="utf-8")
    elif case == "Gt":
        _write(repo / "src" / "found.js", DANGEROUS)
        body = "".join(f"v{n} = fn{n}({n});\n" for n in range(2_500))
        _write(repo / "src" / "wide.js", "'use strict';\n" + body)
        with rules.open("a", encoding="utf-8") as stream:
            stream.write(SLOW_RULE)
    elif case == "Go":
        body = "".join(f"out{n} = eval(input{n});\n" for n in range(5_000))
        _write(repo / "src" / "many.js", "'use strict';\n" + body)
    elif case == "H":
        _write(repo / "src" / "ok.js", CLEAN)
        _write(repo / "src" / "other.js", CLEAN)
    elif case == "Hp":
        _write(repo / "src" / "ok.js", CLEAN)
        _write(repo / "src" / "found.js", DANGEROUS)
    elif case == "Hm":
        _write(repo / "src" / "ok.js", CLEAN)
        _write(repo / "tools" / "build.py", "def build():\n    return 1\n")
        _write(repo / "README.md", "# sample\n")
    elif case == "Hn":
        _write(repo / "src" / "ok.js", CLEAN)
        _write(repo / "node_modules" / "dep" / "index.js", DANGEROUS)
    elif case == "I1":
        _write(repo / "src" / "found.js", DANGEROUS)
        _write(repo / "docs" / "guide.md", "# guide\n")
        target = repo / "docs"
    elif case == "I2":
        _write(repo / "src" / "found.js", DANGEROUS)
        target = repo / "srcc"
    elif case == "J":
        _write(repo / "src" / "fixed.js", CLEAN)
        _write(repo / "src" / "legacy.js", DANGEROUS)
        _write(repo / ".semgrepignore", "src/legacy.js\n")

    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "state")
    for relative, text in untracked.items():
        _write(repo / relative, text)
    return {"repo": repo, "target": target, "rules_dir": rules_dir}

"""P6-A research harness: A8 dynamic-eval false negative.

Research only. Reads the production rule file without modifying it, derives
ablation and candidate rule variants from its exact text, and runs Semgrep on
synthetic corpora copied into a temporary directory. Uses only the standard
library and the Semgrep CLI already required by the project.

    uv run --locked python experiments/p6a-dynamic-eval/run_p6a.py \
        [--r1-root DIR] [--timing-runs N]

`--r1-root` points at an exported copy of `experiments/r1-detection` from the
research commit ff88612 (cases/ + labels.json). It is optional.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BASELINE_RULES = REPO / "rules" / "security-baseline.yml"
BASELINE_SHA256 = "77d085dd4901863f8873c987f70d6ccd376ab33590724a1389885df09d5ff9df"
RULE_ID = "baseline.javascript-dynamic-eval"
FIXTURE = REPO / "tests" / "fixtures" / "dynamic_eval_rule_test" / "dynamic-eval.js"
BENCHMARK_ROOTS = {
    "6A": REPO / "tests" / "benchmark" / "cases",
    "6D": REPO / "tests" / "benchmark" / "phase6d",
    "6E": REPO / "tests" / "benchmark" / "phase6e",
}
SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
R1_IN_SCOPE = {"GE_DIRECT", "GE_INDIRECT", "FC", "NEG"}  # NEG holds the in-scope negative sites

EXCLUSION_EVAL_PARAM = "      - pattern-not-inside: |\n          function $F(..., eval, ...) { ... }\n"
EXCLUSION_FUNCTION_PARAM = "      - pattern-not-inside: |\n          function $F(..., Function, ...) { ... }\n"
EXCLUSION_CONST = "      - pattern-not-inside: |\n          const eval = $V;\n          ...\n"
EXCLUSION_LET = "      - pattern-not-inside: |\n          let eval = $V;\n          ...\n"
SYMBOLIC_PROPAGATION = re.compile(r"    options:\n(?:      #.*\n)*      symbolic_propagation: true\n")

CANDIDATE_A_BRANCH = """      - patterns:
          - pattern-either:
              - pattern-inside: |
                  const eval = globalThis.eval;
                  ...
              - pattern-inside: |
                  let eval = globalThis.eval;
                  ...
              - pattern-inside: |
                  const eval = window.eval;
                  ...
              - pattern-inside: |
                  let eval = window.eval;
                  ...
          - pattern: eval(...)
          - pattern-not-inside: |
              function $F(..., eval, ...) { ... }
"""
CANDIDATE_B_BRANCH = """      - pattern-either:
          - pattern: globalThis.eval(...)
          - pattern: window.eval(...)
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def baseline_block() -> str:
    data = BASELINE_RULES.read_bytes()
    if sha256(data) != BASELINE_SHA256:
        raise SystemExit("baseline rule file changed; update the research record before rerunning")
    text = data.decode("utf-8")
    start = text.index(f"  - id: {RULE_ID}\n")
    end = text.index("\n  - id: ", start + 1) + 1
    return text[start:end]


def remove_once(block: str, fragment: str | re.Pattern[str]) -> str:
    if isinstance(fragment, re.Pattern):
        updated, count = fragment.subn("", block)
    else:
        count = block.count(fragment)
        updated = block.replace(fragment, "")
    if count != 1:
        raise SystemExit(f"expected exactly one occurrence while deriving a variant, found {count}")
    return updated


def with_branch(block: str, branch: str) -> str:
    head, body = block.split("    patterns:\n", 1)
    nested = "".join(f"    {line}" if line.strip() else line for line in body.splitlines(keepends=True))
    return f"{head}    pattern-either:\n      - patterns:\n{nested}{branch}"


def variants() -> dict[str, tuple[str, str]]:
    block = baseline_block()
    without_const_let = remove_once(remove_once(block, EXCLUSION_CONST), EXCLUSION_LET)
    return {
        "R0": ("Production rule, unchanged", block),
        "X1": ("Ablation: no `eval` parameter exclusion", remove_once(block, EXCLUSION_EVAL_PARAM)),
        "X2": ("Ablation: no `Function` parameter exclusion", remove_once(block, EXCLUSION_FUNCTION_PARAM)),
        "X3": ("Ablation: no `const eval = $V` exclusion", remove_once(block, EXCLUSION_CONST)),
        "X4": ("Ablation: no `let eval = $V` exclusion", remove_once(block, EXCLUSION_LET)),
        "X5": ("Ablation: no symbolic propagation", remove_once(block, SYMBOLIC_PROPAGATION)),
        "CA": ("Candidate A: re-include const/let eval bound to globalThis.eval or window.eval", with_branch(block, CANDIDATE_A_BRANCH)),
        "CB": ("Candidate B: globalThis.eval / window.eval call branch via symbolic propagation", with_branch(block, CANDIDATE_B_BRANCH)),
        "CC": ("Candidate C: drop const/let exclusions", without_const_let),
    }


def write_rule_files(variant_map: dict[str, tuple[str, str]], check: bool) -> dict[str, str]:
    rule_dir = HERE / "rules"
    rule_dir.mkdir(exist_ok=True)
    hashes: dict[str, str] = {}
    for name, (description, block) in variant_map.items():
        text = f"# P6-A research variant {name}: {description}\n# Derived by run_p6a.py from rules/security-baseline.yml ({BASELINE_SHA256[:12]}); not a product rule.\nrules:\n{block}"
        path = rule_dir / f"{name}.yml"
        if check and path.exists() and path.read_text() != text:
            raise SystemExit(f"committed variant {path.name} differs from the derived text")
        path.write_text(text)
        hashes[name] = sha256(text.encode("utf-8"))
    return hashes


def copy_sources(source: Path, destination: Path) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_file() and path.suffix in SOURCE_SUFFIXES:
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)


def semgrep_env(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home),
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    }


def run_semgrep(rule: Path, root: Path, env: dict[str, str]) -> tuple[set[tuple[str, int, int]], list[str], int]:
    completed = subprocess.run(
        ["semgrep", "scan", "--config", str(rule), "--json", "--metrics=off", "--disable-version-check",
         "--no-git-ignore", "--quiet", str(root)],
        capture_output=True, text=True, env=env, cwd=root, timeout=600, check=False,
    )
    if completed.returncode not in (0, 1):
        raise SystemExit(f"semgrep failed for {rule.name}: exit {completed.returncode}")
    payload = json.loads(completed.stdout)
    matches = {
        (str(Path(item["path"]).resolve().relative_to(root.resolve())), item["start"]["line"], item["start"]["col"])
        for item in payload["results"] if item["check_id"].endswith(RULE_ID)
    }
    # Keep only the file name and error kind; Semgrep error payloads embed absolute temporary paths.
    errors = sorted({f"{Path(item.get('path', '?')).name}: {item['type'][0] if isinstance(item.get('type'), list) else item.get('type', '?')}"
                     for item in payload["errors"]})
    return matches, errors, len(payload["paths"]["scanned"])


OUTCOME_KEYS = {
    "positive": ("TP", "FN"),
    "negative": ("FP", "TN"),
    "undetermined": ("undetermined_reported", "undetermined_silent"),
    "invalid_program": ("invalid_reported", "invalid_silent"),
}


def score(labels: list[dict], matches: set[tuple[str, int, int]], prefix: str) -> dict:
    """Score labelled sites. Only positive and negative sites enter TP/FP/FN/TN; the others are counted separately."""
    counts = {key: 0 for pair in OUTCOME_KEYS.values() for key in pair}
    denominators = {label: 0 for label in OUTCOME_KEYS}
    sites = {}
    for site in labels:
        label = site["label"]
        if label not in OUTCOME_KEYS:
            raise SystemExit(f"unknown label {label!r} for {site['id']}")
        reported = (f"{prefix}/{site['file']}", site["line"], site["column"]) in matches
        key = OUTCOME_KEYS[label][0 if reported else 1]
        counts[key] += 1
        denominators[label] += 1
        sites[site["id"]] = key
    if sum(counts.values()) != len(labels) or sum(denominators.values()) != len(labels):
        raise SystemExit("scoring lost or double-counted a site")
    denominators["scored_in_confusion_matrix"] = denominators["positive"] + denominators["negative"]
    denominators["total_sites"] = len(labels)
    return {"counts": counts, "denominators": denominators, "sites": sites}


def p6a_sites() -> list[dict]:
    labels = json.loads((HERE / "labels.json").read_text())
    return [{**site, "id": site["case"]} for site in labels["sites"]]


def r1_sites(r1_root: Path) -> list[dict]:
    labels = json.loads((r1_root / "labels.json").read_text())
    sites = []
    for set_name, entry in labels["sets"].items():
        for site in entry["sites"]:
            if site["category"] not in R1_IN_SCOPE or site["label"] not in {"positive", "negative"}:
                continue
            line_text = (r1_root / "cases" / set_name / site["file"]).read_text().splitlines()[site["line"] - 1]
            occurrence, start = site.get("occurrence", 1), -1
            for _ in range(occurrence):
                start = line_text.index(site["anchor"], start + 1)
            sites.append({"id": f"{set_name}/{site['file']}:{site['line']}:{occurrence}", "set": set_name, "file": f"{set_name}/{site['file']}",
                          "line": site["line"], "column": start + 1, "label": site["label"]})
    return sites


def fixture_annotations() -> list[dict]:
    lines = FIXTURE.read_text().splitlines()
    pattern = re.compile(rf"//\s*(ruleid|ok|todoruleid|todook):\s*{re.escape(RULE_ID)}")
    annotations = []
    for index, line in enumerate(lines):
        found = pattern.search(line)
        if found:
            annotations.append({"kind": found.group(1), "line": index + 2, "code": lines[index + 1].strip()})
    return annotations


def native_rule_test(rule: Path, fixture_copy: Path, env: dict[str, str]) -> str:
    completed = subprocess.run(
        ["semgrep", "--test", "--metrics=off", "--disable-version-check", "--config", str(rule), str(fixture_copy)],
        capture_output=True, text=True, env=env, timeout=600, check=False,
    )
    output = completed.stdout + completed.stderr
    summary = [line.strip() for line in output.splitlines() if re.search(r"(passed|failed|missed|incorrect)", line)]
    return f"exit={completed.returncode}; " + " | ".join(summary[-3:])


EVIDENCE_INSIDE_CONST = f"""  - id: {RULE_ID}
    languages: [javascript, typescript]
    severity: ERROR
    message: "P6-A-R evidence probe: eval(...) is inside the region `const eval = $V; ...`"
    options:
      symbolic_propagation: true
    patterns:
      - pattern: eval(...)
      - pattern-inside: |
          const eval = $V;
          ...
"""


def evidence_variants() -> dict[str, tuple[str, str]]:
    block = baseline_block()
    positive_only = block
    for fragment in (EXCLUSION_EVAL_PARAM, EXCLUSION_FUNCTION_PARAM, EXCLUSION_CONST, EXCLUSION_LET):
        positive_only = remove_once(positive_only, fragment)
    return {
        "E1": ("Evidence: eval(...) inside the `const eval = $V; ...` region, capturing $V", EVIDENCE_INSIDE_CONST),
        "E2": ("Evidence: production positive patterns with all four exclusions removed", positive_only),
    }


def evidence_run(rule: Path, cases_root: Path, env: dict[str, str]) -> dict[str, dict]:
    completed = subprocess.run(
        ["semgrep", "scan", "--config", str(rule), "--json", "--metrics=off", "--disable-version-check",
         "--no-git-ignore", "--quiet", str(cases_root)],
        capture_output=True, text=True, env=env, cwd=cases_root, timeout=600, check=False,
    )
    if completed.returncode not in (0, 1):
        raise SystemExit(f"semgrep failed for {rule.name}: exit {completed.returncode}")
    found: dict[str, dict] = {}
    for item in json.loads(completed.stdout)["results"]:
        case = Path(item["path"]).stem
        # Semgrep interpolates the bound $V into the message; pattern-inside metavariables are not in extra.metavars.
        message = item["extra"].get("message", "")
        bound = message.split("const eval = ", 1)[1].rsplit("; ...", 1)[0] if "const eval = " in message else None
        found[f"{case}:{item['start']['line']}:{item['start']['col']}"] = {"V": bound}
    return found


CALLEE = re.compile(r"Call\(\s*(Special\(\((\w+)|N\(\s*Id\(\(\"([^\"]+)\"|DotAccess)")


def ast_callees(path: Path, env: dict[str, str]) -> list[str]:
    completed = subprocess.run(["semgrep", "--dump-ast", "-l", "js", str(path)], capture_output=True, text=True,
                               env=env, timeout=120, check=True)
    flat = re.sub(r"\s+", " ", completed.stdout)
    shapes = []
    for match in CALLEE.finditer(flat):
        if match.group(2):
            shapes.append(f"Call(Special({match.group(2)}))")
        elif match.group(3):
            shapes.append(f"Call(Id({match.group(3)}))")
        else:
            shapes.append("Call(DotAccess)")
    return shapes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--r1-root", type=Path)
    parser.add_argument("--timing-runs", type=int, default=5)
    parser.add_argument("--check-rules", action="store_true", help="fail if committed variant files differ")
    args = parser.parse_args()

    variant_map = variants()
    evidence_map = evidence_variants()
    rule_hashes = write_rule_files({**variant_map, **evidence_map}, args.check_rules)
    version = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
    if version != "1.182.1":
        raise SystemExit(f"Semgrep 1.182.1 required, found {version}")

    with tempfile.TemporaryDirectory(prefix="p6a-") as temp:
        workspace = Path(temp) / "workspace"
        home = Path(temp) / "home"
        home.mkdir()
        env = semgrep_env(home)
        copy_sources(HERE / "cases", workspace / "p6a" / "cases")
        (workspace / "fixture").mkdir(parents=True)
        shutil.copyfile(FIXTURE, workspace / "fixture" / FIXTURE.name)
        for name, root in BENCHMARK_ROOTS.items():
            copy_sources(root, workspace / "bench" / name)
        r1 = r1_sites(args.r1_root) if args.r1_root else []
        if args.r1_root:
            copy_sources(args.r1_root / "cases", workspace / "r1")
        fixture_copy = Path(temp) / "native" / FIXTURE.name
        fixture_copy.parent.mkdir()
        shutil.copyfile(FIXTURE, fixture_copy)

        p6a = p6a_sites()
        annotations = fixture_annotations()
        # One untimed warm-up so the first variant is not charged for cold caches.
        run_semgrep(HERE / "rules" / "R0.yml", workspace, env)
        results: dict = {"semgrep_version": version, "baseline_rule_sha256": BASELINE_SHA256,
                         "rule_variant_sha256": rule_hashes, "variants": {}, "evidence": {}}
        timing: dict = {"note": "Wall-clock seconds; varies with machine load. Not a performance claim.", "variants": {}}
        cases_root = workspace / "p6a" / "cases"
        for name, (description, _block) in evidence_map.items():
            results["evidence"][name] = {"description": description,
                                         "matches": evidence_run(HERE / "rules" / f"{name}.yml", cases_root, env)}
        results["evidence"]["ast_callees"] = {
            case: ast_callees(cases_root / f"{case}.js", env)
            for case in ("P01_direct_eval", "P03_alias", "P05_a8_const_global_this", "P13_member_alias")
        }
        baseline_matches: set[tuple[str, int, int]] = set()
        for name, (description, _block) in variant_map.items():
            rule = HERE / "rules" / f"{name}.yml"
            matches, errors, scanned = run_semgrep(rule, workspace, env)
            if name == "R0":
                baseline_matches = matches
            fixture_lines = {line for path, line, _col in matches if path == f"fixture/{FIXTURE.name}"}
            fixture = [{**item, "reported": item["line"] in fixture_lines} for item in annotations]
            bench_delta = {
                corpus: {
                    "added": sorted(f"{p}:{l}:{c}" for p, l, c in matches - baseline_matches if p.startswith(f"bench/{corpus}/")),
                    "removed": sorted(f"{p}:{l}:{c}" for p, l, c in baseline_matches - matches if p.startswith(f"bench/{corpus}/")),
                }
                for corpus in BENCHMARK_ROOTS
            }
            timings = []
            for _ in range(args.timing_runs):
                started = time.perf_counter()
                run_semgrep(rule, workspace, env)
                timings.append(time.perf_counter() - started)
            results["variants"][name] = {
                "description": description,
                "semgrep_errors": errors,
                "files_scanned": scanned,
                "p6a": score(p6a, matches, "p6a"),
                "r1": {set_name: score([s for s in r1 if s["set"] == set_name], matches, "r1") for set_name in ("dev", "heldout")} if r1 else None,
                "fixture": fixture,
                "fixture_ruleid_ok_violations": [f"{item['kind']}@{item['line']}" for item in fixture
                                                  if (item["kind"] == "ruleid" and not item["reported"])
                                                  or (item["kind"] == "ok" and item["reported"])],
                "native_rule_test": native_rule_test(rule, fixture_copy, env),
                "benchmark_delta_vs_R0": bench_delta,
            }
            timing["variants"][name] = {"runs": [round(value, 3) for value in timings],
                                        "median": round(statistics.median(timings), 3)}
    out = HERE / "results" / "results.json"
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    (HERE / "results" / "timing.json").write_text(json.dumps(timing, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out.relative_to(REPO)} and results/timing.json")
    for name, item in results["variants"].items():
        p, d = item["p6a"]["counts"], item["p6a"]["denominators"]
        r1_text = " ".join(f"{k}:TP={v['counts']['TP']}/FP={v['counts']['FP']}/FN={v['counts']['FN']}/TN={v['counts']['TN']}"
                           for k, v in (item["r1"] or {}).items()) or "n/a"
        print(f"{name}: P6A pos={d['positive']} TP={p['TP']} FN={p['FN']} neg={d['negative']} FP={p['FP']} TN={p['TN']} "
              f"undet={d['undetermined']} U+={p['undetermined_reported']} invalid={d['invalid_program']} I+={p['invalid_reported']} "
              f"| R1 {r1_text} "
              f"| fixture violations={item['fixture_ruleid_ok_violations']} | errors={item['semgrep_errors']} "
              f"| median={timing['variants'][name]['median']}s")


if __name__ == "__main__":
    main()

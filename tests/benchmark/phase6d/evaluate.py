"""Independent, static-only evaluation of the Phase 6D synthetic corpus."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DATA_ROOT = Path(__file__).resolve().parent
CASES_ROOT = DATA_ROOT / "cases"
DATASET_VERSION = "phase6d-generalization-v1"
EXPECTED_SEMGREP_VERSION = "1.182.1"
MANIFEST_SHA256 = "3dff49a55a61fede2021afc224f037e53502a77def1f12d3d994893dda4d6cc8"
ORACLE_SHA256 = "0d70ef57a247e31bb8bbea1258069a649ae5ead764f2a423e938c7e05e0c4ea8"
ORIGINAL_ORACLE_SHA256 = "af911e6c2a02d23e4ce6dcee970931002360ec13c40600964dcdd724f88df2e3"
ORACLE_CORRECTIONS_SHA256 = "f0748cf517cfc1ac99e47c77ab9e97319e126c2131931931dc7db24f3b4d5a00"

RULE_PROFILES: dict[str, tuple[str, str]] = {
    "baseline.javascript-dynamic-eval": ("baseline", "js_eval"),
    "baseline.react-dangerous-html": ("baseline", "react_html"),
    "baseline.firestore-unconditional-write": ("baseline", "firestore"),
    "experimental.javascript-eval-taint": ("eval_taint", "eval_taint"),
    "experimental.javascript-eval-taint-with-synthetic-sanitizer": ("eval_taint", "eval_taint"),
    "experimental.javascript-command-injection-taint": ("command_injection", "command_injection"),
}
SIGNALS = {"positive", "negative", "out_of_scope"}
RELEVANCE = {"review_worthy", "lower_priority", "undetermined"}
PROFILES = {
    "baseline": "rules/security-baseline.yml",
    "eval_taint": "rules/experimental/javascript-eval-taint.yml",
    "command_injection": "rules/experimental/javascript-command-injection-taint.yml",
}


class EvaluationInputError(ValueError):
    """Stable, non-sensitive error for malformed benchmark inputs."""


@dataclass(frozen=True)
class Case:
    case_id: str
    category: str
    language: str
    path: str
    expected_rule_signals: dict[str, str]
    expected_matches: dict[str, tuple[tuple[str, int], ...]]
    expected_cardinality: dict[str, int]
    security_review_relevance: str
    rationale: str
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class Dataset:
    version: str
    cases: tuple[Case, ...]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise EvaluationInputError("benchmark_input_invalid") from None
    if not isinstance(value, dict):
        raise EvaluationInputError("benchmark_schema_invalid")
    return value


def load_dataset(
    manifest_path: Path = DATA_ROOT / "manifest.json",
    oracle_path: Path = DATA_ROOT / "oracle.json",
) -> Dataset:
    """Validate pinned metadata and ensure every case path stays in the corpus."""
    if manifest_path == DATA_ROOT / "manifest.json" and oracle_path == DATA_ROOT / "oracle.json":
        try:
            manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            oracle_hash = hashlib.sha256(oracle_path.read_bytes()).hexdigest()
        except OSError:
            raise EvaluationInputError("benchmark_input_invalid") from None
        if manifest_hash != MANIFEST_SHA256 or oracle_hash != ORACLE_SHA256:
            raise EvaluationInputError("benchmark_integrity_invalid")
        try:
            original_hash = hashlib.sha256((DATA_ROOT / "oracle-v1-original.json").read_bytes()).hexdigest()
        except OSError:
            raise EvaluationInputError("benchmark_input_invalid") from None
        if original_hash != ORIGINAL_ORACLE_SHA256:
            raise EvaluationInputError("benchmark_integrity_invalid")
        try:
            correction_hash = hashlib.sha256((DATA_ROOT / "oracle-corrections.json").read_bytes()).hexdigest()
        except OSError:
            raise EvaluationInputError("benchmark_input_invalid") from None
        if correction_hash != ORACLE_CORRECTIONS_SHA256:
            raise EvaluationInputError("benchmark_integrity_invalid")
    manifest, oracle = _read_json(manifest_path), _read_json(oracle_path)
    if set(manifest) != {"evaluation_set_version", "case_count", "cases"}:
        raise EvaluationInputError("benchmark_schema_invalid")
    if set(oracle) != {"evaluation_set_version", "case_count", "cases", "confirmed_vulnerability"}:
        raise EvaluationInputError("benchmark_schema_invalid")
    if (manifest["evaluation_set_version"] != DATASET_VERSION
            or oracle["evaluation_set_version"] != DATASET_VERSION
            or oracle["confirmed_vulnerability"] != "NOT_EVALUATED"):
        raise EvaluationInputError("benchmark_version_invalid")
    if not isinstance(manifest["cases"], list) or not isinstance(oracle["cases"], list):
        raise EvaluationInputError("benchmark_schema_invalid")
    if manifest["case_count"] != 50 or oracle["case_count"] != 50:
        raise EvaluationInputError("benchmark_count_invalid")
    if len(manifest["cases"]) != 50 or len(oracle["cases"]) != 50:
        raise EvaluationInputError("benchmark_count_invalid")

    manifest_by_id: dict[str, dict[str, Any]] = {}
    case_file_lines: dict[str, dict[str, int]] = {}
    categories = {category for _, category in RULE_PROFILES.values()}
    for item in manifest["cases"]:
        if not isinstance(item, dict) or set(item) != {"case_id", "category", "language", "path", "files"}:
            raise EvaluationInputError("benchmark_schema_invalid")
        case_id, category, language, relative = (item[key] for key in ("case_id", "category", "language", "path"))
        if (not isinstance(case_id, str) or not case_id.isascii() or not case_id.replace("_", "").isalnum()
                or case_id in manifest_by_id or category not in categories):
            raise EvaluationInputError("benchmark_case_invalid")
        if language not in {"javascript", "typescript", "firestore_rules"}:
            raise EvaluationInputError("benchmark_language_invalid")
        if (not isinstance(relative, str) or "\\" in relative or Path(relative).is_absolute()
                or Path(relative).as_posix() != relative or any(p in {"", ".", ".."} for p in Path(relative).parts)):
            raise EvaluationInputError("benchmark_path_invalid")
        expected_prefix = f"cases/{category}/{case_id}"
        if relative != expected_prefix:
            raise EvaluationInputError("benchmark_path_invalid")
        candidate = DATA_ROOT / relative
        if candidate.is_symlink() or not candidate.is_dir():
            raise EvaluationInputError("benchmark_path_invalid")
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(CASES_ROOT.resolve())
        except (OSError, ValueError, RuntimeError):
            raise EvaluationInputError("benchmark_path_invalid") from None
        listed_files = item["files"]
        if not isinstance(listed_files, list) or not listed_files or len(listed_files) > 20:
            raise EvaluationInputError("benchmark_case_empty")
        expected_files: dict[str, str] = {}
        for entry in listed_files:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                raise EvaluationInputError("benchmark_schema_invalid")
            rel, digest = entry["path"], entry["sha256"]
            if (not isinstance(rel, str) or "\\" in rel or Path(rel).is_absolute()
                    or Path(rel).as_posix() != rel
                    or any(part in {"", ".", ".."} for part in Path(rel).parts)
                    or not isinstance(digest, str) or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)
                    or rel in expected_files):
                raise EvaluationInputError("benchmark_path_invalid")
            expected_files[rel] = digest
        actual_files: set[str] = set()
        line_counts: dict[str, int] = {}
        for walk_root, directories, filenames in os.walk(resolved, followlinks=False):
            base = Path(walk_root)
            if any((base / name).is_symlink() for name in directories):
                raise EvaluationInputError("benchmark_path_invalid")
            for filename in filenames:
                source = base / filename
                if source.is_symlink() or not source.is_file():
                    raise EvaluationInputError("benchmark_path_invalid")
                rel = source.relative_to(resolved).as_posix()
                if rel in actual_files or len(actual_files) >= 20:
                    raise EvaluationInputError("benchmark_case_size_invalid")
                try:
                    data = source.read_bytes()
                    text = data.decode("utf-8")
                except (OSError, UnicodeError):
                    raise EvaluationInputError("benchmark_path_invalid") from None
                if len(data) > 65_536 or hashlib.sha256(data).hexdigest() != expected_files.get(rel):
                    raise EvaluationInputError("benchmark_fixture_integrity_invalid")
                actual_files.add(rel)
                line_counts[rel] = len(text.splitlines())
        if actual_files != set(expected_files):
            raise EvaluationInputError("benchmark_fixture_integrity_invalid")
        case_file_lines[case_id] = line_counts
        manifest_by_id[case_id] = item

    oracle_by_id: dict[str, dict[str, Any]] = {}
    parsed: list[Case] = []
    required = {
        "case_id", "category", "language", "path", "evaluation_set_version", "expected_rule_signals",
        "expected_matches", "expected_cardinality", "security_review_relevance", "rationale", "limitations",
    }
    for item in oracle["cases"]:
        if not isinstance(item, dict) or set(item) != required:
            raise EvaluationInputError("benchmark_schema_invalid")
        case_id = item["case_id"]
        manifest_case = manifest_by_id.get(case_id) if isinstance(case_id, str) else None
        if manifest_case is None or case_id in oracle_by_id:
            raise EvaluationInputError("benchmark_case_invalid")
        if (item["evaluation_set_version"] != DATASET_VERSION
                or item["category"] != manifest_case["category"]
                or item["language"] != manifest_case["language"]
                or item["path"] != manifest_case["path"]):
            raise EvaluationInputError("benchmark_case_mismatch")
        relevance = item["security_review_relevance"]
        if relevance not in RELEVANCE:
            raise EvaluationInputError("benchmark_relevance_invalid")
        rationale, limitations = item["rationale"], item["limitations"]
        if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 1000:
            raise EvaluationInputError("benchmark_rationale_invalid")
        if not isinstance(limitations, list) or not limitations or any(
            not isinstance(value, str) or not value.strip() or len(value) > 1000 for value in limitations
        ):
            raise EvaluationInputError("benchmark_limitations_invalid")
        signals, matches, cardinality = item["expected_rule_signals"], item["expected_matches"], item["expected_cardinality"]
        if not isinstance(signals, dict) or not isinstance(matches, dict) or not isinstance(cardinality, dict):
            raise EvaluationInputError("benchmark_oracle_invalid")
        if not signals or set(signals) != set(matches) or set(signals) != set(cardinality):
            raise EvaluationInputError("benchmark_oracle_invalid")
        parsed_matches: dict[str, tuple[tuple[str, int], ...]] = {}
        for rule_id, label in signals.items():
            if rule_id not in RULE_PROFILES or RULE_PROFILES[rule_id][1] != item["category"] or label not in SIGNALS:
                raise EvaluationInputError("benchmark_rule_label_invalid")
            expected = matches[rule_id]
            count = cardinality[rule_id]
            if not isinstance(expected, list) or type(count) is not int or not 0 <= count <= 20 or count != len(expected):
                raise EvaluationInputError("benchmark_cardinality_invalid")
            if (label == "positive" and count == 0) or (label != "positive" and count != 0):
                raise EvaluationInputError("benchmark_oracle_invalid")
            seen_locations: set[tuple[str, int]] = set()
            for location in expected:
                if not isinstance(location, dict) or set(location) != {"path", "line"}:
                    raise EvaluationInputError("benchmark_location_invalid")
                rel, line = location["path"], location["line"]
                if (not isinstance(rel, str) or Path(rel).is_absolute() or "\\" in rel
                        or Path(rel).as_posix() != rel or any(part in {"", ".", ".."} for part in Path(rel).parts)
                        or type(line) is not int or line < 1):
                    raise EvaluationInputError("benchmark_location_invalid")
                if rel not in case_file_lines[case_id] or line > case_file_lines[case_id][rel]:
                    raise EvaluationInputError("benchmark_location_invalid")
                pair = (rel, line)
                if pair in seen_locations:
                    raise EvaluationInputError("benchmark_location_duplicate")
                seen_locations.add(pair)
            parsed_matches[rule_id] = tuple((location["path"], location["line"]) for location in expected)
        oracle_by_id[case_id] = item
        parsed.append(Case(
            case_id=case_id, category=item["category"], language=item["language"], path=manifest_case["path"],
            expected_rule_signals=dict(signals), expected_matches=parsed_matches,
            expected_cardinality=dict(cardinality), security_review_relevance=relevance,
            rationale=rationale, limitations=tuple(limitations),
        ))
    if set(manifest_by_id) != set(oracle_by_id):
        raise EvaluationInputError("benchmark_case_mismatch")
    counts = Counter(case.category for case in parsed)
    if counts != Counter({"js_eval": 10, "react_html": 10, "firestore": 10, "eval_taint": 10, "command_injection": 10}):
        raise EvaluationInputError("benchmark_category_counts_invalid")
    return Dataset(DATASET_VERSION, tuple(sorted(parsed, key=lambda case: case.case_id)))


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _metrics(counts: Counter[str]) -> dict[str, int | float | None]:
    tp, fp, fn, tn = (counts[key] for key in ("TP", "FP", "FN", "TN"))
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
            "false_positive_rate": _ratio(fp, fp + tn)}


def score_rule(rule_id: str, cases: tuple[Case, ...], actual: dict[str, list[tuple[str, int]]]) -> dict[str, Any]:
    scoped = [case for case in cases if rule_id in case.expected_rule_signals]
    scored = [case for case in scoped if case.expected_rule_signals[rule_id] in {"positive", "negative"}]
    case_counts: Counter[str] = Counter()
    finding_counts: Counter[str] = Counter()
    duplicates = 0
    location_mismatches: list[dict[str, Any]] = []
    false_positives: list[dict[str, str]] = []
    false_negatives: list[dict[str, str]] = []
    out_of_scope_matches: list[dict[str, Any]] = []
    relevance_counts: Counter[str] = Counter()
    missed_review_worthy: list[str] = []
    for case in scoped:
        observed = list(actual.get(case.case_id, []))
        label = case.expected_rule_signals[rule_id]
        expected = list(case.expected_matches[rule_id])
        if label == "out_of_scope":
            if observed:
                out_of_scope_matches.append({"case_id": case.case_id, "match_count": len(observed)})
                relevance_counts[case.security_review_relevance] += len(observed)
            continue
        matched = bool(observed)
        if label == "positive":
            case_counts["TP" if matched else "FN"] += 1
            if not matched:
                false_negatives.append({"case_id": case.case_id, "failure_type": "missed_positive"})
                if case.security_review_relevance == "review_worthy":
                    missed_review_worthy.append(case.case_id)
        else:
            case_counts["FP" if matched else "TN"] += 1
            if matched:
                false_positives.append({"case_id": case.case_id, "failure_type": "reported_negative"})
        # Finding metrics are signal-count based; extras are duplicate/unexpected signals.
        if label == "positive":
            finding_counts["TP"] += min(len(observed), len(expected))
            finding_counts["FN"] += max(0, len(expected) - len(observed))
            finding_counts["FP"] += max(0, len(observed) - len(expected))
        else:
            finding_counts["FP"] += len(observed)
            finding_counts["TN"] += 1 if not observed else 0
        duplicates += max(0, len(observed) - len(expected))
        if sorted(observed) != sorted(expected):
            location_mismatches.append({"case_id": case.case_id, "expected_matches": expected, "actual_matches": observed})
        if observed:
            relevance_counts[case.security_review_relevance] += len(observed)
    return {
        "rule_id": rule_id,
        "category": RULE_PROFILES[rule_id][1],
        "case_count": len(scoped),
        "scored_case_count": len(scored),
        "out_of_scope_case_count": sum(case.expected_rule_signals[rule_id] == "out_of_scope" for case in scoped),
        "rule_signal_case_metrics": _metrics(case_counts),
        "finding_metrics": _metrics(finding_counts),
        "duplicate_findings": duplicates,
        "location_mismatches": location_mismatches,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "out_of_scope_matches": out_of_scope_matches,
        "reported_finding_relevance": {key: relevance_counts[key] for key in sorted(RELEVANCE)},
        "missed_review_worthy_cases": missed_review_worthy,
    }


def evaluate_results(dataset: Dataset, results: dict[str, Any]) -> dict[str, Any]:
    from ai_code_security_analyzer.semgrep_adapter import ScanStatus

    scan_runs: dict[str, dict[str, Any]] = {}
    observed: dict[str, dict[str, list[tuple[str, int]]]] = {rule: defaultdict(list) for rule in RULE_PROFILES}
    unexpected_rules: list[dict[str, str]] = []
    unmapped: list[dict[str, str]] = []
    cross_category: list[dict[str, str]] = []
    profile_rules = {profile: {rule for rule, (profile_id, _) in RULE_PROFILES.items() if profile_id == profile}
                     for profile in PROFILES}
    by_case_prefix = {case.path: case for case in dataset.cases}
    all_rule_ids = set(RULE_PROFILES)
    for profile, result in results.items():
        status = result.status.value if hasattr(result.status, "value") else str(result.status)
        scan_runs[profile] = {
            "scan_status": status, "semgrep_version": result.semgrep_version,
            "exit_code": result.exit_code, "issues": list(result.issues),
            "finding_count": len(result.findings),
        }
        for finding in result.findings:
            rule_id = str(finding.rule_id)
            if rule_id not in profile_rules.get(profile, set()):
                unexpected_rules.append({"profile": profile, "rule_id": rule_id})
                continue
            relative_path = Path(finding.file_path).as_posix()
            if not relative_path.startswith("cases/"):
                relative_path = f"cases/{relative_path}"
            case = next((item for prefix, item in by_case_prefix.items()
                         if relative_path == prefix or relative_path.startswith(prefix + "/")), None)
            if case is None:
                unmapped.append({"profile": profile, "rule_id": rule_id})
                continue
            category = RULE_PROFILES[rule_id][1]
            if rule_id not in case.expected_rule_signals:
                cross_category.append({"profile": profile, "rule_id": rule_id, "case_id": case.case_id})
                continue
            relative_to_case = relative_path[len(case.path):].lstrip("/")
            observed[rule_id][case.case_id].append((relative_to_case, finding.line_number or 0))
    all_runs_ok = set(results) == set(PROFILES) and all(
        run["scan_status"] == ScanStatus.COMPLETED.value
        and run["semgrep_version"] == EXPECTED_SEMGREP_VERSION
        and run["exit_code"] == 0
        for run in scan_runs.values()
    )
    # The adapter reports paths relative to the scanned directory, whose root
    # is the manifest's `cases/` directory. Any finding that cannot be mapped
    # to that frozen corpus invalidates the run instead of silently improving
    # or degrading its scores.
    metrics_available = all_runs_ok and not unexpected_rules and not unmapped
    metrics = {rule_id: score_rule(rule_id, dataset.cases, observed[rule_id])
               for rule_id in sorted(RULE_PROFILES)} if metrics_available else {}
    return {
        "evaluation_set_version": dataset.version,
        "manifest_sha256": MANIFEST_SHA256,
        "oracle_sha256": ORACLE_SHA256,
        "original_oracle_sha256": ORIGINAL_ORACLE_SHA256,
        "oracle_corrections_sha256": ORACLE_CORRECTIONS_SHA256,
        "expected_semgrep_version": EXPECTED_SEMGREP_VERSION,
        "metrics_available": metrics_available,
        "scan_runs": scan_runs,
        "metrics_by_rule": metrics,
        "unexpected_rule_ids": unexpected_rules,
        "unmapped_findings": unmapped,
        "cross_category_observations": cross_category,
        "rule_signal_is_not_vulnerability_confirmation": True,
        "confirmed_vulnerability": "NOT_EVALUATED",
    }


def run_evaluation(dataset: Dataset | None = None) -> dict[str, Any]:
    if shutil.which("semgrep") is None:
        raise EvaluationInputError("semgrep_not_installed")
    from ai_code_security_analyzer.semgrep_adapter import SemgrepAdapter

    dataset = dataset or load_dataset()
    results = {}
    with tempfile.TemporaryDirectory(prefix="phase6d-generalization-") as temporary:
        target = Path(temporary) / "cases"
        shutil.copytree(CASES_ROOT, target)
        for profile, relative_rules in PROFILES.items():
            adapter = SemgrepAdapter(ROOT / "rules")
            results[profile] = adapter.scan(target, ROOT / relative_rules)
    report = evaluate_results(dataset, results)
    report["rule_sha256"] = {
        rule: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for rule, path in {
            "baseline": PROFILES["baseline"],
            "eval_taint": PROFILES["eval_taint"],
            "command_injection": PROFILES["command_injection"],
        }.items()
    }
    return report


def main() -> int:
    try:
        report = run_evaluation()
    except EvaluationInputError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    except Exception:
        print(json.dumps({"error": "benchmark_execution_failed"}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["metrics_available"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

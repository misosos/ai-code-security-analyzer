"""Reproducible, local-only scoring for the Phase 6A synthetic benchmark."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_ROOT = Path(__file__).resolve().parent
CASES_ROOT = BENCHMARK_ROOT / "cases"
DATASET_VERSION = "phase6a-synthetic-v1"
EXPECTED_SEMGREP_VERSION = "1.182.1"
MANIFEST_SHA256 = "954f9e33359bdcd478a6edbdcc83b9aa8cb962c01e7e90c5b6f60ef1b2c23c53"
ORACLE_SHA256 = "d5c10325bb0ce38f9187739afb704287de1cdbab94e879d57ade152eb05e1747"

RULES: dict[str, tuple[str, str]] = {
    "baseline.javascript-dynamic-eval": ("js_eval", "rules/security-baseline.yml"),
    "baseline.react-dangerous-html": ("react_html", "rules/security-baseline.yml"),
    "baseline.firestore-unconditional-write": ("firestore", "rules/security-baseline.yml"),
    "experimental.javascript-eval-taint": ("eval_taint", "rules/experimental/javascript-eval-taint.yml"),
    "experimental.javascript-eval-taint-with-synthetic-sanitizer": (
        "eval_taint",
        "rules/experimental/javascript-eval-taint.yml",
    ),
    "experimental.javascript-command-injection-taint": (
        "command_injection",
        "rules/experimental/javascript-command-injection-taint.yml",
    ),
}
REQUIRED_MANIFEST_KEYS = {"evaluation_set_version", "case_count", "cases"}
REQUIRED_CASE_KEYS = {"case_id", "category", "language", "path"}
REQUIRED_ORACLE_KEYS = {"evaluation_set_version", "case_count", "cases"}
REQUIRED_ORACLE_CASE_KEYS = {
    "case_id",
    "category",
    "language",
    "evaluation_set_version",
    "expected_rule_signals",
    "security_review_relevance",
    "rationale",
    "expected_match_locations",
    "expected_cardinality",
    "known_limitations",
}
_CASE_ID = re.compile(r"^[A-Z][0-9]{2}_[A-Za-z0-9_]+$")
_RULE_ID = re.compile(r"^[a-z][a-z0-9_.-]+$")
_LANGUAGES = {"javascript", "typescript", "firestore_rules", "text"}
_RELEVANCE = {"review_worthy", "lower_priority", "undetermined"}
_LABELS = {"positive", "negative"}
_SAFE_TEXT_MAX = 1000


class BenchmarkInputError(ValueError):
    """A fixed, safe error for invalid local benchmark inputs."""


@dataclass(frozen=True)
class Case:
    case_id: str
    category: str
    language: str
    path: str
    expected_rule_signals: dict[str, str]
    expected_match_locations: dict[str, tuple[int, ...]]
    expected_cardinality: dict[str, int]
    security_review_relevance: str


@dataclass(frozen=True)
class Dataset:
    version: str
    cases: tuple[Case, ...]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise BenchmarkInputError("benchmark_input_invalid") from None
    if not isinstance(value, dict):
        raise BenchmarkInputError("benchmark_input_invalid")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str]) -> bool:
    return set(value) == expected


def load_dataset(
    manifest_path: Path = BENCHMARK_ROOT / "manifest.json",
    oracle_path: Path = BENCHMARK_ROOT / "oracle.json",
) -> Dataset:
    """Load a strict, path-confined manifest and independently-authored oracle."""
    if manifest_path == BENCHMARK_ROOT / "manifest.json" and oracle_path == BENCHMARK_ROOT / "oracle.json":
        try:
            manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            oracle_hash = hashlib.sha256(oracle_path.read_bytes()).hexdigest()
        except OSError:
            raise BenchmarkInputError("benchmark_input_invalid") from None
        if manifest_hash != MANIFEST_SHA256 or oracle_hash != ORACLE_SHA256:
            raise BenchmarkInputError("benchmark_integrity_invalid")
    manifest = _read_json(manifest_path)
    oracle = _read_json(oracle_path)
    if not _exact_keys(manifest, REQUIRED_MANIFEST_KEYS) or not _exact_keys(oracle, REQUIRED_ORACLE_KEYS):
        raise BenchmarkInputError("benchmark_schema_invalid")
    if manifest["evaluation_set_version"] != DATASET_VERSION or oracle["evaluation_set_version"] != DATASET_VERSION:
        raise BenchmarkInputError("benchmark_version_invalid")
    manifest_items, oracle_items = manifest["cases"], oracle["cases"]
    if not isinstance(manifest_items, list) or not isinstance(oracle_items, list):
        raise BenchmarkInputError("benchmark_schema_invalid")
    if manifest["case_count"] != len(manifest_items) or oracle["case_count"] != len(oracle_items):
        raise BenchmarkInputError("benchmark_count_invalid")
    if len(manifest_items) != 50 or len(oracle_items) != 50:
        raise BenchmarkInputError("benchmark_count_invalid")

    indexed_manifest: dict[str, dict[str, Any]] = {}
    for item in manifest_items:
        if not isinstance(item, dict) or not _exact_keys(item, REQUIRED_CASE_KEYS):
            raise BenchmarkInputError("benchmark_schema_invalid")
        case_id = item["case_id"]
        if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id) or case_id in indexed_manifest:
            raise BenchmarkInputError("benchmark_case_id_invalid")
        if item["category"] not in {entry[0] for entry in RULES.values()}:
            raise BenchmarkInputError("benchmark_category_invalid")
        if item["language"] not in _LANGUAGES:
            raise BenchmarkInputError("benchmark_language_invalid")
        relative = item["path"]
        if not isinstance(relative, str) or "\\" in relative or Path(relative).is_absolute():
            raise BenchmarkInputError("benchmark_path_invalid")
        path = Path(relative)
        if any(part in {"", ".", ".."} for part in path.parts) or path.as_posix() != relative:
            raise BenchmarkInputError("benchmark_path_invalid")
        candidate = BENCHMARK_ROOT / path
        if any((BENCHMARK_ROOT / Path(*path.parts[:index])).is_symlink() for index in range(1, len(path.parts) + 1)):
            raise BenchmarkInputError("benchmark_path_invalid")
        try:
            resolved = candidate.resolve(strict=True)
            source_lines = resolved.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError, ValueError):
            raise BenchmarkInputError("benchmark_path_invalid")
        if not resolved.is_relative_to(CASES_ROOT.resolve()) or not resolved.is_file():
            raise BenchmarkInputError("benchmark_path_invalid")
        indexed_manifest[case_id] = item
        item["_line_count"] = len(source_lines)

    indexed_oracle: dict[str, dict[str, Any]] = {}
    for item in oracle_items:
        if not isinstance(item, dict) or not _exact_keys(item, REQUIRED_ORACLE_CASE_KEYS):
            raise BenchmarkInputError("benchmark_schema_invalid")
        case_id = item["case_id"]
        if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id) or case_id in indexed_oracle:
            raise BenchmarkInputError("benchmark_case_id_invalid")
        if item["evaluation_set_version"] != DATASET_VERSION:
            raise BenchmarkInputError("benchmark_version_invalid")
        if item["security_review_relevance"] not in _RELEVANCE:
            raise BenchmarkInputError("benchmark_relevance_invalid")
        if not isinstance(item["rationale"], str) or not 1 <= len(item["rationale"]) <= _SAFE_TEXT_MAX:
            raise BenchmarkInputError("benchmark_rationale_invalid")
        limitations = item["known_limitations"]
        if not isinstance(limitations, list) or not limitations or any(
            not isinstance(entry, str) or not 1 <= len(entry) <= _SAFE_TEXT_MAX for entry in limitations
        ):
            raise BenchmarkInputError("benchmark_limitations_invalid")
        signals = item["expected_rule_signals"]
        locations = item["expected_match_locations"]
        cardinality = item["expected_cardinality"]
        if not isinstance(signals, dict) or not signals or not isinstance(locations, dict) or not isinstance(cardinality, dict):
            raise BenchmarkInputError("benchmark_oracle_invalid")
        if set(signals) != set(locations) or set(signals) != set(cardinality):
            raise BenchmarkInputError("benchmark_oracle_invalid")
        for rule_id, label in signals.items():
            if rule_id not in RULES or not _RULE_ID.fullmatch(rule_id) or label not in _LABELS:
                raise BenchmarkInputError("benchmark_rule_label_invalid")
            rule_category, _ = RULES[rule_id]
            if rule_category != item["category"]:
                raise BenchmarkInputError("benchmark_rule_category_invalid")
            line_numbers = locations[rule_id]
            count = cardinality[rule_id]
            if not isinstance(line_numbers, list) or any(type(line) is not int or line < 1 for line in line_numbers):
                raise BenchmarkInputError("benchmark_location_invalid")
            manifest_item = indexed_manifest.get(case_id)
            if manifest_item is None or any(line > manifest_item["_line_count"] for line in line_numbers):
                raise BenchmarkInputError("benchmark_location_invalid")
            if type(count) is not int or count < 0 or count > 10:
                raise BenchmarkInputError("benchmark_cardinality_invalid")
            if count != len(line_numbers) or (label == "negative" and count != 0) or (label == "positive" and count == 0):
                raise BenchmarkInputError("benchmark_oracle_invalid")
        if item["category"] != indexed_manifest.get(case_id, {}).get("category"):
            raise BenchmarkInputError("benchmark_case_mismatch")
        if item["language"] != indexed_manifest.get(case_id, {}).get("language"):
            raise BenchmarkInputError("benchmark_case_mismatch")
        indexed_oracle[case_id] = item

    if set(indexed_manifest) != set(indexed_oracle):
        raise BenchmarkInputError("benchmark_case_mismatch")
    cases = []
    for case_id, item in indexed_manifest.items():
        expected = indexed_oracle[case_id]
        cases.append(
            Case(
                case_id=case_id,
                category=item["category"],
                language=item["language"],
                path=item["path"],
                expected_rule_signals=dict(expected["expected_rule_signals"]),
                expected_match_locations={key: tuple(value) for key, value in expected["expected_match_locations"].items()},
                expected_cardinality=dict(expected["expected_cardinality"]),
                security_review_relevance=expected["security_review_relevance"],
            )
        )
    return Dataset(DATASET_VERSION, tuple(sorted(cases, key=lambda item: item.case_id)))


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def score_rule(rule_id: str, cases: tuple[Case, ...], actual: dict[str, list[int]]) -> dict[str, Any]:
    """Calculate standard binary metrics at case and expected-finding units."""
    scoped = [case for case in cases if rule_id in case.expected_rule_signals]
    if not scoped:
        raise BenchmarkInputError("benchmark_rule_scope_empty")
    case_counts = Counter()
    finding_counts = Counter()
    duplicate_findings = 0
    location_discrepancies = []
    case_results = []
    for case in scoped:
        label = case.expected_rule_signals[rule_id]
        expected = case.expected_cardinality[rule_id]
        expected_lines = list(case.expected_match_locations[rule_id])
        actual_lines = list(actual.get(case.case_id, []))
        matched = bool(actual_lines)
        if label == "positive":
            case_counts["TP" if matched else "FN"] += 1
        else:
            case_counts["FP" if matched else "TN"] += 1
        tp = min(expected, len(actual_lines))
        fp = max(0, len(actual_lines) - expected) if label == "positive" else len(actual_lines)
        fn = max(0, expected - len(actual_lines))
        tn = 1 if label == "negative" and not actual_lines else 0
        finding_counts.update({"TP": tp, "FP": fp, "FN": fn, "TN": tn})
        duplicate_findings += max(0, len(actual_lines) - expected)
        if sorted(set(actual_lines)) != sorted(expected_lines):
            location_discrepancies.append({"case_id": case.case_id, "expected_lines": expected_lines, "actual_lines": actual_lines})
        case_results.append({"case_id": case.case_id, "expected": label, "actual_match_count": len(actual_lines)})
    def metrics(counts: Counter[str]) -> dict[str, int | float | None]:
        tp, fp, fn, tn = (counts[key] for key in ("TP", "FP", "FN", "TN"))
        return {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "false_positive_rate": _ratio(fp, fp + tn),
        }
    return {
        "rule_id": rule_id,
        "category": RULES[rule_id][0],
        "case_count": len(scoped),
        "positive_cases": sum(case.expected_rule_signals[rule_id] == "positive" for case in scoped),
        "negative_cases": sum(case.expected_rule_signals[rule_id] == "negative" for case in scoped),
        "security_review_relevance": dict(Counter(case.security_review_relevance for case in scoped)),
        "case_metrics": metrics(case_counts),
        "finding_metrics": metrics(finding_counts),
        "duplicate_findings": duplicate_findings,
        "unexpected_findings": [],
        "location_discrepancies": location_discrepancies,
        "cases": case_results,
    }


def evaluate_with_results(dataset: Dataset, results_by_profile: dict[str, Any]) -> dict[str, Any]:
    """Score parsed ScanResults; failed/partial runs remain unscored."""
    profile_results: dict[str, dict[str, Any]] = {}
    actual_by_rule: dict[str, dict[str, list[int]]] = {rule: defaultdict(list) for rule in RULES}
    unexpected_findings: list[dict[str, str]] = []
    unscored_findings: list[dict[str, Any]] = []
    for profile, result in results_by_profile.items():
        profile_rules = {rule for rule, (_, path) in RULES.items() if Path(path).name == profile}
        # Baseline has several IDs in one file; experimental profiles can share the basename,
        # so callers use the canonical profile key below instead of a path-derived key.
        if profile == "baseline":
            profile_rules = {rule for rule, (_, path) in RULES.items() if path == "rules/security-baseline.yml"}
        elif profile == "eval_taint":
            profile_rules = {rule for rule, (category, _) in RULES.items() if category == "eval_taint"}
        elif profile == "command_injection":
            profile_rules = {rule for rule, (category, _) in RULES.items() if category == "command_injection"}
        status = str(result.status.value if hasattr(result.status, "value") else result.status)
        profile_results[profile] = {
            "scan_status": status,
            "semgrep_version": result.semgrep_version,
            "exit_code": result.exit_code,
            "issues": list(result.issues),
            "finding_count": len(result.findings),
        }
        path_case = {case.path.removeprefix("cases/"): case.case_id for case in dataset.cases}
        for finding in result.findings:
            case_id = path_case.get(Path(finding.file_path).as_posix())
            if case_id is None:
                unexpected_findings.append({"profile": profile, "rule_id": str(finding.rule_id), "case_id": "unmapped"})
                continue
            if finding.rule_id not in profile_rules:
                unexpected_findings.append({"profile": profile, "rule_id": str(finding.rule_id), "case_id": case_id})
                continue
            case = next((item for item in dataset.cases if item.case_id == case_id), None)
            if case is None or finding.rule_id not in case.expected_rule_signals:
                unscored_findings.append(
                    {"profile": profile, "rule_id": str(finding.rule_id), "case_id": case_id, "line_number": finding.line_number}
                )
                continue
            if finding.rule_id in actual_by_rule:
                actual_by_rule[finding.rule_id][case_id].append(finding.line_number or 0)
        profile_results[profile]["unexpected_rule_ids"] = sorted({item["rule_id"] for item in unexpected_findings if item["profile"] == profile})
        profile_results[profile]["unmapped_findings"] = [item for item in unexpected_findings if item["profile"] == profile and item["case_id"] == "unmapped"]
        profile_results[profile]["unexpected_findings"] = [item for item in unexpected_findings if item["profile"] == profile and item["case_id"] != "unmapped"]
        profile_results[profile]["unscored_out_of_scope_findings"] = [item for item in unscored_findings if item["profile"] == profile]
    metrics_available = all(item["scan_status"] == "completed" for item in profile_results.values())
    scored = {
        rule_id: score_rule(rule_id, dataset.cases, actual_by_rule[rule_id])
        for rule_id in sorted(RULES)
    } if metrics_available else {}
    for rule_id, metric in scored.items():
        profile = "baseline" if RULES[rule_id][1] == "rules/security-baseline.yml" else ("eval_taint" if RULES[rule_id][0] == "eval_taint" else "command_injection")
        metric["unexpected_findings"] = profile_results[profile]["unexpected_findings"]
    return {
        "evaluation_set_version": dataset.version,
        "semgrep_expected_version": EXPECTED_SEMGREP_VERSION,
        "metrics_available": metrics_available,
        "scan_runs": profile_results,
        "metrics_by_rule": scored,
        "unexpected_findings": unexpected_findings,
        "unscored_out_of_scope_findings": unscored_findings,
        "rule_signal_is_not_vulnerability_confirmation": True,
    }


def run_benchmark(dataset: Dataset | None = None) -> dict[str, Any]:
    """Run each local trusted rule profile exactly once over the synthetic corpus."""
    if dataset is None:
        dataset = load_dataset()
    from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter

    results = {}
    # The repository's ignore configuration excludes test data. Copy only the
    # synthetic corpus into an ephemeral directory outside the checkout so the
    # benchmark sees exactly its manifest-controlled cases without changing
    # project ignore policy or exposing developer files to Semgrep.
    with tempfile.TemporaryDirectory(prefix="phase6a-benchmark-") as temporary:
        target = Path(temporary) / "cases"
        shutil.copytree(CASES_ROOT, target)
        for profile, rule_path in (
            ("baseline", REPOSITORY_ROOT / "rules/security-baseline.yml"),
            ("eval_taint", REPOSITORY_ROOT / "rules/experimental/javascript-eval-taint.yml"),
            ("command_injection", REPOSITORY_ROOT / "rules/experimental/javascript-command-injection-taint.yml"),
        ):
            output = SemgrepAdapter(REPOSITORY_ROOT / "rules")._scan_with_evidence(target, rule_path)
            results[profile] = output.result
    report = evaluate_with_results(dataset, results)
    profile_paths = {
        "baseline": REPOSITORY_ROOT / "rules/security-baseline.yml",
        "eval_taint": REPOSITORY_ROOT / "rules/experimental/javascript-eval-taint.yml",
        "command_injection": REPOSITORY_ROOT / "rules/experimental/javascript-command-injection-taint.yml",
    }
    for profile, path in profile_paths.items():
        report["scan_runs"][profile]["rules_file_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    if any(run["semgrep_version"] != EXPECTED_SEMGREP_VERSION for run in report["scan_runs"].values()):
        report["metrics_available"] = False
        report["metrics_by_rule"] = {}
        report["tool_error"] = "semgrep_version_mismatch"
    if any(run["scan_status"] != ScanStatus.COMPLETED.value for run in report["scan_runs"].values()):
        report["metrics_available"] = False
        report["metrics_by_rule"] = {}
    return report


def main() -> int:
    try:
        dataset = load_dataset()
        report = run_benchmark(dataset)
    except BenchmarkInputError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    except Exception:
        print(json.dumps({"error": "benchmark_execution_failed"}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["metrics_available"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Reproducible static evaluation of the pre-registered Phase 6E corpus."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DATA_ROOT = Path(__file__).resolve().parent
CASES_ROOT = DATA_ROOT / "cases"
VERSION = "phase6e-heldout-synthetic-v1"
EXPECTED_SEMGREP_VERSION = "1.182.1"
MANIFEST_SHA256 = "0aa7c9ebf89f9f79ce737db7595cd2b795c989aa5f7de825f1a54d8e5e005c24"
ORIGINAL_MANIFEST_SHA256 = "d978d326eaabfa3050e1276f1208bb3b1a8f4ff26938a988e08f4fcf366a72fd"
ORACLE_SHA256 = "b62dd1b912305d199a640493a2ad1fae00917b65cb87450cd74e561cbb2b54fb"
SIGNAL_CORRECTED_PRE_METADATA_ORACLE_SHA256 = "8d1c8276d8024e3ad014b9e99c1eb7d656a4cd132afc2122fc1eb40626a21136"
ORIGINAL_ORACLE_SHA256 = "0fb9e05cebe47b25b26f9926096d2afee18ccb5a1c9cfbfea73e102c606fe2a5"
ORACLE_CORRECTIONS_SHA256 = "3c7530b82efc1823019962d201d74b2330d1a34657c1b407934177a8dfeadbfa"
RULE_SHA256 = {
    "rules/security-baseline.yml": "bfeb93c42ad942fda138dff3a9be8f4ccc1b137a2b547b6b29b65d98fc70a1a3",
    "rules/experimental/javascript-eval-taint.yml": "6c0274e4c1829b55ef26361953be3d0ed9af56384fcd63968317a5e7c7ad8e8e",
    "rules/experimental/javascript-command-injection-taint.yml": "abcbe9cb181986861c1c8597b0828e14caf839d5283ad27d9e4646ce69893783",
}
RULE_PROFILES = {
    "baseline.javascript-dynamic-eval": ("baseline", "js_eval"),
    "baseline.react-dangerous-html": ("baseline", "react_html"),
    "baseline.firestore-unconditional-write": ("baseline", "firestore"),
    "experimental.javascript-eval-taint": ("eval_taint", "eval_taint"),
    "experimental.javascript-eval-taint-with-synthetic-sanitizer": ("eval_taint", "eval_taint"),
    "experimental.javascript-command-injection-taint": ("command_injection", "command_injection"),
}
PROFILES = {
    "baseline": "rules/security-baseline.yml",
    "eval_taint": "rules/experimental/javascript-eval-taint.yml",
    "command_injection": "rules/experimental/javascript-command-injection-taint.yml",
}
SIGNALS = {"positive", "negative", "out_of_scope"}
RELEVANCE = {"review_worthy", "lower_priority", "undetermined"}
GAPS = {"in_scope", "unsupported_pattern", "unsupported_flow", "unsupported_context", "insufficient_information"}


class EvaluationInputError(ValueError):
    """Safe, stable input or execution error; never includes source content."""


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
    security_coverage_gap: str


@dataclass(frozen=True)
class Dataset:
    version: str
    cases: tuple[Case, ...]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise EvaluationInputError("benchmark_input_invalid") from None
    if not isinstance(value, dict):
        raise EvaluationInputError("benchmark_schema_invalid")
    return value


def _safe_relative(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and path.as_posix() == value and all(part not in {"", ".", ".."} for part in path.parts)


def load_dataset(manifest_path: Path = DATA_ROOT / "manifest.json", oracle_path: Path = DATA_ROOT / "oracle.json") -> Dataset:
    """Validate the immutable corpus before any score can be computed."""
    try:
        manifest_bytes, oracle_bytes = manifest_path.read_bytes(), oracle_path.read_bytes()
    except OSError:
        raise EvaluationInputError("benchmark_input_invalid") from None
    if manifest_path == DATA_ROOT / "manifest.json" and _sha(manifest_bytes) != MANIFEST_SHA256:
        raise EvaluationInputError("benchmark_manifest_integrity_invalid")
    try:
        original_manifest_bytes = (DATA_ROOT / "manifest-v1-original.json").read_bytes()
        signal_corrected_pre_metadata = (DATA_ROOT / "oracle-v1-corrected-signal-before-metadata.json").read_bytes()
    except OSError:
        raise EvaluationInputError("benchmark_preregistration_history_unavailable") from None
    if (_sha(original_manifest_bytes) != ORIGINAL_MANIFEST_SHA256
            or _sha(signal_corrected_pre_metadata) != SIGNAL_CORRECTED_PRE_METADATA_ORACLE_SHA256):
        raise EvaluationInputError("benchmark_preregistration_history_integrity_invalid")
    if oracle_path == DATA_ROOT / "oracle.json" and _sha(oracle_bytes) != ORACLE_SHA256:
        raise EvaluationInputError("benchmark_oracle_integrity_invalid")
    try:
        original_bytes = (DATA_ROOT / "oracle-v1-original.json").read_bytes()
        corrections_bytes = (DATA_ROOT / "oracle-corrections.json").read_bytes()
    except OSError:
        raise EvaluationInputError("benchmark_oracle_history_unavailable") from None
    if _sha(original_bytes) != ORIGINAL_ORACLE_SHA256 or _sha(corrections_bytes) != ORACLE_CORRECTIONS_SHA256:
        raise EvaluationInputError("benchmark_oracle_history_integrity_invalid")
    manifest = _read_json(manifest_path)
    oracle = _read_json(oracle_path)
    if manifest.get("evaluation_set_version") != VERSION or oracle.get("evaluation_set_version") != VERSION:
        raise EvaluationInputError("benchmark_version_invalid")
    if manifest.get("rule_sha256") != RULE_SHA256:
        raise EvaluationInputError("benchmark_rule_set_invalid")
    if manifest.get("authoring", {}).get("independent_review") != "INDEPENDENT_REVIEW_NOT_PERFORMED":
        raise EvaluationInputError("benchmark_provenance_invalid")
    if manifest.get("case_count") != 60 or oracle.get("case_count") != 60:
        raise EvaluationInputError("benchmark_case_count_invalid")
    if oracle.get("oracle_frozen_before_semgrep") is not True:
        raise EvaluationInputError("benchmark_preregistration_invalid")
    if not {"evaluation_set_version", "case_count", "categories", "authoring", "rule_sha256", "cases"} <= set(manifest):
        raise EvaluationInputError("benchmark_schema_invalid")

    manifest_by_id: dict[str, dict[str, Any]] = {}
    lines_by_case: dict[str, dict[str, int]] = {}
    for item in manifest.get("cases", []):
        if not isinstance(item, dict) or set(item) != {"case_id", "category", "language", "path", "files"}:
            raise EvaluationInputError("benchmark_schema_invalid")
        case_id, category, path = item["case_id"], item["category"], item["path"]
        if (not isinstance(case_id, str) or not case_id.isascii() or not case_id.replace("_", "").isalnum()
                or case_id in manifest_by_id or category not in {"js_eval", "react_html", "firestore", "eval_taint", "command_injection"}
                or not _safe_relative(path) or path != f"cases/{category}/{case_id}"):
            raise EvaluationInputError("benchmark_case_invalid")
        case_root = DATA_ROOT / path
        try:
            resolved = case_root.resolve(strict=True)
            resolved.relative_to(CASES_ROOT.resolve(strict=True))
        except (OSError, ValueError, RuntimeError):
            raise EvaluationInputError("benchmark_path_invalid") from None
        if case_root.is_symlink() or not case_root.is_dir():
            raise EvaluationInputError("benchmark_path_invalid")
        entries = item["files"]
        if not isinstance(entries, list) or not entries or len(entries) > 20:
            raise EvaluationInputError("benchmark_case_empty")
        expected_files: dict[str, str] = {}
        line_counts: dict[str, int] = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                raise EvaluationInputError("benchmark_schema_invalid")
            rel, digest = entry["path"], entry["sha256"]
            if not _safe_relative(rel) or rel in expected_files or not isinstance(digest, str) or len(digest) != 64:
                raise EvaluationInputError("benchmark_path_invalid")
            expected_files[rel] = digest
        actual_files: set[str] = set()
        for parent, dirs, filenames in os.walk(resolved, followlinks=False):
            base = Path(parent)
            if any((base / name).is_symlink() for name in dirs):
                raise EvaluationInputError("benchmark_path_invalid")
            for filename in filenames:
                file = base / filename
                if file.is_symlink() or not file.is_file():
                    raise EvaluationInputError("benchmark_path_invalid")
                rel = file.relative_to(resolved).as_posix()
                if rel in actual_files or len(actual_files) >= 20:
                    raise EvaluationInputError("benchmark_case_size_invalid")
                try:
                    data = file.read_bytes()
                    text = data.decode("utf-8")
                except (OSError, UnicodeError):
                    raise EvaluationInputError("benchmark_fixture_invalid") from None
                if len(data) > 65_536 or _sha(data) != expected_files.get(rel):
                    raise EvaluationInputError("benchmark_fixture_integrity_invalid")
                actual_files.add(rel)
                line_counts[rel] = len(text.splitlines())
        if actual_files != set(expected_files):
            raise EvaluationInputError("benchmark_fixture_integrity_invalid")
        lines_by_case[case_id] = line_counts
        manifest_by_id[case_id] = item
    actual_paths = {p for p in CASES_ROOT.rglob("*") if p.is_file()}
    declared_paths = {
        DATA_ROOT / item["path"] / entry["path"]
        for item in manifest_by_id.values() for entry in item["files"]
    }
    if actual_paths != declared_paths or any(path.is_symlink() for path in CASES_ROOT.rglob("*")):
        raise EvaluationInputError("benchmark_fixture_integrity_invalid")

    oracle_items = oracle.get("cases")
    if not isinstance(oracle_items, list) or len(oracle_items) != 60:
        raise EvaluationInputError("benchmark_oracle_invalid")
    cases: list[Case] = []
    seen: set[str] = set()
    required = {"case_id", "category", "language", "path", "evaluation_set_version", "expected_rule_signals",
                "expected_matches", "expected_cardinality", "security_review_relevance", "security_coverage_gap",
                "vulnerability_confirmation", "rationale", "limitations"}
    for item in oracle_items:
        if not isinstance(item, dict) or set(item) != required:
            raise EvaluationInputError("benchmark_oracle_schema_invalid")
        case_id = item["case_id"]
        source = manifest_by_id.get(case_id) if isinstance(case_id, str) else None
        if source is None or case_id in seen or any(item[key] != source[key] for key in ("category", "language", "path")):
            raise EvaluationInputError("benchmark_case_mismatch")
        if item["evaluation_set_version"] != VERSION or item["vulnerability_confirmation"] != "NOT_EVALUATED":
            raise EvaluationInputError("benchmark_oracle_invalid")
        relevance, gap = item["security_review_relevance"], item["security_coverage_gap"]
        if relevance not in RELEVANCE or gap not in GAPS:
            raise EvaluationInputError("benchmark_label_invalid")
        if not isinstance(item["rationale"], str) or not item["rationale"].strip() or not isinstance(item["limitations"], list) or not item["limitations"]:
            raise EvaluationInputError("benchmark_rationale_invalid")
        signals, expected, cardinality = (item[key] for key in ("expected_rule_signals", "expected_matches", "expected_cardinality"))
        if not isinstance(signals, dict) or not signals or set(signals) != set(expected) or set(signals) != set(cardinality):
            raise EvaluationInputError("benchmark_oracle_invalid")
        expected_category = source["category"]
        parsed_expected: dict[str, tuple[tuple[str, int], ...]] = {}
        for rule, label in signals.items():
            if rule not in RULE_PROFILES or RULE_PROFILES[rule][1] != expected_category or label not in SIGNALS:
                raise EvaluationInputError("benchmark_rule_label_invalid")
            locations = expected[rule]
            count = cardinality[rule]
            if not isinstance(locations, list) or type(count) is not int or count != len(locations) or count > 20:
                raise EvaluationInputError("benchmark_cardinality_invalid")
            if (label == "positive") != bool(count):
                raise EvaluationInputError("benchmark_signal_location_invalid")
            parsed_locations = []
            for loc in locations:
                if not isinstance(loc, dict) or set(loc) != {"path", "line"} or not _safe_relative(loc["path"]):
                    raise EvaluationInputError("benchmark_location_invalid")
                line = loc["line"]
                if type(line) is not int or line < 1 or line > lines_by_case[case_id].get(loc["path"], 0):
                    raise EvaluationInputError("benchmark_location_invalid")
                parsed_locations.append((loc["path"], line))
            if len(set(parsed_locations)) != len(parsed_locations):
                raise EvaluationInputError("benchmark_location_duplicate")
            parsed_expected[rule] = tuple(parsed_locations)
        seen.add(case_id)
        cases.append(Case(case_id, expected_category, source["language"], source["path"], dict(signals), parsed_expected,
                          dict(cardinality), relevance, gap))
    if seen != set(manifest_by_id):
        raise EvaluationInputError("benchmark_case_mismatch")
    counts = Counter(case.category for case in cases)
    if counts != Counter({name: 12 for name in ("js_eval", "react_html", "firestore", "eval_taint", "command_injection")}):
        raise EvaluationInputError("benchmark_category_counts_invalid")
    return Dataset(VERSION, tuple(sorted(cases, key=lambda c: c.case_id)))


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _matrix(counts: Counter[str]) -> dict[str, int | float | None]:
    tp, fp, fn, tn = (counts[key] for key in ("TP", "FP", "FN", "TN"))
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
            "false_positive_rate": _ratio(fp, fp + tn)}


def _case_for_path(path: str, dataset: Dataset) -> tuple[Case, str] | None:
    """Map a scan-relative path using its full unique case prefix, never basename."""
    if not _safe_relative(path):
        return None
    candidates = []
    for case in dataset.cases:
        prefix = case.path.removeprefix("cases/")
        if path.startswith(prefix + "/"):
            candidates.append((case, path[len(prefix) + 1:]))
    return max(candidates, key=lambda item: len(item[0].path))[0:2] if len(candidates) == 1 else None


def evaluate_results(dataset: Dataset, results: dict[str, Any]) -> dict[str, Any]:
    from ai_code_security_analyzer.semgrep_adapter import ScanStatus

    run_report: dict[str, dict[str, Any]] = {}
    observed: dict[str, dict[str, list[tuple[str, int]]]] = {rule: defaultdict(list) for rule in RULE_PROFILES}
    finding_relevance: dict[str, Counter[str]] = {rule: Counter() for rule in RULE_PROFILES}
    scoped_finding_relevance: dict[str, Counter[str]] = {rule: Counter() for rule in RULE_PROFILES}
    cross_category_relevance: dict[str, Counter[str]] = {rule: Counter() for rule in RULE_PROFILES}
    unexpected: list[dict[str, str]] = []
    unmapped: list[dict[str, str]] = []
    duplicates_in_result: list[dict[str, Any]] = []
    cross_category: list[dict[str, str]] = []
    oos_matches: dict[str, list[dict[str, Any]]] = {rule: [] for rule in RULE_PROFILES}
    allowed_by_profile = {profile: {rule for rule, (pid, _) in RULE_PROFILES.items() if pid == profile} for profile in PROFILES}

    for profile, result in results.items():
        status = result.status.value if hasattr(result.status, "value") else str(result.status)
        unverified = all(
            (getattr(finding.status, "value", finding.status) == "unverified")
            for finding in result.findings
        )
        run_report[profile] = {"scan_status": status, "semgrep_version": result.semgrep_version,
                               "exit_code": result.exit_code, "finding_count": len(result.findings),
                               "all_findings_unverified": unverified}
        seen_finding_ids: set[str] = set()
        for finding in result.findings:
            rule = str(finding.rule_id)
            if rule not in allowed_by_profile.get(profile, set()):
                unexpected.append({"profile": profile, "rule_id": rule})
                continue
            if finding.finding_id in seen_finding_ids:
                duplicates_in_result.append({"profile": profile, "rule_id": rule})
            seen_finding_ids.add(finding.finding_id)
            mapped = _case_for_path(Path(finding.file_path).as_posix(), dataset)
            if mapped is None:
                unmapped.append({"profile": profile, "rule_id": rule})
                continue
            case, relative_file = mapped
            finding_relevance[rule][case.security_review_relevance] += 1
            if rule not in case.expected_rule_signals:
                cross_category.append({"profile": profile, "rule_id": rule, "case_id": case.case_id,
                                       "security_review_relevance": case.security_review_relevance})
                cross_category_relevance[rule][case.security_review_relevance] += 1
                continue
            scoped_finding_relevance[rule][case.security_review_relevance] += 1
            observed[rule][case.case_id].append((relative_file, finding.line_number or 0))
            if case.expected_rule_signals[rule] == "out_of_scope":
                oos_matches[rule].append({"case_id": case.case_id, "relative_file": relative_file,
                                          "line": finding.line_number or 0,
                                          "security_review_relevance": case.security_review_relevance,
                                          "coverage_gap": case.security_coverage_gap})

    runs_ok = set(results) == set(PROFILES) and all(
        run_report[p]["scan_status"] == ScanStatus.COMPLETED.value
        and run_report[p]["semgrep_version"] == EXPECTED_SEMGREP_VERSION
        and run_report[p]["exit_code"] == 0
        and run_report[p]["all_findings_unverified"] for p in run_report
    )
    metrics_available = runs_ok and not unexpected and not unmapped
    metrics_by_rule: dict[str, Any] = {}
    if metrics_available:
        for rule in sorted(RULE_PROFILES):
            cases = [case for case in dataset.cases if rule in case.expected_rule_signals]
            scored = [case for case in cases if case.expected_rule_signals[rule] in {"positive", "negative"}]
            case_counts: Counter[str] = Counter()
            finding_counts: Counter[str] = Counter()
            duplicates = 0
            location_mismatch = []
            false_positives = []
            false_negatives = []
            missed_review_worthy = []
            for case in cases:
                label = case.expected_rule_signals[rule]
                actual = sorted(observed[rule].get(case.case_id, []))
                expected = sorted(case.expected_matches[rule])
                if label == "out_of_scope":
                    continue
                if label == "positive":
                    case_counts["TP" if actual else "FN"] += 1
                    finding_counts["TP"] += min(len(actual), len(expected))
                    finding_counts["FN"] += max(0, len(expected) - len(actual))
                    finding_counts["FP"] += max(0, len(actual) - len(expected))
                    if not actual:
                        false_negatives.append(case.case_id)
                        if case.security_review_relevance == "review_worthy":
                            missed_review_worthy.append(case.case_id)
                else:
                    case_counts["FP" if actual else "TN"] += 1
                    finding_counts["FP"] += len(actual)
                    finding_counts["TN"] += int(not actual)
                    if actual:
                        false_positives.append(case.case_id)
                duplicates += max(0, len(actual) - len(expected))
                if actual != expected:
                    location_mismatch.append({"case_id": case.case_id, "expected_count": len(expected),
                                              "actual_count": len(actual), "expected_locations": expected,
                                              "actual_locations": actual})

            relevant = [case for case in cases if case.security_review_relevance == "review_worthy"]
            gap_counts: Counter[str] = Counter(case.security_coverage_gap for case in relevant)
            reported_relevance = {label: scoped_finding_relevance[rule][label] for label in sorted(RELEVANCE)}
            total_reported = sum(reported_relevance.values())
            review_coverage = {
                "review_worthy_case_count": len(relevant),
                "in_scope_review_worthy_case_count": sum(c.security_coverage_gap == "in_scope" for c in relevant),
                "out_of_scope_review_worthy_case_count": sum(c.security_coverage_gap != "in_scope" for c in relevant),
                "unreported_review_worthy_case_count": sum(not observed[rule].get(c.case_id) for c in relevant),
                "unreported_review_worthy_cases_by_gap": {
                    gap: [c.case_id for c in relevant if c.security_coverage_gap == gap and not observed[rule].get(c.case_id)]
                    for gap in sorted(GAPS)
                },
                "review_worthy_cases_by_gap": {gap: gap_counts[gap] for gap in sorted(GAPS)},
                "reported_finding_relevance": reported_relevance,
                "reported_lower_priority_share": _ratio(reported_relevance["lower_priority"], total_reported),
                "reported_undetermined_share": _ratio(reported_relevance["undetermined"], total_reported),
            }
            metrics_by_rule[rule] = {
                "category": RULE_PROFILES[rule][1], "case_count": len(cases),
                "scored_case_count": len(scored), "out_of_scope_case_count": len(cases) - len(scored),
                "rule_signal_case_metrics": _matrix(case_counts), "finding_level_metrics": _matrix(finding_counts),
                "duplicate_findings": duplicates, "location_mismatches": location_mismatch,
                "false_positives": false_positives, "false_negatives": false_negatives,
                "out_of_scope_matches": oos_matches[rule], "coverage_gap": review_coverage,
                "missed_in_scope_review_worthy_positive_cases": missed_review_worthy,
                "cross_category_reported_finding_relevance": {
                    label: cross_category_relevance[rule][label] for label in sorted(RELEVANCE)
                },
                "all_profile_reported_finding_relevance": {
                    label: finding_relevance[rule][label] for label in sorted(RELEVANCE)
                },
            }

    return {
        "evaluation_set_version": VERSION, "manifest_sha256": MANIFEST_SHA256, "oracle_sha256": ORACLE_SHA256,
        "original_manifest_sha256": ORIGINAL_MANIFEST_SHA256,
        "signal_corrected_pre_metadata_oracle_sha256": SIGNAL_CORRECTED_PRE_METADATA_ORACLE_SHA256,
        "original_oracle_sha256": ORIGINAL_ORACLE_SHA256,
        "oracle_corrections_sha256": ORACLE_CORRECTIONS_SHA256,
        "expected_semgrep_version": EXPECTED_SEMGREP_VERSION, "metrics_available": metrics_available,
        "scan_runs": run_report, "metrics_by_rule": metrics_by_rule,
        "unexpected_rule_ids": unexpected, "unmapped_findings": unmapped,
        "duplicate_finding_ids": duplicates_in_result, "cross_category_observations": cross_category,
        "security_review_relevance_is_not_vulnerability_accuracy": True,
        "confirmed_vulnerability": "NOT_EVALUATED",
    }


def run_evaluation() -> dict[str, Any]:
    if shutil.which("semgrep") is None:
        raise EvaluationInputError("semgrep_not_installed")
    dataset = load_dataset()
    for relative, expected in RULE_SHA256.items():
        try:
            if _sha((ROOT / relative).read_bytes()) != expected:
                raise EvaluationInputError("benchmark_rule_hash_mismatch")
        except OSError:
            raise EvaluationInputError("benchmark_rule_unavailable") from None
    from ai_code_security_analyzer.semgrep_adapter import SemgrepAdapter

    results = {}
    with tempfile.TemporaryDirectory(prefix="phase6e-heldout-") as temporary:
        target = Path(temporary) / "cases"
        shutil.copytree(CASES_ROOT, target)
        for profile, rule_path in PROFILES.items():
            results[profile] = SemgrepAdapter(ROOT / "rules").scan(target, ROOT / rule_path)
    report = evaluate_results(dataset, results)
    report["rule_sha256"] = RULE_SHA256
    return report


def main() -> int:
    try:
        report = run_evaluation()
    except EvaluationInputError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 2
    except Exception:
        print(json.dumps({"error": "benchmark_execution_failed"}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["metrics_available"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

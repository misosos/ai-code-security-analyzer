"""Static integrity checks for the Phase 6E corpus, before its first scan."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "benchmark" / "phase6e"
VERSION = "phase6e-heldout-synthetic-v1"
MANIFEST_SHA256 = "d978d326eaabfa3050e1276f1208bb3b1a8f4ff26938a988e08f4fcf366a72fd"
ORACLE_SHA256 = "0fb9e05cebe47b25b26f9926096d2afee18ccb5a1c9cfbfea73e102c606fe2a5"
RULE_SHA256 = {
    "rules/security-baseline.yml": "bfeb93c42ad942fda138dff3a9be8f4ccc1b137a2b547b6b29b65d98fc70a1a3",
    "rules/experimental/javascript-eval-taint.yml": "6c0274e4c1829b55ef26361953be3d0ed9af56384fcd63968317a5e7c7ad8e8e",
    "rules/experimental/javascript-command-injection-taint.yml": "abcbe9cb181986861c1c8597b0828e14caf839d5283ad27d9e4646ce69893783",
}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_phase6e_manifest_and_oracle_are_frozen() -> None:
    manifest_bytes = (DATA / "manifest.json").read_bytes()
    oracle_bytes = (DATA / "oracle.json").read_bytes()
    assert _digest(manifest_bytes) == MANIFEST_SHA256
    assert _digest(oracle_bytes) == ORACLE_SHA256


def test_phase6e_fixture_and_rule_hashes_match_preregistration() -> None:
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["evaluation_set_version"] == VERSION
    assert manifest["rule_sha256"] == RULE_SHA256
    for relative_rule, expected in RULE_SHA256.items():
        assert _digest((ROOT / relative_rule).read_bytes()) == expected

    declared: set[Path] = set()
    seen_case_ids: set[str] = set()
    for case in manifest["cases"]:
        assert case["case_id"] not in seen_case_ids
        seen_case_ids.add(case["case_id"])
        case_root = DATA / case["path"]
        assert case_root.is_dir() and not case_root.is_symlink()
        for entry in case["files"]:
            relative = Path(entry["path"])
            assert not relative.is_absolute()
            assert all(part not in {"", ".", ".."} for part in relative.parts)
            fixture = case_root / relative
            assert fixture.is_file() and not fixture.is_symlink()
            payload = fixture.read_bytes()
            assert len(payload) <= 65_536
            assert _digest(payload) == entry["sha256"]
            payload.decode("utf-8")
            declared.add(fixture)

    actual = {path for path in (DATA / "cases").rglob("*") if path.is_file()}
    assert actual == declared
    assert not any(path.is_symlink() for path in (DATA / "cases").rglob("*"))


def test_phase6e_oracle_is_complete_and_has_separate_labels() -> None:
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    oracle = json.loads((DATA / "oracle.json").read_text(encoding="utf-8"))
    assert manifest["case_count"] == oracle["case_count"] == 60
    assert manifest["evaluation_set_version"] == oracle["evaluation_set_version"] == VERSION
    assert oracle["oracle_frozen_before_semgrep"] is True
    assert manifest["authoring"]["independent_review"] == "INDEPENDENT_REVIEW_NOT_PERFORMED"
    assert manifest["authoring"]["prior_exposure"]

    manifest_cases = {case["case_id"]: case for case in manifest["cases"]}
    oracle_cases = {case["case_id"]: case for case in oracle["cases"]}
    assert len(manifest_cases) == len(oracle_cases) == 60
    assert set(manifest_cases) == set(oracle_cases)
    for case_id, case in oracle_cases.items():
        source = manifest_cases[case_id]
        assert case["path"] == source["path"]
        assert case["category"] == source["category"]
        assert case["evaluation_set_version"] == VERSION
        assert case["vulnerability_confirmation"] == "NOT_EVALUATED"
        assert case["security_review_relevance"] in {"review_worthy", "lower_priority", "undetermined"}
        assert case["security_coverage_gap"] in {
            "in_scope", "unsupported_pattern", "unsupported_flow", "unsupported_context",
            "insufficient_information",
        }
        signals = case["expected_rule_signals"]
        matches = case["expected_matches"]
        cardinality = case["expected_cardinality"]
        assert signals and set(signals) == set(matches) == set(cardinality)
        for rule_id, label in signals.items():
            assert label in {"positive", "negative", "out_of_scope"}
            locations = matches[rule_id]
            assert cardinality[rule_id] == len(locations)
            assert (label == "positive") == (len(locations) > 0)
            for location in locations:
                assert location["path"] in {item["path"] for item in source["files"]}
                assert type(location["line"]) is int and location["line"] > 0
                fixture = DATA / source["path"] / location["path"]
                assert location["line"] <= len(fixture.read_text(encoding="utf-8").splitlines())

    assert Counter(case["category"] for case in oracle["cases"]) == {
        "js_eval": 12, "react_html": 12, "firestore": 12,
        "eval_taint": 12, "command_injection": 12,
    }

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from ai_code_security_analyzer.firestore_context import FirestoreContextStatus, classify_semgrep_span, classify_span
from ai_code_security_analyzer.code_context import read_regular_file_under_root
from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.models import FindingStatus
import ai_code_security_analyzer.semgrep_adapter as semgrep_adapter_module
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter
from ai_code_security_analyzer.services.scan_service import ApiSettings


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules/security-baseline.yml"
FIXTURES = ROOT / "tests/fixtures/firestore_hardening/cases"
CONTEXT_FIXTURES = ROOT / "tests/fixtures/firestore_context_validation"
CANARY = "SYNTHETIC_FIRESTORE_CONTEXT_CANARY"
CONTEXT_MANIFEST_SHA256 = "b6d631177cf9611a1c8f237d7b832f0dc4a5453851c2e77b981860d1be3e558d"
CONTEXT_ORACLE_SHA256 = "4a677997c3a0c8fee4a80cd4f04ddb22879f5fa8c3e4f82f87a615e507c94ce1"


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")


def test_context_oracle_is_frozen_and_declares_29_preimplementation_cases() -> None:
    manifest_path = CONTEXT_FIXTURES / "manifest.json"
    oracle_path = CONTEXT_FIXTURES / "oracle.json"
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == CONTEXT_MANIFEST_SHA256
    assert hashlib.sha256(oracle_path.read_bytes()).hexdigest() == CONTEXT_ORACLE_SHA256
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    assert oracle["dataset_version"] == "firestore-context-v1"
    assert oracle["case_count"] == 29
    assert sum(case["label"] == "positive" for case in oracle["cases"]) == 12
    assert sum(case["label"] == "negative" for case in oracle["cases"]) == 14
    assert sum(case["label"] == "exploratory" for case in oracle["cases"]) == 3


@pytest.mark.parametrize(
    ("source", "match", "expected"),
    [
        (b"/* allow write: if true; */", b"allow write: if true;", FirestoreContextStatus.CONFIRMED_COMMENT),
        (b"// allow write: if true;", b"allow write: if true;", FirestoreContextStatus.CONFIRMED_COMMENT),
        (b'let x = "allow write: if true;";', b"allow write: if true;", FirestoreContextStatus.CONFIRMED_STRING),
        (b'let x = "escaped ' + bytes([92, 34]) + b' allow write: if true;";', b"allow write: if true;", FirestoreContextStatus.CONFIRMED_STRING),
        (b"/* comment */ allow write: if true;", b"allow write: if true;", FirestoreContextStatus.CONFIRMED_CODE),
        (b'let x = "/* // text */"; allow write: if true;', b"allow write: if true;", FirestoreContextStatus.CONFIRMED_CODE),
        (b"/* unterminated allow write: if true;", b"allow write: if true;", FirestoreContextStatus.AMBIGUOUS),
        (b'let x = "unterminated\nallow write: if true;', b"allow write: if true;", FirestoreContextStatus.AMBIGUOUS),
    ],
)
def test_lexical_span_classification_is_conservative(source, match, expected) -> None:
    start = source.index(match)
    assert classify_span(source, start, start + len(match)) is expected


def test_unavailable_or_mixed_spans_are_not_treated_as_comments() -> None:
    assert classify_span(b"\xff allow", 1, 7) is FirestoreContextStatus.UNAVAILABLE
    assert classify_span(b"allow\x00", 0, 5) is FirestoreContextStatus.UNAVAILABLE
    assert classify_span(b"allow /* comment */", 0, len(b"allow /* comment */")) is FirestoreContextStatus.AMBIGUOUS
    assert classify_span(b"allow", 0, 0) is FirestoreContextStatus.UNAVAILABLE


def test_bounded_reader_rejects_symlinks_and_oversized_files(tmp_path: Path) -> None:
    (tmp_path / "real.rules").write_bytes(b"allow write: if true;")
    (tmp_path / "firestore.rules").symlink_to(tmp_path / "real.rules")
    data, issue = read_regular_file_under_root(tmp_path, ("firestore.rules",), 1024)
    assert data is None and issue is not None
    data, issue = read_regular_file_under_root(tmp_path, ("real.rules",), 4)
    assert data is None and issue == "file_too_large"


def test_semgrep_span_requires_consistent_byte_offsets_and_coordinates() -> None:
    source = "// café\nallow update: if true;\n".encode("utf-8")
    start = source.index(b"allow")
    end = start + len(b"allow update: if true;")
    assert classify_semgrep_span(
        source,
        start_offset=start,
        end_offset=end,
        start_line=2,
        start_column=1,
        end_line=2,
        end_column=end - start + 1,
        expected_line=2,
    ) is FirestoreContextStatus.CONFIRMED_CODE
    assert classify_semgrep_span(
        source,
        start_offset=start + 1,
        end_offset=end,
        start_line=2,
        start_column=1,
        end_line=2,
        end_column=end - start + 1,
        expected_line=2,
    ) is FirestoreContextStatus.UNAVAILABLE


def test_block_comment_only_firestore_match_is_filtered_from_shared_scan_result(tmp_path: Path) -> None:
    """A Semgrep regex candidate inside a block comment is not a code finding."""
    _require_semgrep()
    target = tmp_path / "project"
    shutil.copytree(FIXTURES / "N14_multiline_block_comment", target / "N14_multiline_block_comment")
    shutil.copytree(FIXTURES / "P06_create_update_delete", target / "P06_create_update_delete")
    n14_path = target / "N14_multiline_block_comment/firestore.rules"
    n14_path.write_text(
        n14_path.read_text(encoding="utf-8").replace("*/", f"{CANARY}\n      */"),
        encoding="utf-8",
    )

    result = SemgrepAdapter(ROOT / "rules").scan(target, RULES)

    assert result.status is ScanStatus.COMPLETED
    assert [finding.file_path for finding in result.findings] == [
        "P06_create_update_delete/firestore.rules",
    ]
    assert result.findings[0].line_number == 4
    assert result.findings[0].finding_id.startswith("semgrep:")


def test_context_corpus_filters_only_confirmed_non_code_matches(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "project"
    shutil.copytree(CONTEXT_FIXTURES / "cases", target)
    oracle = json.loads((CONTEXT_FIXTURES / "oracle.json").read_text(encoding="utf-8"))
    result = SemgrepAdapter(ROOT / "rules").scan(target, RULES)
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == "1.182.1"
    actual: dict[str, list[int]] = {}
    for finding in result.findings:
        case_id = Path(finding.file_path).parent.name
        actual.setdefault(case_id, []).append(finding.line_number)
        assert finding.rule_id == "baseline.firestore-unconditional-write"
        assert finding.status.value == "unverified"
    for case in oracle["cases"]:
        case_id = case["case_id"]
        assert sorted(actual.get(case_id, [])) == case["expected_final_lines"], case_id
    assert sorted(actual["E01_unterminated_block"]) == [2]
    assert sorted(actual["E02_unterminated_string"]) == [2]
    assert sorted(actual["E03_malformed_escape_string"]) == [2]


@pytest.mark.parametrize("read_mode", ["unavailable", "changed_after_scan"])
def test_uncertain_or_changed_source_keeps_semgrep_candidate(tmp_path: Path, monkeypatch, read_mode: str) -> None:
    _require_semgrep()
    target = tmp_path / "project"
    shutil.copytree(FIXTURES / "N14_multiline_block_comment", target)
    safe_reader = semgrep_adapter_module.read_regular_file_under_root
    reads = 0

    def uncertain_read(root: Path, parts: tuple[str, ...], limit: int):
        nonlocal reads
        reads += 1
        if reads == 1:
            return safe_reader(root, parts, limit)
        if read_mode == "unavailable":
            return None, "file_changed_during_read"
        original, issue = safe_reader(root, parts, limit)
        assert issue is None and original is not None
        return b"// inserted after Semgrep\n" + original, None

    monkeypatch.setattr(semgrep_adapter_module, "read_regular_file_under_root", uncertain_read)
    result = SemgrepAdapter(ROOT / "rules").scan(target, RULES)
    assert result.status is ScanStatus.COMPLETED
    assert len(result.findings) == 1
    assert result.findings[0].line_number == 5
    assert result.findings[0].status.value == "unverified"


def test_cli_and_api_share_filtered_firestore_findings(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "project"
    shutil.copytree(FIXTURES / "N14_multiline_block_comment", target / "N14_multiline_block_comment")
    shutil.copytree(FIXTURES / "P06_create_update_delete", target / "P06_create_update_delete")

    cli = subprocess.run(
        [sys.executable, "-m", "ai_code_security_analyzer", "scan", "--path", str(target),
         "--rules", str(RULES), "--format", "json"],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=90,
        env={**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
    )
    assert cli.returncode == 0
    cli_payload = json.loads(cli.stdout)
    assert [(item["file_path"], item["line_number"]) for item in cli_payload["findings"]] == [
        ("P06_create_update_delete/firestore.rules", 4),
    ]
    assert "N14_multiline_block_comment" not in cli.stdout
    assert CANARY not in cli.stdout
    assert "allow write: if true;" not in cli.stdout

    settings = ApiSettings(
        target_directory=target,
        trusted_rules_directory=ROOT / "rules",
        api_token="phase6c-synthetic-token-" + "x" * 40,
        allowed_hosts=("testserver", "127.0.0.1", "localhost"),
    )
    from fastapi.testclient import TestClient

    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/scans",
            headers={"X-Local-API-Token": settings.api_token},
            json={"target_id": "local-project", "rule_profile_id": "baseline"},
        )
    assert response.status_code == 200
    api_payload = response.json()
    assert [(item["file_path"], item["line_number"]) for item in api_payload["findings"]] == [
        ("P06_create_update_delete/firestore.rules", 4),
    ]
    assert api_payload["findings"][0]["verification_status"] == FindingStatus.UNVERIFIED.value
    assert "N14_multiline_block_comment" not in response.text
    assert CANARY not in response.text
    assert "allow write: if true;" not in response.text

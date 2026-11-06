from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from ai_code_security_analyzer import rule_bytes_identity as identity
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus, SemgrepAdapter, _ScanOutput


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path.resolve()
    target = root / "target"
    rules = root / "rules"
    target.mkdir()
    rules.mkdir()
    (target / "sample.js").write_text("function f(x) { return eval(x); }\n", encoding="utf-8")
    source = Path(__file__).resolve().parents[1] / "rules" / "security-baseline.yml"
    rule = rules / "security-baseline.yml"
    shutil.copyfile(source, rule)
    return target, rules, rule


def _complete() -> _ScanOutput:
    return _ScanOutput(ScanResult(ScanStatus.COMPLETED, exit_code=0, semgrep_version="1.182.1"))


def test_private_snapshot_is_read_only_and_comparison_is_context_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target, rules, rule = _fixture(tmp_path)
    original = rule.read_bytes()
    snapshots: list[Path] = []

    def scan(_self, project, snapshot, **options):
        assert project == target and options["investigation_verbose"] is True
        assert snapshot.name == rule.name
        if snapshot.read_bytes() != original:
            pytest.fail("snapshot_content_mismatch", pytrace=False)
        assert snapshot.stat().st_mode & 0o777 == 0o400
        assert snapshot.parent.stat().st_mode & 0o777 == 0o700
        snapshots.append(snapshot)
        return _complete()

    monkeypatch.setattr(identity.SemgrepAdapter, "_scan_with_evidence", scan)
    first = identity._scan_with_rule_copy(target, rules)
    second = identity._scan_with_rule_copy(target, rules)
    assert identity._compare_selected_rule_bytes(first, second) is identity.RuleBytesComparison.SAME_SELECTED_BYTES
    assert identity._compare_selected_rule_bytes(first, first) is identity.RuleBytesComparison.INCOMPARABLE
    assert identity._compare_selected_rule_bytes(first, None) is identity.RuleBytesComparison.UNVERIFIED
    assert identity._compare_selected_rule_bytes(first, replace(second, _target_identity=(0, 0))) is identity.RuleBytesComparison.INCOMPARABLE
    different_version = replace(second, output=_ScanOutput(ScanResult(ScanStatus.COMPLETED, semgrep_version="0.0.0")))
    assert identity._compare_selected_rule_bytes(first, different_version) is identity.RuleBytesComparison.INCOMPARABLE
    assert all(not path.exists() for path in snapshots)
    assert original not in repr(first).encode()
    assert first._digest.hex() not in repr(first)


def test_tmpdir_environment_does_not_choose_rule_snapshot_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target, rules, _rule = _fixture(tmp_path)
    monkeypatch.setenv("TMPDIR", str(target))

    def scan(_self, _project, snapshot, **_options):
        assert snapshot.parent.parent == Path("/tmp").resolve()
        return _complete()

    monkeypatch.setattr(identity.SemgrepAdapter, "_scan_with_evidence", scan)
    assert identity._scan_with_rule_copy(target, rules)._digest is not None


def test_original_change_after_snapshot_does_not_change_execution_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target, rules, rule = _fixture(tmp_path)
    before = rule.read_bytes()

    def scan(_self, _project, snapshot, **_options):
        rule.write_bytes(before + b"\n# changed original after snapshot\n")
        if snapshot.read_bytes() != before:
            pytest.fail("snapshot_content_mismatch", pytrace=False)
        return _complete()

    monkeypatch.setattr(identity.SemgrepAdapter, "_scan_with_evidence", scan)
    run = identity._scan_with_rule_copy(target, rules)
    assert run._digest is not None
    if rule.read_bytes() == before:
        pytest.fail("original_not_changed", pytrace=False)


def test_original_replaced_after_read_keeps_captured_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target, rules, rule = _fixture(tmp_path)
    before = rule.read_bytes()
    read = identity._safe_read
    replaced = False

    def replace_after_read(root: Path, name: str) -> bytes:
        nonlocal replaced
        data = read(root, name)
        if root == rules and not replaced:
            replacement = rules / "replacement"
            replacement.write_text("different", encoding="utf-8")
            replacement.replace(rule)
            replaced = True
        return data

    def scan(_self, _project, snapshot, **_options):
        if snapshot.read_bytes() != before:
            raise AssertionError("snapshot_content_mismatch")
        return _complete()

    monkeypatch.setattr(identity, "_safe_read", replace_after_read)
    monkeypatch.setattr(identity.SemgrepAdapter, "_scan_with_evidence", scan)
    assert identity._scan_with_rule_copy(target, rules)._digest is not None
    assert replaced


@pytest.mark.parametrize("replacement", ["modify", "replace", "symlink"])
def test_snapshot_replacement_during_execution_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str) -> None:
    target, rules, _rule = _fixture(tmp_path)

    def scan(_self, _project, snapshot, **_options):
        if replacement == "modify":
            snapshot.chmod(0o600)
            snapshot.write_text("changed", encoding="utf-8")
            snapshot.chmod(0o400)
        else:
            snapshot.unlink()
            if replacement == "symlink":
                snapshot.symlink_to(rules / "security-baseline.yml")
            else:
                snapshot.write_text("replacement", encoding="utf-8")
                snapshot.chmod(0o400)
        return _complete()

    monkeypatch.setattr(identity.SemgrepAdapter, "_scan_with_evidence", scan)
    with pytest.raises(identity.RuleBytesIdentityError, match="^rule_snapshot_changed$"):
        identity._scan_with_rule_copy(target, rules)


def test_rule_symlink_size_missing_and_permission_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target, rules, rule = _fixture(tmp_path)
    outside = tmp_path / "outside.yml"
    outside.write_text("rules: []", encoding="utf-8")
    rule.unlink()
    rule.symlink_to(outside)
    with pytest.raises(identity.RuleBytesIdentityError, match="^rule_bytes_unavailable$"):
        identity._scan_with_rule_copy(target, rules)
    rule.unlink()
    with pytest.raises(identity.RuleBytesIdentityError, match="^rule_bytes_unavailable$"):
        identity._scan_with_rule_copy(target, rules)
    rule.write_bytes(b"x" * (identity._MAX_RULE_BYTES + 1))
    with pytest.raises(identity.RuleBytesIdentityError, match="^rule_bytes_unavailable$"):
        identity._scan_with_rule_copy(target, rules)
    monkeypatch.setattr(identity, "read_regular_file_under_root", lambda *_args: (None, "file_access_denied"))
    with pytest.raises(identity.RuleBytesIdentityError, match="^rule_bytes_unavailable$"):
        identity._scan_with_rule_copy(target, rules)


def test_hardlinked_rule_and_symlinked_root_are_rejected(tmp_path: Path) -> None:
    target, rules, rule = _fixture(tmp_path)
    linked_root = tmp_path.resolve() / "linked_rules"
    linked_root.symlink_to(rules, target_is_directory=True)
    with pytest.raises(identity.RuleBytesIdentityError, match="^rule_context_invalid$"):
        identity._scan_with_rule_copy(target, linked_root)
    os.link(rule, rules / "second_link")
    with pytest.raises(identity.RuleBytesIdentityError, match="^rule_bytes_unavailable$"):
        identity._scan_with_rule_copy(target, rules)


def test_original_mutation_during_bounded_read_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target, rules, rule = _fixture(tmp_path)
    original_read = os.read
    original_inode = rule.stat().st_ino
    changed = False

    def mutate_after_read(fd: int, size: int) -> bytes:
        nonlocal changed
        chunk = original_read(fd, size)
        if not changed and os.fstat(fd).st_ino == original_inode:
            changed = True
            rule.write_text("changed during read", encoding="utf-8")
        return chunk

    monkeypatch.setattr(os, "read", mutate_after_read)
    with pytest.raises(identity.RuleBytesIdentityError, match="^rule_bytes_unavailable$"):
        identity._scan_with_rule_copy(target, rules)
    assert changed


def test_execution_exception_is_sanitized_and_snapshot_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target, rules, _rule = _fixture(tmp_path)
    snapshots: list[Path] = []

    def fail(_self, _project, snapshot, **_options):
        snapshots.append(snapshot)
        raise RuntimeError("SYNTHETIC_CANARY_PRIVATE_RULE_PATH")

    monkeypatch.setattr(identity.SemgrepAdapter, "_scan_with_evidence", fail)
    with pytest.raises(identity.RuleBytesIdentityError, match="^rule_input_unavailable$") as error:
        identity._scan_with_rule_copy(target, rules)
    assert "SYNTHETIC_CANARY" not in str(error.value)
    assert all(not snapshot.exists() for snapshot in snapshots)


@pytest.mark.parametrize("status", [ScanStatus.PARTIAL, ScanStatus.TIMED_OUT, ScanStatus.OUTPUT_LIMIT_EXCEEDED, ScanStatus.EXECUTION_FAILED, ScanStatus.INVALID_JSON])
def test_failed_execution_has_no_comparable_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: ScanStatus) -> None:
    target, rules, _rule = _fixture(tmp_path)
    monkeypatch.setattr(identity.SemgrepAdapter, "_scan_with_evidence", lambda *_args, **_kwargs: _ScanOutput(ScanResult(status)))
    first = identity._scan_with_rule_copy(target, rules)
    second = identity._scan_with_rule_copy(target, rules)
    assert first._digest is None
    assert identity._compare_selected_rule_bytes(first, second) is identity.RuleBytesComparison.UNVERIFIED


def test_real_semgrep_copy_binding_and_rule_id_compatibility(tmp_path: Path) -> None:
    if not shutil.which("semgrep"):
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("required_semgrep_unavailable")
        pytest.skip("Semgrep is not installed")
    version = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, check=True, timeout=10)
    assert version.stdout.strip() == "1.182.1"
    target, rules, rule = _fixture(tmp_path)
    (target / "firestore.rules").write_text("service cloud.firestore {\n match /databases/{db}/documents {\n  match /{doc=**} {\n   allow write: if true;\n  }\n }\n}\n", encoding="utf-8")
    before = rule.read_bytes()
    original = SemgrepAdapter(rules)._scan_with_evidence(target, rule, investigation_verbose=True)
    first = identity._scan_with_rule_copy(target, rules)
    same = identity._scan_with_rule_copy(target, rules)
    assert first.output.result.status is ScanStatus.COMPLETED
    assert identity._compare_selected_rule_bytes(first, same) is identity.RuleBytesComparison.SAME_SELECTED_BYTES
    projection = lambda output: [(f.rule_id, f.finding_id, f.file_path) for f in output.result.findings]
    assert projection(original) == projection(first.output) == projection(same.output)
    assert {item[0] for item in projection(original)} == {"baseline.javascript-dynamic-eval", "baseline.firestore-unconditional-write"}
    assert first.output.taint_evidence == original.taint_evidence
    rule.write_bytes(before + b"\n# synthetic comment-only variant\n")
    comment = identity._scan_with_rule_copy(target, rules)
    assert identity._compare_selected_rule_bytes(first, comment) is identity.RuleBytesComparison.DIFFERENT_SELECTED_BYTES
    assert projection(first.output) == projection(comment.output)
    rule.write_bytes(before.replace(b"severity: ERROR", b"severity: WARNING", 1))
    changed = identity._scan_with_rule_copy(target, rules)
    assert identity._compare_selected_rule_bytes(first, changed) is identity.RuleBytesComparison.DIFFERENT_SELECTED_BYTES
    assert projection(first.output) == projection(changed.output)
    rule.write_bytes(b"rules: [\n")
    invalid = identity._scan_with_rule_copy(target, rules)
    assert invalid.output.result.status is ScanStatus.EXECUTION_FAILED
    assert identity._compare_selected_rule_bytes(first, invalid) is identity.RuleBytesComparison.UNVERIFIED
    rule.write_bytes(before)
    (target / "ignored.js").write_text("function ignored(x) { return eval(x); }\n", encoding="utf-8")
    (target / ".semgrepignore").write_text("ignored.js\n", encoding="utf-8")
    skipped = identity._scan_with_rule_copy(target, rules)
    assert skipped.output.result.status is ScanStatus.PARTIAL
    assert identity._compare_selected_rule_bytes(first, skipped) is identity.RuleBytesComparison.UNVERIFIED
    assert [(item.path, item.reason_code) for item in skipped.output.scope_evidence.skipped_paths] == [
        ("ignored.js", "semgrepignore_patterns_match")
    ]
    assert skipped.output.scope_evidence.completeness_status.value == "UNVERIFIED"
    if (Path(__file__).resolve().parents[1] / "rules" / "security-baseline.yml").read_bytes() != before:
        pytest.fail("repository_rules_changed", pytrace=False)

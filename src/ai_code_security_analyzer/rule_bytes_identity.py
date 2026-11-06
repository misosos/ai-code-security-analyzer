"""Private, bounded experiment binding a selected rule copy to one scan.

This module is not connected to the API, CLI, manifest or evidence registry.
Its equality result describes selected file bytes only, never loaded rules.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from ai_code_security_analyzer.code_context import read_regular_file_under_root
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter, _ScanOutput


_MAX_RULE_BYTES = 2_000_000
_RULE_NAME = "security-baseline.yml"
_PRIVATE_INVOCATION = "semgrep-json-private-rule-snapshot-v1"


class RuleBytesIdentityError(Exception):
    """A fixed error which never includes a filesystem path or rule content."""


class RuleBytesComparison(StrEnum):
    SAME_SELECTED_BYTES = "SAME_SELECTED_BYTES"
    DIFFERENT_SELECTED_BYTES = "DIFFERENT_SELECTED_BYTES"
    UNVERIFIED = "UNVERIFIED"
    INCOMPARABLE = "INCOMPARABLE"


@dataclass(frozen=True, slots=True)
class _BoundRuleRun:
    """Ephemeral private result from the same invocation that used the copy."""

    output: _ScanOutput = field(repr=False)
    _digest: bytes | None = field(repr=False)
    _run_id: bytes = field(repr=False)
    _target_identity: tuple[int, int] = field(repr=False)
    _invocation: str = _PRIVATE_INVOCATION
    _profile: str = "baseline"


def _safe_read(root: Path, name: str) -> bytes:
    data, issue = read_regular_file_under_root(root, (name,), _MAX_RULE_BYTES)
    if issue is not None or data is None or not data:
        raise RuleBytesIdentityError("rule_bytes_unavailable") from None
    return data


def _identity(path: Path) -> tuple[int, int, int, int, int, int]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400:
        raise RuleBytesIdentityError("rule_snapshot_changed")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)


def _directory_identity(path: Path) -> tuple[int, int, int, int, int]:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuleBytesIdentityError("rule_snapshot_changed")
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)


def _trusted_root(path: Path) -> Path:
    supplied = Path(path)
    if not supplied.is_absolute() or ".." in supplied.parts:
        raise RuleBytesIdentityError("rule_context_invalid")
    current = Path(supplied.anchor)
    for part in supplied.parts[1:]:
        current = current / part
        if stat.S_ISLNK(current.lstat().st_mode):
            raise RuleBytesIdentityError("rule_context_invalid")
    return supplied.resolve(strict=True)


def _temporary_parent() -> Path:
    # Do not let TMPDIR choose where rule bytes are written. This private
    # prototype supports POSIX hosts with a sticky system temporary directory.
    if os.name != "posix":
        raise RuleBytesIdentityError("rule_input_unavailable")
    parent = Path("/tmp").resolve(strict=True)
    info = parent.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()}
            or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
        raise RuleBytesIdentityError("rule_input_unavailable")
    return parent


def _scan_with_rule_copy(target: Path, trusted_rules_directory: Path, *, timeout: int = 60) -> _BoundRuleRun:
    """Scan an approved baseline file copy. Callers must provide trusted roots.

    Only the baseline filename/profile is supported. This is an isolated private
    invocation; its observations are not serializable C1/C3 evidence.
    """
    try:
        root = _trusted_root(Path(trusted_rules_directory))
        project = Path(target).resolve(strict=True)
        if not root.is_dir() or not project.is_dir() or root == project or root in project.parents or project in root.parents:
            raise RuleBytesIdentityError("rule_context_invalid")
        target_info = project.stat()
        target_identity = (target_info.st_dev, target_info.st_ino)
        data = _safe_read(root, _RULE_NAME)
        digest = hashlib.sha256(data).digest()
        with tempfile.TemporaryDirectory(prefix="ai-csa-rule-input-", dir=_temporary_parent()) as temporary:
            snapshot_root = Path(temporary).resolve(strict=True)
            if (snapshot_root == project or project in snapshot_root.parents or snapshot_root in project.parents
                    or snapshot_root == root or root in snapshot_root.parents or snapshot_root in root.parents):
                raise RuleBytesIdentityError("rule_context_invalid")
            snapshot = snapshot_root / _RULE_NAME
            descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                    os.fchmod(stream.fileno(), 0o400)
            except BaseException:
                raise
            before = _identity(snapshot)
            before_directory = _directory_identity(snapshot_root)
            if _safe_read(snapshot_root, _RULE_NAME) != data:
                raise RuleBytesIdentityError("rule_snapshot_changed")
            output = SemgrepAdapter(snapshot_root)._scan_with_evidence(
                project, snapshot, timeout=timeout, investigation_verbose=True,
            )
            if (_identity(snapshot) != before or _directory_identity(snapshot_root) != before_directory
                    or _safe_read(snapshot_root, _RULE_NAME) != data):
                raise RuleBytesIdentityError("rule_snapshot_changed")
            after_target = project.stat()
            if (after_target.st_dev, after_target.st_ino) != target_identity:
                raise RuleBytesIdentityError("rule_context_invalid")
        # Do not turn launch/timeout/parse failures into a successful observation.
        usable = (output.result.status is ScanStatus.COMPLETED
                  and output.result.exit_code == 0 and bool(output.result.semgrep_version))
        return _BoundRuleRun(output, digest if usable else None, secrets.token_bytes(16), target_identity)
    except RuleBytesIdentityError:
        raise
    except Exception:
        raise RuleBytesIdentityError("rule_input_unavailable") from None


def _compare_selected_rule_bytes(
    baseline: _BoundRuleRun | None, current: _BoundRuleRun | None,
) -> RuleBytesComparison:
    """Compare only two distinct private scan results in the same context."""
    if baseline is None or current is None:
        return RuleBytesComparison.UNVERIFIED
    if not isinstance(baseline, _BoundRuleRun) or not isinstance(current, _BoundRuleRun):
        return RuleBytesComparison.INCOMPARABLE
    if (baseline._run_id == current._run_id or baseline._target_identity != current._target_identity
            or baseline._profile != current._profile or baseline._invocation != current._invocation):
        return RuleBytesComparison.INCOMPARABLE
    if baseline._digest is None or current._digest is None:
        return RuleBytesComparison.UNVERIFIED
    baseline_version = baseline.output.result.semgrep_version
    current_version = current.output.result.semgrep_version
    if not baseline_version or not current_version:
        return RuleBytesComparison.UNVERIFIED
    if baseline_version != current_version:
        return RuleBytesComparison.INCOMPARABLE
    if len(baseline._digest) != 32 or len(current._digest) != 32:
        return RuleBytesComparison.INCOMPARABLE
    return (RuleBytesComparison.SAME_SELECTED_BYTES
            if secrets.compare_digest(baseline._digest, current._digest)
            else RuleBytesComparison.DIFFERENT_SELECTED_BYTES)

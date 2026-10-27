"""Conservative secret-like value checks for model-generated public text.

This is a heuristic output guard, not a general secret detector. It deliberately
allows security vocabulary by itself while rejecting credential-shaped values.
"""

import re
from enum import StrEnum


class SensitiveTextStatus(StrEnum):
    SAFE = "safe"
    DETECTED = "detected"
    UNCERTAIN = "uncertain"


_KNOWN_CREDENTIAL = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|"
    r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_SYNTHETIC_CANARY = re.compile(
    r"\bSYNTHETIC[_-](?:TOKEN|SECRET|PASSWORD|API[_-]?KEY)[_-][A-Za-z0-9]{3,}\b",
    re.IGNORECASE,
)
_CREDENTIAL_NAME = (
    r"api[_-]?key|apikey|password|passwd|passphrase|token|secret|credential|"
    r"authorization|bearer|private[_-]?key"
)
_ASSIGNED_CREDENTIAL = re.compile(
    rf"\b(?:{_CREDENTIAL_NAME})\b\s*[:=]\s*(?:\"[^\"]+\"|'[^']+'|`[^`]+`|"
    r"[A-Za-z0-9_./+=:-]{8,})",
    re.IGNORECASE,
)
_OPAQUE_LONG_VALUE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9])")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def inspect_model_text(text: str) -> SensitiveTextStatus:
    """Classify model text without returning or retaining a matched value."""
    if (_KNOWN_CREDENTIAL.search(text) or _PRIVATE_KEY.search(text) or _EMAIL.search(text)
            or _SYNTHETIC_CANARY.search(text)):
        return SensitiveTextStatus.DETECTED
    if _ASSIGNED_CREDENTIAL.search(text):
        return SensitiveTextStatus.DETECTED
    if _OPAQUE_LONG_VALUE.search(text):
        return SensitiveTextStatus.UNCERTAIN
    return SensitiveTextStatus.SAFE

"""Bounded lexical context checks for Semgrep Firestore rule candidates.

This module distinguishes comments and strings from code for the narrow span
Semgrep already reported. It does not parse or validate Firestore semantics.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from enum import StrEnum


class FirestoreContextStatus(StrEnum):
    CONFIRMED_CODE = "confirmed_code_context"
    CONFIRMED_COMMENT = "confirmed_comment_context"
    CONFIRMED_STRING = "confirmed_string_context"
    UNAVAILABLE = "context_unavailable"
    AMBIGUOUS = "context_ambiguous"


_CODE = 0
_COMMENT = 1
_STRING = 2
_AMBIGUOUS = 3


@dataclass(frozen=True, slots=True)
class FirestoreLexicalContext:
    """Per-file byte-state map, built once and reused for every reported match."""

    source_size: int
    states: bytes | None
    line_starts: tuple[int, ...]

    def locate(self, offset: int) -> tuple[int, int] | None:
        if type(offset) is not int or offset < 0 or offset > self.source_size:
            return None
        line_index = bisect_right(self.line_starts, offset) - 1
        return line_index + 1, offset - self.line_starts[line_index] + 1

    def classify(self, start: int, end: int) -> FirestoreContextStatus:
        if (
            self.states is None
            or type(start) is not int or type(end) is not int
            or start < 0 or end <= start or end > self.source_size
        ):
            return FirestoreContextStatus.UNAVAILABLE
        span = self.states[start:end]
        if not span or _AMBIGUOUS in span:
            return FirestoreContextStatus.AMBIGUOUS if span else FirestoreContextStatus.UNAVAILABLE
        first = span[0]
        if any(state != first for state in span):
            return FirestoreContextStatus.AMBIGUOUS
        if first == _COMMENT:
            return FirestoreContextStatus.CONFIRMED_COMMENT
        if first == _STRING:
            return FirestoreContextStatus.CONFIRMED_STRING
        return FirestoreContextStatus.CONFIRMED_CODE


def scan_lexical_context(source: bytes) -> FirestoreLexicalContext:
    """Build the deliberately small comment/string scanner for one Firestore file."""
    if b"\x00" in source:
        return FirestoreLexicalContext(len(source), None, (0,))
    try:
        source.decode("utf-8")
    except UnicodeDecodeError:
        return FirestoreLexicalContext(len(source), None, (0,))
    states = bytearray(len(source))
    index = 0
    size = len(source)
    while index < size:
        current = source[index]
        following = source[index + 1] if index + 1 < size else -1
        if current == ord("/") and following == ord("/"):
            stop = source.find(b"\n", index + 2)
            stop = size if stop < 0 else stop
            states[index:stop] = bytes([_COMMENT]) * (stop - index)
            index = stop
            continue
        if current == ord("/") and following == ord("*"):
            stop = source.find(b"*/", index + 2)
            if stop < 0:
                states[index:] = bytes([_AMBIGUOUS]) * (size - index)
                break
            stop += 2
            states[index:stop] = bytes([_COMMENT]) * (stop - index)
            index = stop
            continue
        if current in (ord("'"), ord('"'), ord("`")):
            quote = current
            beginning = index
            cursor = index + 1
            closed = False
            while cursor < size:
                char = source[cursor]
                if char == ord("\\"):
                    if cursor + 1 >= size:
                        break
                    if source[cursor + 1] == ord("\n") and quote != ord("`"):
                        # Escaped newlines are kept in the quoted region.
                        cursor += 2
                        continue
                    cursor += 2
                    continue
                if char == quote:
                    cursor += 1
                    closed = True
                    break
                if char == ord("\n") and quote != ord("`"):
                    # A multiline ordinary string is outside the supported
                    # lexical subset; do not infer that following text is code.
                    break
                cursor += 1
            if not closed:
                states[beginning:] = bytes([_AMBIGUOUS]) * (size - beginning)
                break
            states[beginning:cursor] = bytes([_STRING]) * (cursor - beginning)
            index = cursor
            continue
        index += 1

    line_starts = (0, *(index + 1 for index, byte in enumerate(source) if byte == ord("\n")))
    return FirestoreLexicalContext(len(source), bytes(states), line_starts)


def classify_span(source: bytes, start: int, end: int) -> FirestoreContextStatus:
    """Classify an exclusive byte span, conservatively retaining uncertainty."""
    return scan_lexical_context(source).classify(start, end)


def classify_semgrep_span(
    source: bytes,
    *,
    start_offset: object,
    end_offset: object,
    start_line: object,
    start_column: object,
    end_line: object,
    end_column: object,
    expected_line: int | None,
    lexical_context: FirestoreLexicalContext | None = None,
) -> FirestoreContextStatus:
    """Validate Semgrep's 1-based line/column and byte-offset coordinates."""
    values = (start_offset, end_offset, start_line, start_column, end_line, end_column)
    if any(type(value) is not int or value < 1 for value in values):
        return FirestoreContextStatus.UNAVAILABLE
    start_offset = int(start_offset)
    end_offset = int(end_offset)
    start_line = int(start_line)
    start_column = int(start_column)
    end_line = int(end_line)
    end_column = int(end_column)
    if expected_line != start_line or end_offset <= start_offset or end_offset > len(source):
        return FirestoreContextStatus.UNAVAILABLE

    context = lexical_context or scan_lexical_context(source)
    if context.source_size != len(source):
        return FirestoreContextStatus.UNAVAILABLE
    if context.locate(start_offset) != (start_line, start_column):
        return FirestoreContextStatus.UNAVAILABLE
    if context.locate(end_offset) != (end_line, end_column):
        return FirestoreContextStatus.UNAVAILABLE
    return context.classify(start_offset, end_offset)

"""Shared, presentation-neutral field difference calculation.

The comparison deliberately operates on original logical lines. Display width
is a rendering concern and must never introduce false additions or removals.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, replace
from typing import Literal, Optional


ChangeKind = Literal["equal", "added", "removed"]
BlockKind = Literal["equal", "insert", "delete", "replace", "context"]

DEFAULT_DETAILED_CHARACTER_LIMIT = 50_000
DEFAULT_DETAILED_CHARACTER_PRODUCT_LIMIT = 25_000_000
DEFAULT_TOTAL_CHARACTER_LIMIT = 200_000
DEFAULT_LINE_COUNT_LIMIT = 5_000
DEFAULT_LINE_PRODUCT_LIMIT = 1_000_000

_WHITESPACE_PARTS = re.compile(r"(\r\n|\r|\n|\t)")
_LINE_BREAKS = re.compile(r"\r\n|\r|\n")


@dataclass(frozen=True)
class DiffSegment:
    """One safely renderable text segment and its semantic change type."""

    text: str
    change: ChangeKind
    marker: Optional[Literal["newline", "tab"]] = None


@dataclass(frozen=True)
class DiffLine:
    """Segments belonging to one logical source line."""

    source_line: Optional[int]
    segments: tuple[DiffSegment, ...]


@dataclass(frozen=True)
class DiffBlock:
    """One aligned group of equal, inserted, deleted, or replaced lines."""

    kind: BlockKind
    left_lines: tuple[DiffLine, ...]
    right_lines: tuple[DiffLine, ...]
    collapsed_line_count: int = 0


@dataclass(frozen=True)
class FieldDiff:
    """Complete semantic diff plus display-only change metrics."""

    blocks: tuple[DiffBlock, ...]
    added_characters: int
    removed_characters: int
    added_line_breaks: int
    removed_line_breaks: int
    approximate: bool = False


def build_semantic_diff(
    left_text: str,
    right_text: str,
    *,
    context_lines: Optional[int] = 2,
    detailed_character_limit: int = DEFAULT_DETAILED_CHARACTER_LIMIT,
    detailed_character_product_limit: int = DEFAULT_DETAILED_CHARACTER_PRODUCT_LIMIT,
    total_character_limit: int = DEFAULT_TOTAL_CHARACTER_LIMIT,
    line_count_limit: int = DEFAULT_LINE_COUNT_LIMIT,
    line_product_limit: int = DEFAULT_LINE_PRODUCT_LIMIT,
) -> FieldDiff:
    """Compare two strings without using presentation wrapping as input.

    Detailed character comparison is bounded because ``SequenceMatcher`` can
    become expensive for large repetitive values. Oversized input falls back
    to a deterministic common-prefix/common-suffix comparison.
    """
    if not isinstance(left_text, str) or not isinstance(right_text, str):
        raise TypeError("build_semantic_diff expects string values")

    left_lines = _logical_lines(left_text)
    right_lines = _logical_lines(right_text)
    total_characters = len(left_text) + len(right_text)

    if (
        total_characters > total_character_limit
        or len(left_lines) + len(right_lines) > line_count_limit
        or len(left_lines) * len(right_lines) > line_product_limit
    ):
        left_segments, right_segments, metrics = _fallback_segments(left_text, right_text)
        block = DiffBlock(
            kind="equal" if left_text == right_text else "replace",
            left_lines=_segments_to_lines(left_segments, 1),
            right_lines=_segments_to_lines(right_segments, 1),
        )
        return FieldDiff(
            blocks=(block,),
            approximate=True,
            **metrics,
        )

    blocks: list[DiffBlock] = []
    totals = _empty_metrics()
    approximate = False
    matcher = difflib.SequenceMatcher(None, left_lines, right_lines, autojunk=False)

    for opcode, left_start, left_end, right_start, right_end in matcher.get_opcodes():
        left_chunk = "".join(left_lines[left_start:left_end])
        right_chunk = "".join(right_lines[right_start:right_end])

        if opcode == "equal":
            left_segments = (DiffSegment(left_chunk, "equal"),)
            right_segments = (DiffSegment(right_chunk, "equal"),)
            kind: BlockKind = "equal"
            metrics = _empty_metrics()
        elif opcode == "delete":
            left_segments = (DiffSegment(left_chunk, "removed"),)
            right_segments = ()
            kind = "delete"
            metrics = _metrics_for_change(removed=left_chunk)
        elif opcode == "insert":
            left_segments = ()
            right_segments = (DiffSegment(right_chunk, "added"),)
            kind = "insert"
            metrics = _metrics_for_change(added=right_chunk)
        else:
            kind = "replace"
            if _can_use_detailed_character_diff(
                left_chunk,
                right_chunk,
                detailed_character_limit,
                detailed_character_product_limit,
            ):
                left_segments, right_segments, metrics = _detailed_segments(left_chunk, right_chunk)
            else:
                left_segments, right_segments, metrics = _fallback_segments(left_chunk, right_chunk)
                approximate = True

        _add_metrics(totals, metrics)
        blocks.append(
            DiffBlock(
                kind=kind,
                left_lines=_segments_to_lines(left_segments, left_start + 1),
                right_lines=_segments_to_lines(right_segments, right_start + 1),
            )
        )

    if context_lines is not None:
        blocks = _collapse_equal_context(blocks, max(0, context_lines))

    return FieldDiff(
        blocks=tuple(blocks),
        approximate=approximate,
        **totals,
    )


def _logical_lines(value: str) -> list[str]:
    """Return logical lines while retaining separators for newline changes."""
    return value.splitlines(keepends=True) or [""]


def _can_use_detailed_character_diff(
    left: str,
    right: str,
    character_limit: int,
    product_limit: int,
) -> bool:
    return (
        len(left) + len(right) <= max(0, character_limit)
        and len(left) * len(right) <= max(0, product_limit)
    )


def _detailed_segments(
    left: str,
    right: str,
) -> tuple[tuple[DiffSegment, ...], tuple[DiffSegment, ...], dict[str, int]]:
    """Build exact character segments for one local replacement block."""
    left_segments: list[DiffSegment] = []
    right_segments: list[DiffSegment] = []
    totals = _empty_metrics()
    matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)

    for opcode, left_start, left_end, right_start, right_end in matcher.get_opcodes():
        left_value = left[left_start:left_end]
        right_value = right[right_start:right_end]
        if opcode == "equal":
            _append_segment(left_segments, left_value, "equal")
            _append_segment(right_segments, right_value, "equal")
        elif opcode == "delete":
            _append_segment(left_segments, left_value, "removed")
            _add_metrics(totals, _metrics_for_change(removed=left_value))
        elif opcode == "insert":
            _append_segment(right_segments, right_value, "added")
            _add_metrics(totals, _metrics_for_change(added=right_value))
        else:
            _append_segment(left_segments, left_value, "removed")
            _append_segment(right_segments, right_value, "added")
            _add_metrics(totals, _metrics_for_change(removed=left_value, added=right_value))

    return tuple(left_segments), tuple(right_segments), totals


def _fallback_segments(
    left: str,
    right: str,
) -> tuple[tuple[DiffSegment, ...], tuple[DiffSegment, ...], dict[str, int]]:
    """Return a linear, deterministic prefix/suffix diff for large values."""
    prefix_length = 0
    prefix_limit = min(len(left), len(right))
    while prefix_length < prefix_limit and left[prefix_length] == right[prefix_length]:
        prefix_length += 1

    suffix_length = 0
    suffix_limit = min(len(left) - prefix_length, len(right) - prefix_length)
    while (
        suffix_length < suffix_limit
        and left[len(left) - suffix_length - 1] == right[len(right) - suffix_length - 1]
    ):
        suffix_length += 1

    left_middle_end = len(left) - suffix_length if suffix_length else len(left)
    right_middle_end = len(right) - suffix_length if suffix_length else len(right)
    prefix = left[:prefix_length]
    left_middle = left[prefix_length:left_middle_end]
    right_middle = right[prefix_length:right_middle_end]
    suffix = left[left_middle_end:] if suffix_length else ""

    left_segments: list[DiffSegment] = []
    right_segments: list[DiffSegment] = []
    _append_segment(left_segments, prefix, "equal")
    _append_segment(right_segments, prefix, "equal")
    _append_segment(left_segments, left_middle, "removed")
    _append_segment(right_segments, right_middle, "added")
    _append_segment(left_segments, suffix, "equal")
    _append_segment(right_segments, suffix, "equal")

    return (
        tuple(left_segments),
        tuple(right_segments),
        _metrics_for_change(removed=left_middle, added=right_middle),
    )


def _append_segment(segments: list[DiffSegment], text: str, change: ChangeKind) -> None:
    """Append non-empty text, coalescing adjacent segments of the same type."""
    if not text:
        return
    if segments and segments[-1].change == change and segments[-1].marker is None:
        segments[-1] = replace(segments[-1], text=segments[-1].text + text)
    else:
        segments.append(DiffSegment(text=text, change=change))


def _segments_to_lines(segments: tuple[DiffSegment, ...], start_line: int) -> tuple[DiffLine, ...]:
    """Split semantic segments into numbered lines with visible changed whitespace."""
    if not segments:
        return ()

    lines: list[DiffLine] = []
    current_segments: list[DiffSegment] = []
    current_line = start_line
    ended_with_newline = False

    for segment in segments:
        for part in _WHITESPACE_PARTS.split(segment.text):
            if not part:
                continue
            if _LINE_BREAKS.fullmatch(part):
                if segment.change != "equal":
                    current_segments.append(DiffSegment("↵", segment.change, marker="newline"))
                lines.append(DiffLine(current_line, tuple(current_segments)))
                current_segments = []
                current_line += 1
                ended_with_newline = True
            elif part == "\t" and segment.change != "equal":
                current_segments.append(DiffSegment("→", segment.change, marker="tab"))
                ended_with_newline = False
            else:
                _append_segment(current_segments, part, segment.change)
                ended_with_newline = False

    if current_segments or not lines or not ended_with_newline:
        lines.append(DiffLine(current_line, tuple(current_segments)))
    return tuple(lines)


def _collapse_equal_context(blocks: list[DiffBlock], context_lines: int) -> list[DiffBlock]:
    """Replace distant unchanged lines with deterministic context markers."""
    if len(blocks) == 1 and blocks[0].kind == "equal":
        return blocks

    collapsed: list[DiffBlock] = []
    for index, block in enumerate(blocks):
        if block.kind != "equal":
            collapsed.append(block)
            continue

        line_count = len(block.left_lines)
        at_start = index == 0
        at_end = index == len(blocks) - 1
        keep_before = 0 if at_start else context_lines
        keep_after = 0 if at_end else context_lines
        if at_start:
            keep_after = context_lines
        if at_end:
            keep_before = context_lines

        if line_count <= keep_before + keep_after:
            collapsed.append(block)
            continue

        hidden_count = line_count - keep_before - keep_after
        if keep_before:
            collapsed.append(_slice_equal_block(block, 0, keep_before))
        collapsed.append(DiffBlock("context", (), (), collapsed_line_count=hidden_count))
        if keep_after:
            collapsed.append(_slice_equal_block(block, line_count - keep_after, line_count))

    return collapsed


def _slice_equal_block(block: DiffBlock, start: int, end: int) -> DiffBlock:
    return DiffBlock(
        kind="equal",
        left_lines=block.left_lines[start:end],
        right_lines=block.right_lines[start:end],
    )


def _empty_metrics() -> dict[str, int]:
    return {
        "added_characters": 0,
        "removed_characters": 0,
        "added_line_breaks": 0,
        "removed_line_breaks": 0,
    }


def _metrics_for_change(*, added: str = "", removed: str = "") -> dict[str, int]:
    return {
        "added_characters": _count_non_control_characters(added),
        "removed_characters": _count_non_control_characters(removed),
        "added_line_breaks": len(_LINE_BREAKS.findall(added)),
        "removed_line_breaks": len(_LINE_BREAKS.findall(removed)),
    }


def _count_non_control_characters(value: str) -> int:
    return len(_LINE_BREAKS.sub("", value).replace("\t", ""))


def _add_metrics(totals: dict[str, int], addition: dict[str, int]) -> None:
    for key, value in addition.items():
        totals[key] += value

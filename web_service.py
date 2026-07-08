from __future__ import annotations

import copy
import difflib
import json
import uuid
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Optional

from globals import get_config
from matching import fuzzy_match_findings
from merge import (
    ResolvedWinner,
    get_auto_suggest_values,
    get_single_sided_content_choice,
    normalise_merge_pair,
    renumber_findings,
)
from model import Finding, get_type_as_str, is_optional_field
from sensitivity import apply_sensitive_replacement, check_for_sensitivities
from utils import blank_for_type, normalise_finding_record, stringify_field, wrap_string

CONFIG = get_config()


class WebMergeError(ValueError):
    """Raised when uploaded data or review decisions cannot be processed."""


@dataclass
class ConflictReviewItem:
    match_index: int
    field_name: str
    left_value: Any
    right_value: Any
    offered_value: Any
    offered_side: str
    field_type: str
    is_optional: bool
    allow_merge: bool
    diff_rows: list[dict[str, str]]


@dataclass
class SensitivityReviewItem:
    side: str
    record_index: int
    field_name: str
    field_value: Any
    sensitive_term: str
    offered: Optional[str]
    hit_index: int
    highlighted_parts: list[dict[str, Any]]


@dataclass
class MergeResult:
    left_records: list[dict[str, Any]]
    right_records: list[dict[str, Any]]


@dataclass
class MergeJob:
    job_id: str
    matches: list[dict[str, Any]]
    unmatched_left: list[Finding]
    unmatched_right: list[Finding]
    merged_left: list[Finding]
    merged_right: list[Finding]
    match_index: int = 0
    field_index: int = 0
    conflict_phase_complete: bool = False
    sensitivity_phase_complete: bool = False
    sensitivity_side: str = "left"
    sensitivity_record_index: int = 0
    sensitivity_field_index: int = 0
    sensitivity_hit_index: int = 0
    final_left: Optional[list[Finding]] = None
    final_right: Optional[list[Finding]] = None
    preview_acknowledged: bool = False
    input_sources: dict[str, str] = field(default_factory=lambda: {"left": "file", "right": "file"})
    sync_results: dict[str, Any] = field(default_factory=dict)


@dataclass
class MatchPreviewItem:
    match_index: int
    score: float
    rows: list[dict[str, Any]]


@dataclass
class PreviousJobItem:
    job_id: str
    phase: str
    matches: int
    completed_matches: int
    has_left_output: bool
    has_right_output: bool
    sync_results: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


def load_records_from_json_text(json_text: str) -> list[dict[str, Any]]:
    """Parse uploaded JSON text and require the GhostMerge list-of-records shape."""
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise WebMergeError(f"Invalid JSON: {exc.msg}") from exc

    if not isinstance(data, list):
        raise WebMergeError("JSON input must be a list of finding records.")
    if not all(isinstance(item, dict) for item in data):
        raise WebMergeError("Every finding record must be a JSON object.")
    return data


def parse_findings(records: list[dict[str, Any]]) -> list[Finding]:
    """Convert raw dictionaries to Finding objects using the existing model rules."""
    findings: list[Finding] = []
    for index, record in enumerate(records, start=1):
        try:
            finding = Finding.from_dict(record)
        except Exception as exc:
            raise WebMergeError(f"Finding {index} could not be parsed.") from exc
        if finding is not None:
            findings.append(finding)
    return findings


def create_merge_job(
    left_records: list[dict[str, Any]],
    right_records: list[dict[str, Any]],
    job_id: Optional[str] = None,
    input_sources: Optional[dict[str, str]] = None,
) -> MergeJob:
    """Create a merge job and run the existing fuzzy matching rounds."""
    findings_left = parse_findings(left_records)
    findings_right = parse_findings(right_records)

    matches: list[dict[str, Any]] = []
    unmatched_left = findings_left
    unmatched_right = findings_right
    for fuzzy_threshold in CONFIG["fuzzy_match_threshold"]:
        new_matches, unmatched_left, unmatched_right = fuzzy_match_findings(
            unmatched_left,
            unmatched_right,
            fuzzy_threshold,
        )
        for match in new_matches:
            normalise_merge_pair(match)
            auto_value, auto_side = get_auto_suggest_values(match["left"], match["right"])
            match["auto_value"] = auto_value
            match["auto_side"] = auto_side
            normalise_merge_pair(match)
        matches.extend(new_matches)

    return MergeJob(
        job_id=job_id or uuid.uuid4().hex,
        matches=matches,
        unmatched_left=unmatched_left,
        unmatched_right=unmatched_right,
        merged_left=[],
        merged_right=[],
        input_sources=input_sources or {"left": "file", "right": "file"},
    )


def get_next_conflict(job: MergeJob) -> Optional[ConflictReviewItem]:
    """Return the next field-level conflict, auto-applying fields that do not need review."""
    while job.match_index < len(job.matches):
        match = job.matches[job.match_index]
        field_defs = list(fields(Finding))

        while job.field_index < len(field_defs):
            field_def = field_defs[job.field_index]
            job.field_index += 1
            if field_def.name == "id":
                continue

            item = _prepare_conflict_for_field(job.match_index, match, field_def)
            if item is not None:
                return item

        job.merged_left.append(match["left"])
        job.merged_right.append(match["right"])
        job.match_index += 1
        job.field_index = 0
        job.preview_acknowledged = False

    _append_unmatched_records(job)
    job.conflict_phase_complete = True
    return None


def get_current_match_preview(job: MergeJob) -> Optional[MatchPreviewItem]:
    """Return whole-record preview data for the current matched pair."""
    if job.conflict_phase_complete or job.match_index >= len(job.matches):
        return None

    match = job.matches[job.match_index]
    rows = []
    for field_def in fields(Finding):
        expected_type = get_type_as_str(field_def.type)
        left_value = getattr(match["left"], field_def.name, blank_for_type(expected_type))
        right_value = getattr(match["right"], field_def.name, blank_for_type(expected_type))
        offered_value = match["auto_value"].get(field_def.name)
        requires_review = field_def.name != "id" and left_value != right_value
        rows.append(
            {
                "field_name": field_def.name,
                "left_value": stringify_field(left_value),
                "right_value": stringify_field(right_value),
                "offered_value": stringify_field(offered_value),
                "different": requires_review,
                "diff_rows": (
                    build_field_diff(left_value, right_value, offered_value)
                    if requires_review
                    else []
                ),
            }
        )

    return MatchPreviewItem(
        match_index=job.match_index,
        score=float(match["score"]),
        rows=rows,
    )


def acknowledge_current_preview(job: MergeJob) -> None:
    if job.conflict_phase_complete or job.match_index >= len(job.matches):
        raise WebMergeError("There is no active match preview.")
    job.preview_acknowledged = True


def accept_offered_for_current_match(job: MergeJob) -> None:
    """Apply every offered value for the current matched pair and advance."""
    if job.conflict_phase_complete or job.match_index >= len(job.matches):
        raise WebMergeError("There is no active match to accept.")

    match = job.matches[job.match_index]
    for field_def in fields(Finding):
        if field_def.name == "id":
            continue
        offered_value = match["auto_value"].get(field_def.name)
        match["left"].set(field_def.name, offered_value)
        match["right"].set(field_def.name, offered_value)

    job.merged_left.append(match["left"])
    job.merged_right.append(match["right"])
    job.match_index += 1
    job.field_index = 0
    job.preview_acknowledged = False


def accept_offered_fields_for_current_match(job: MergeJob, field_names: list[str]) -> int:
    """Apply offered values for selected preview fields, then continue field review."""
    if job.conflict_phase_complete or job.match_index >= len(job.matches):
        raise WebMergeError("There is no active match to update.")

    selected = {name for name in field_names if name and name != "id"}
    if not selected:
        job.preview_acknowledged = True
        return 0

    match = job.matches[job.match_index]
    valid_fields = {field_def.name for field_def in fields(Finding)}
    applied = 0
    for field_name in selected:
        if field_name not in valid_fields:
            raise WebMergeError(f"Unknown field selected: {field_name}")
        offered_value = match["auto_value"].get(field_name)
        match["left"].set(field_name, offered_value)
        match["right"].set(field_name, offered_value)
        applied += 1

    job.preview_acknowledged = True
    return applied


def apply_conflict_decision(job: MergeJob, decision: dict[str, Any]) -> None:
    """Apply a submitted field decision to the current matched pair."""
    if job.conflict_phase_complete or job.match_index >= len(job.matches):
        raise WebMergeError("There is no active conflict to update.")

    match = job.matches[job.match_index]
    field_name = str(decision.get("field_name", ""))
    action = str(decision.get("action", ""))
    field_def = next((item for item in fields(Finding) if item.name == field_name), None)
    if field_def is None or field_name == "id":
        raise WebMergeError("Unknown or unsupported field decision.")

    left_value = getattr(match["left"], field_name)
    right_value = getattr(match["right"], field_name)
    offered_value = match["auto_value"].get(field_name)
    expected_type = get_type_as_str(field_def.type)

    if action == "keep":
        new_left, new_right = left_value, right_value
    elif action == "left":
        new_left = new_right = left_value
    elif action == "right":
        new_left = new_right = right_value
    elif action == "offered":
        new_left = new_right = offered_value
    elif action == "blank" and is_optional_field(expected_type):
        new_left = new_right = blank_for_type(expected_type)
    elif action == "merge" and "str" in expected_type:
        new_left = new_right = f"{left_value} {right_value}"
    elif action == "custom" and "str" in expected_type:
        new_left = new_right = str(decision.get("custom_value", ""))
    else:
        raise WebMergeError("Unsupported conflict decision.")

    match["left"].set(field_name, new_left)
    match["right"].set(field_name, new_right)


def get_next_sensitivity_item(
    job: MergeJob,
    terms: Optional[dict[str, Optional[str]]],
) -> Optional[SensitivityReviewItem]:
    """Return the next post-merge sensitivity item that requires human review."""
    if not job.conflict_phase_complete:
        raise WebMergeError("Conflict review must be complete before sensitivity review.")
    if not terms:
        job.sensitivity_phase_complete = True
        return None

    sides = {"left": job.merged_left, "right": job.merged_right}
    field_defs = list(fields(Finding))

    while job.sensitivity_side in sides:
        records = sides[job.sensitivity_side]
        while job.sensitivity_record_index < len(records):
            record = records[job.sensitivity_record_index]
            while job.sensitivity_field_index < len(field_defs):
                field_def = field_defs[job.sensitivity_field_index]
                if field_def.name == "id" or not record.get(field_def.name):
                    job.sensitivity_hit_index = 0
                    job.sensitivity_field_index += 1
                    continue
                hits = check_for_sensitivities(record.get(field_def.name), terms)
                if hits and job.sensitivity_hit_index < len(hits):
                    sensitive_term, offered = hits[job.sensitivity_hit_index]
                    return SensitivityReviewItem(
                        side=job.sensitivity_side,
                        record_index=job.sensitivity_record_index,
                        field_name=field_def.name,
                        field_value=record.get(field_def.name),
                        sensitive_term=sensitive_term,
                        offered=offered,
                        hit_index=job.sensitivity_hit_index,
                        highlighted_parts=_highlight_term_parts(record.get(field_def.name), sensitive_term),
                    )
                job.sensitivity_hit_index = 0
                job.sensitivity_field_index += 1
            job.sensitivity_field_index = 0
            job.sensitivity_hit_index = 0
            job.sensitivity_record_index += 1

        if job.sensitivity_side == "left":
            job.sensitivity_side = "right"
            job.sensitivity_record_index = 0
            job.sensitivity_field_index = 0
            job.sensitivity_hit_index = 0
        else:
            break

    job.sensitivity_phase_complete = True
    return None


def apply_sensitivity_decision(job: MergeJob, decision: dict[str, Any]) -> None:
    """Apply a sensitivity-review decision to the selected output record."""
    side = str(decision.get("side", ""))
    records = {"left": job.merged_left, "right": job.merged_right}.get(side)
    if records is None:
        raise WebMergeError("Unknown sensitivity decision side.")

    record_index = int(decision.get("record_index", -1))
    field_name = str(decision.get("field_name", ""))
    sensitive_term = str(decision.get("sensitive_term", ""))
    action = str(decision.get("action", ""))
    if record_index < 0 or record_index >= len(records):
        raise WebMergeError("Unknown sensitivity decision record.")

    record = records[record_index]
    if action == "keep":
        job.sensitivity_hit_index += 1
        return
    if action == "offered":
        replacement = decision.get("offered")
    elif action == "custom":
        replacement = decision.get("custom_value", "")
    else:
        raise WebMergeError("Unsupported sensitivity decision.")

    record.set(field_name, apply_sensitive_replacement(record.get(field_name), sensitive_term, replacement))
    job.sensitivity_hit_index = 0


def finalise_job(job: MergeJob) -> MergeResult:
    """Renumber and serialise final left/right output records."""
    if not job.conflict_phase_complete:
        raise WebMergeError("Conflict review must be complete before finalising output.")

    left = [copy.deepcopy(item) for item in job.merged_left]
    right = [copy.deepcopy(item) for item in job.merged_right]
    left, right = renumber_findings(left, right, start_id=1)
    job.final_left = left
    job.final_right = right
    return MergeResult(
        left_records=[item.to_dict() for item in left],
        right_records=[item.to_dict() for item in right],
    )


def save_job(job: MergeJob, jobs_dir: Path) -> Path:
    """Persist a job to a local job directory."""
    job_dir = _job_dir(jobs_dir, job.job_id)
    job_dir.mkdir(parents=True, exist_ok=True)
    job_path = job_dir / "job.json"
    _write_json_atomic(job_path, job_to_dict(job))
    return job_path


def load_job(jobs_dir: Path, job_id: str) -> MergeJob:
    """Load a persisted job by opaque ID."""
    if not job_id or not job_id.isalnum():
        raise WebMergeError("Invalid job ID.")
    job_path = _job_dir(jobs_dir, job_id) / "job.json"
    if not job_path.exists():
        raise WebMergeError("Job not found.")
    try:
        data = json.loads(job_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WebMergeError("Job state could not be read. Please refresh and try again.") from exc
    return job_from_dict(data)


def list_previous_jobs(jobs_dir: Path) -> list[PreviousJobItem]:
    """Return persisted jobs that can be resumed or downloaded from the home page."""
    if not jobs_dir.exists():
        return []

    jobs = []
    for job_path in sorted(jobs_dir.glob("*/job.json"), key=lambda path: path.stat().st_mtime, reverse=True):
        job_dir = job_path.parent
        try:
            job = job_from_dict(json.loads(job_path.read_text(encoding="utf-8")))
        except Exception as exc:
            jobs.append(
                PreviousJobItem(
                    job_id=job_dir.name,
                    phase="error",
                    matches=0,
                    completed_matches=0,
                    has_left_output=(job_dir / "left.json").exists(),
                    has_right_output=(job_dir / "right.json").exists(),
                    error=f"Job state could not be read: {exc}",
                )
            )
            continue
        progress = get_review_progress(job)
        jobs.append(
            PreviousJobItem(
                job_id=job.job_id,
                phase=str(progress["phase"]),
                matches=int(progress["total_matches"]),
                completed_matches=min(int(progress["completed_matches"]), int(progress["total_matches"])),
                has_left_output=(job_dir / "left.json").exists(),
                has_right_output=(job_dir / "right.json").exists(),
                sync_results=job.sync_results,
            )
        )
    return jobs


def save_outputs(job: MergeJob, jobs_dir: Path, result: MergeResult) -> None:
    job_dir = _job_dir(jobs_dir, job.job_id)
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "left.json").write_text(json.dumps(result.left_records, indent=2), encoding="utf-8")
    (job_dir / "right.json").write_text(json.dumps(result.right_records, indent=2), encoding="utf-8")


def job_summary(job: MergeJob) -> dict[str, int | bool | str]:
    summary = get_review_progress(job)
    summary.update({
        "job_id": job.job_id,
        "matches": len(job.matches),
        "unmatched_left": len(job.unmatched_left),
        "unmatched_right": len(job.unmatched_right),
        "merged": len(job.merged_left),
        "conflict_phase_complete": job.conflict_phase_complete,
        "sensitivity_phase_complete": job.sensitivity_phase_complete,
        "sync_results": job.sync_results,
    })
    return summary


def get_review_progress(job: MergeJob) -> dict[str, int | bool | str]:
    phase = "conflicts"
    if job.conflict_phase_complete and not job.sensitivity_phase_complete:
        phase = "sensitivity"
    elif job.conflict_phase_complete and job.sensitivity_phase_complete:
        phase = "complete"

    return {
        "phase": phase,
        "current_match": min(job.match_index + 1, len(job.matches)) if job.matches else 0,
        "total_matches": len(job.matches),
        "completed_matches": len(job.merged_left),
        "current_field": job.field_index,
        "total_fields": len(fields(Finding)),
        "preview_acknowledged": job.preview_acknowledged,
        "unmatched_left": len(job.unmatched_left),
        "unmatched_right": len(job.unmatched_right),
    }


def build_field_diff(left_value: Any, right_value: Any, offered_value: Any = None) -> list[dict[str, str]]:
    """Build template-friendly diff rows for left, right, and offered field values."""
    left_text = _wrap_for_web_diff(left_value)
    right_text = _wrap_for_web_diff(right_value)
    rows = []
    for line in difflib.ndiff(left_text.splitlines(), right_text.splitlines()):
        code = line[:2]
        value = line[2:]
        if code == "- ":
            rows.append({"side": "left", "class": "removed", "text": value})
        elif code == "+ ":
            rows.append({"side": "right", "class": "added", "text": value})
        elif code == "  ":
            rows.append({"side": "both", "class": "same", "text": value})

    if offered_value not in (None, ""):
        rows.append({"side": "offered", "class": "offered", "text": _wrap_for_web_diff(offered_value)})

    return rows


def job_to_dict(job: MergeJob) -> dict[str, Any]:
    data = asdict(job)
    data["matches"] = [
        {
            "left": _finding_to_state(match["left"]),
            "right": _finding_to_state(match["right"]),
            "score": match["score"],
            "auto_value": _finding_to_state(match["auto_value"]),
            "auto_side": _winners_to_state(match["auto_side"]),
        }
        for match in job.matches
    ]
    for key in ("unmatched_left", "unmatched_right", "merged_left", "merged_right", "final_left", "final_right"):
        value = getattr(job, key)
        data[key] = None if value is None else [_finding_to_state(item) for item in value]
    return data


def job_from_dict(data: dict[str, Any]) -> MergeJob:
    return MergeJob(
        job_id=data["job_id"],
        matches=[
            {
                "left": _finding_from_state(match["left"]),
                "right": _finding_from_state(match["right"]),
                "score": match["score"],
                "auto_value": _finding_from_state(match["auto_value"]),
                "auto_side": _winners_from_state(match["auto_side"]),
            }
            for match in data["matches"]
        ],
        unmatched_left=[_finding_from_state(item) for item in data["unmatched_left"]],
        unmatched_right=[_finding_from_state(item) for item in data["unmatched_right"]],
        merged_left=[_finding_from_state(item) for item in data["merged_left"]],
        merged_right=[_finding_from_state(item) for item in data["merged_right"]],
        match_index=data["match_index"],
        field_index=data["field_index"],
        conflict_phase_complete=data["conflict_phase_complete"],
        sensitivity_phase_complete=data["sensitivity_phase_complete"],
        sensitivity_side=data["sensitivity_side"],
        sensitivity_record_index=data["sensitivity_record_index"],
        sensitivity_field_index=data["sensitivity_field_index"],
        sensitivity_hit_index=data.get("sensitivity_hit_index", 0),
        final_left=None if data["final_left"] is None else [_finding_from_state(item) for item in data["final_left"]],
        final_right=None if data["final_right"] is None else [_finding_from_state(item) for item in data["final_right"]],
        preview_acknowledged=data.get("preview_acknowledged", False),
        input_sources=data.get("input_sources", {"left": "file", "right": "file"}),
        sync_results=data.get("sync_results", {}),
    )


def _prepare_conflict_for_field(match_index: int, match: dict[str, Any], field_def: Any) -> Optional[ConflictReviewItem]:
    field_name = field_def.name
    expected_type = get_type_as_str(field_def.type)
    left_value = getattr(match["left"], field_name, blank_for_type(expected_type))
    right_value = getattr(match["right"], field_name, blank_for_type(expected_type))
    offered_value = match["auto_value"].get(field_name)
    offered_side = match["auto_side"].get(field_name)

    if left_value == right_value:
        match["left"].set(field_name, offered_value)
        match["right"].set(field_name, offered_value)
        return None

    should_auto_accept, _, populated_value = get_single_sided_content_choice(left_value, right_value)
    if CONFIG.get("auto_accept_single_sided_content", False) and should_auto_accept:
        match["left"].set(field_name, populated_value)
        match["right"].set(field_name, populated_value)
        return None

    return ConflictReviewItem(
        match_index=match_index,
        field_name=field_name,
        left_value=left_value,
        right_value=right_value,
        offered_value=offered_value,
        offered_side=_winner_to_state(offered_side),
        field_type=expected_type,
        is_optional=is_optional_field(expected_type),
        allow_merge="str" in expected_type,
        diff_rows=build_field_diff(left_value, right_value, offered_value),
    )


def _append_unmatched_records(job: MergeJob) -> None:
    if job.conflict_phase_complete:
        return
    for record in job.unmatched_left:
        normalise_finding_record(record)
        job.merged_left.append(record)
        job.merged_right.append(copy.deepcopy(record))
    for record in job.unmatched_right:
        normalise_finding_record(record)
        job.merged_left.append(copy.deepcopy(record))
        job.merged_right.append(record)


def _finding_to_state(finding: Finding) -> dict[str, Any]:
    return asdict(finding)


def _finding_from_state(data: dict[str, Any]) -> Finding:
    return Finding(**data)


def _winner_to_state(winner: Any) -> Any:
    if isinstance(winner, ResolvedWinner):
        return winner.name
    if isinstance(winner, dict):
        return _winners_to_state(winner)
    return winner


def _winners_to_state(winners: dict[str, Any]) -> dict[str, Any]:
    return {key: _winner_to_state(value) for key, value in winners.items()}


def _winners_from_state(winners: dict[str, Any]) -> dict[str, Any]:
    restored = {}
    for key, value in winners.items():
        if isinstance(value, dict):
            restored[key] = _winners_from_state(value)
        elif isinstance(value, str) and value in ResolvedWinner.__members__:
            restored[key] = ResolvedWinner[value]
        else:
            restored[key] = value
    return restored


def _job_dir(jobs_dir: Path, job_id: str) -> Path:
    if not job_id or not job_id.isalnum():
        raise WebMergeError("Invalid job ID.")
    return jobs_dir / job_id


def _write_json_atomic(path: Path, data: Any) -> None:
    """Write JSON via same-directory replace so readers never see partial state."""
    tmp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def _wrap_for_web_diff(value: Any) -> str:
    width = CONFIG.get("field_level_diff_max_width", 114)
    return wrap_string(stringify_field(value), width)


def _highlight_term_parts(value: Any, term: str) -> list[dict[str, Any]]:
    text = stringify_field(value)
    lowered = text.lower()
    term_lowered = term.lower()
    if not term_lowered:
        return [{"text": text, "hit": False}]

    parts = []
    cursor = 0
    while True:
        index = lowered.find(term_lowered, cursor)
        if index < 0:
            break
        if index > cursor:
            parts.append({"text": text[cursor:index], "hit": False})
        end = index + len(term)
        parts.append({"text": text[index:end], "hit": True})
        cursor = end
    if cursor < len(text):
        parts.append({"text": text[cursor:], "hit": False})
    return parts or [{"text": text, "hit": False}]

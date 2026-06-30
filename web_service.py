from __future__ import annotations

import copy
import json
import uuid
from dataclasses import asdict, dataclass, fields
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
from utils import blank_for_type, normalise_finding_record

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


@dataclass
class SensitivityReviewItem:
    side: str
    record_index: int
    field_name: str
    field_value: Any
    sensitive_term: str
    offered: Optional[str]


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
    final_left: Optional[list[Finding]] = None
    final_right: Optional[list[Finding]] = None


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

    _append_unmatched_records(job)
    job.conflict_phase_complete = True
    return None


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
                job.sensitivity_field_index += 1
                if field_def.name == "id" or not record.get(field_def.name):
                    continue
                hits = check_for_sensitivities(record.get(field_def.name), terms)
                if hits:
                    sensitive_term, offered = hits[0]
                    return SensitivityReviewItem(
                        side=job.sensitivity_side,
                        record_index=job.sensitivity_record_index,
                        field_name=field_def.name,
                        field_value=record.get(field_def.name),
                        sensitive_term=sensitive_term,
                        offered=offered,
                    )
            job.sensitivity_field_index = 0
            job.sensitivity_record_index += 1

        if job.sensitivity_side == "left":
            job.sensitivity_side = "right"
            job.sensitivity_record_index = 0
            job.sensitivity_field_index = 0
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
        return
    if action == "offered":
        replacement = decision.get("offered")
    elif action == "custom":
        replacement = decision.get("custom_value", "")
    else:
        raise WebMergeError("Unsupported sensitivity decision.")

    record.set(field_name, apply_sensitive_replacement(record.get(field_name), sensitive_term, replacement))


def finalise_job(job: MergeJob) -> MergeResult:
    """Renumber and serialise final left/right output records."""
    if not job.conflict_phase_complete:
        get_next_conflict(job)

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
    job_path.write_text(json.dumps(job_to_dict(job), indent=2), encoding="utf-8")
    return job_path


def load_job(jobs_dir: Path, job_id: str) -> MergeJob:
    """Load a persisted job by opaque ID."""
    if not job_id or not job_id.isalnum():
        raise WebMergeError("Invalid job ID.")
    job_path = _job_dir(jobs_dir, job_id) / "job.json"
    if not job_path.exists():
        raise WebMergeError("Job not found.")
    return job_from_dict(json.loads(job_path.read_text(encoding="utf-8")))


def save_outputs(job: MergeJob, jobs_dir: Path, result: MergeResult) -> None:
    job_dir = _job_dir(jobs_dir, job.job_id)
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "left.json").write_text(json.dumps(result.left_records, indent=2), encoding="utf-8")
    (job_dir / "right.json").write_text(json.dumps(result.right_records, indent=2), encoding="utf-8")


def job_summary(job: MergeJob) -> dict[str, int | bool | str]:
    return {
        "job_id": job.job_id,
        "matches": len(job.matches),
        "unmatched_left": len(job.unmatched_left),
        "unmatched_right": len(job.unmatched_right),
        "merged": len(job.merged_left),
        "conflict_phase_complete": job.conflict_phase_complete,
        "sensitivity_phase_complete": job.sensitivity_phase_complete,
    }


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
        final_left=None if data["final_left"] is None else [_finding_from_state(item) for item in data["final_left"]],
        final_right=None if data["final_right"] is None else [_finding_from_state(item) for item in data["final_right"]],
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

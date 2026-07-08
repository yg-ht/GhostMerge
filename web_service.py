from __future__ import annotations

import copy
import difflib
import json
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from globals import get_config
from matching import fuzzy_match_records
from merge import (
    ResolvedWinner,
    get_auto_suggest_values,
    get_single_sided_content_choice,
    normalise_merge_pair,
    renumber_records,
)
from model import Finding, Observation, get_type_as_str, is_optional_field
from sensitivity import apply_sensitive_replacement, check_for_sensitivities
from utils import blank_for_type, normalise_finding_record, stringify_field, wrap_string

CONFIG = get_config()
NON_REVIEWABLE_FIELDS = {"id"}
TEMPLATE_KINDS = ("finding", "observation")
TEMPLATE_MODELS = {"finding": Finding, "observation": Observation}
TEMPLATE_PLURALS = {"finding": "findings", "observation": "observations"}


class WebMergeError(ValueError):
    """Raised when uploaded data or review decisions cannot be processed."""


@dataclass
class ConflictReviewItem:
    template_type: str
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
    template_type: str
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
    left_observations: list[dict[str, Any]] = field(default_factory=list)
    right_observations: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class MergeJob:
    job_id: str
    matches: list[dict[str, Any]]
    unmatched_left: list[Finding]
    unmatched_right: list[Finding]
    merged_left: list[Finding]
    merged_right: list[Finding]
    observation_matches: list[dict[str, Any]] = field(default_factory=list)
    unmatched_observations_left: list[Observation] = field(default_factory=list)
    unmatched_observations_right: list[Observation] = field(default_factory=list)
    merged_observations_left: list[Observation] = field(default_factory=list)
    merged_observations_right: list[Observation] = field(default_factory=list)
    match_index: int = 0
    field_index: int = 0
    finding_conflict_phase_complete: bool = False
    observation_match_index: int = 0
    observation_field_index: int = 0
    observation_conflict_phase_complete: bool = False
    conflict_phase_complete: bool = False
    sensitivity_phase_complete: bool = False
    sensitivity_template_type: str = "finding"
    sensitivity_side: str = "left"
    sensitivity_record_index: int = 0
    sensitivity_field_index: int = 0
    sensitivity_hit_index: int = 0
    final_left: Optional[list[Finding]] = None
    final_right: Optional[list[Finding]] = None
    final_observations_left: Optional[list[Observation]] = None
    final_observations_right: Optional[list[Observation]] = None
    preview_acknowledged: bool = False
    input_sources: dict[str, str] = field(default_factory=lambda: {"left": "file", "right": "file"})
    sync_results: dict[str, Any] = field(default_factory=dict)
    includes_observations: bool = False


@dataclass
class MatchPreviewItem:
    template_type: str
    match_index: int
    score: float
    rows: list[dict[str, Any]]


@dataclass
class PreviousJobItem:
    job_id: str
    phase: str
    matches: int
    completed_matches: int
    updated_at: str
    has_left_output: bool
    has_right_output: bool
    sync_results: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


def load_records_from_json_text(json_text: str) -> list[dict[str, Any]] | dict[str, list[dict[str, Any]]]:
    """Parse uploaded JSON text and require the GhostMerge list-of-records shape."""
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise WebMergeError(f"Invalid JSON: {exc.msg}") from exc

    if isinstance(data, list):
        if not all(isinstance(item, dict) for item in data):
            raise WebMergeError("Every finding record must be a JSON object.")
        return data

    if isinstance(data, dict):
        if "findings" not in data and "observations" not in data:
            raise WebMergeError("Combined JSON input must contain findings or observations.")
        findings = data.get("findings", [])
        observations = data.get("observations", [])
        if not isinstance(findings, list) or not isinstance(observations, list):
            raise WebMergeError("Combined JSON input must contain list values for findings and observations.")
        if not all(isinstance(item, dict) for item in findings + observations):
            raise WebMergeError("Every template record must be a JSON object.")
        return {"findings": findings, "observations": observations}

    raise WebMergeError("JSON input must be a list of finding records or a combined template object.")


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


def parse_observations(records: list[dict[str, Any]]) -> list[Observation]:
    """Convert raw dictionaries to Observation objects using the observation model rules."""
    observations: list[Observation] = []
    for index, record in enumerate(records, start=1):
        try:
            observation = Observation.from_dict(record)
        except Exception as exc:
            raise WebMergeError(f"Observation {index} could not be parsed.") from exc
        if observation is not None:
            observations.append(observation)
    return observations


def split_template_records(records: list[dict[str, Any]] | dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Return finding and observation lists from legacy or combined input."""
    if isinstance(records, list):
        return {"findings": records, "observations": []}
    return {
        "findings": list(records.get("findings") or []),
        "observations": list(records.get("observations") or []),
    }


def create_merge_job(
    left_records: list[dict[str, Any]] | dict[str, list[dict[str, Any]]],
    right_records: list[dict[str, Any]] | dict[str, list[dict[str, Any]]],
    job_id: Optional[str] = None,
    input_sources: Optional[dict[str, str]] = None,
) -> MergeJob:
    """Create a merge job and run the existing fuzzy matching rounds."""
    includes_observations = _input_includes_observations(left_records) or _input_includes_observations(right_records)
    left_templates = split_template_records(left_records)
    right_templates = split_template_records(right_records)
    findings_left = parse_findings(left_templates["findings"])
    findings_right = parse_findings(right_templates["findings"])
    observations_left = parse_observations(left_templates["observations"])
    observations_right = parse_observations(right_templates["observations"])

    matches: list[dict[str, Any]] = []
    unmatched_left = findings_left
    unmatched_right = findings_right
    for fuzzy_threshold in CONFIG["fuzzy_match_threshold"]:
        new_matches, unmatched_left, unmatched_right = fuzzy_match_records(
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

    observation_matches: list[dict[str, Any]] = []
    unmatched_observations_left = observations_left
    unmatched_observations_right = observations_right
    for fuzzy_threshold in CONFIG["fuzzy_match_threshold"]:
        new_matches, unmatched_observations_left, unmatched_observations_right = fuzzy_match_records(
            unmatched_observations_left,
            unmatched_observations_right,
            fuzzy_threshold,
        )
        for match in new_matches:
            normalise_merge_pair(match)
            auto_value, auto_side = get_auto_suggest_values(match["left"], match["right"])
            match["auto_value"] = auto_value
            match["auto_side"] = auto_side
            normalise_merge_pair(match)
        observation_matches.extend(new_matches)

    return MergeJob(
        job_id=job_id or uuid.uuid4().hex,
        matches=matches,
        unmatched_left=unmatched_left,
        unmatched_right=unmatched_right,
        merged_left=[],
        merged_right=[],
        observation_matches=observation_matches,
        unmatched_observations_left=unmatched_observations_left,
        unmatched_observations_right=unmatched_observations_right,
        merged_observations_left=[],
        merged_observations_right=[],
        input_sources=input_sources or {"left": "file", "right": "file"},
        includes_observations=includes_observations,
    )


def get_next_conflict(job: MergeJob) -> Optional[ConflictReviewItem]:
    """Return the next field-level conflict, auto-applying fields that do not need review."""
    item = _get_next_conflict_for_kind(job, "finding")
    if item is not None:
        return item
    item = _get_next_conflict_for_kind(job, "observation")
    if item is not None:
        return item

    job.conflict_phase_complete = True
    return None


def get_current_match_preview(job: MergeJob) -> Optional[MatchPreviewItem]:
    """Return whole-record preview data for the current matched pair."""
    kind = _active_conflict_kind(job)
    if kind is None:
        return None

    match = _matches_for_kind(job, kind)[_match_index_for_kind(job, kind)]
    rows = []
    for field_def in _reviewable_field_defs(kind):
        expected_type = get_type_as_str(field_def.type)
        left_value = getattr(match["left"], field_def.name, blank_for_type(expected_type))
        right_value = getattr(match["right"], field_def.name, blank_for_type(expected_type))
        offered_value = match["auto_value"].get(field_def.name)
        requires_review = left_value != right_value
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
    if not any(row["different"] for row in rows):
        return None

    return MatchPreviewItem(
        template_type=kind,
        match_index=_match_index_for_kind(job, kind),
        score=float(match["score"]),
        rows=rows,
    )


def acknowledge_current_preview(job: MergeJob) -> None:
    if _active_conflict_kind(job) is None:
        raise WebMergeError("There is no active match preview.")
    job.preview_acknowledged = True


def accept_offered_for_current_match(job: MergeJob) -> None:
    """Apply every offered value for the current matched pair and advance."""
    kind = _active_conflict_kind(job)
    if kind is None:
        raise WebMergeError("There is no active match to accept.")

    match = _matches_for_kind(job, kind)[_match_index_for_kind(job, kind)]
    for field_def in _reviewable_field_defs(kind):
        offered_value = match["auto_value"].get(field_def.name)
        match["left"].set(field_def.name, offered_value)
        match["right"].set(field_def.name, offered_value)

    _merged_for_kind(job, kind, "left").append(match["left"])
    _merged_for_kind(job, kind, "right").append(match["right"])
    _set_match_index_for_kind(job, kind, _match_index_for_kind(job, kind) + 1)
    _set_field_index_for_kind(job, kind, 0)
    job.preview_acknowledged = False


def accept_offered_fields_for_current_match(job: MergeJob, field_names: list[str]) -> int:
    """Apply offered values for selected preview fields, then continue field review."""
    kind = _active_conflict_kind(job)
    if kind is None:
        raise WebMergeError("There is no active match to update.")

    selected = {name for name in field_names if name and name not in NON_REVIEWABLE_FIELDS}
    if not selected:
        job.preview_acknowledged = True
        return 0

    match = _matches_for_kind(job, kind)[_match_index_for_kind(job, kind)]
    valid_fields = {field_def.name for field_def in _reviewable_field_defs(kind)}
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


def apply_preview_field_choices(job: MergeJob, choices: dict[str, str]) -> int:
    """Apply explicit left/right/offered choices made on the whole-record preview."""
    kind = _active_conflict_kind(job)
    if kind is None:
        raise WebMergeError("There is no active match to update.")

    valid_fields = {field_def.name for field_def in _reviewable_field_defs(kind)}
    valid_actions = {"left", "right", "offered"}
    match = _matches_for_kind(job, kind)[_match_index_for_kind(job, kind)]
    applied = 0
    for field_name, action in choices.items():
        if field_name not in valid_fields:
            raise WebMergeError(f"Unknown field selected: {field_name}")
        if action not in valid_actions:
            raise WebMergeError("Unsupported preview field choice.")

        if action == "left":
            value = getattr(match["left"], field_name)
        elif action == "right":
            value = getattr(match["right"], field_name)
        else:
            value = match["auto_value"].get(field_name)
        match["left"].set(field_name, value)
        match["right"].set(field_name, value)
        applied += 1

    job.preview_acknowledged = True
    return applied


def apply_conflict_decision(job: MergeJob, decision: dict[str, Any]) -> None:
    """Apply a submitted field decision to the current matched pair."""
    kind = _active_conflict_kind(job)
    if kind is None:
        raise WebMergeError("There is no active conflict to update.")

    match = _matches_for_kind(job, kind)[_match_index_for_kind(job, kind)]
    field_name = str(decision.get("field_name", ""))
    action = str(decision.get("action", ""))
    field_def = next((item for item in _reviewable_field_defs(kind) if item.name == field_name), None)
    if field_def is None:
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

    while job.sensitivity_template_type in TEMPLATE_KINDS:
        sides = {
            "left": _merged_for_kind(job, job.sensitivity_template_type, "left"),
            "right": _merged_for_kind(job, job.sensitivity_template_type, "right"),
        }
        field_defs = list(fields(TEMPLATE_MODELS[job.sensitivity_template_type]))

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
                            template_type=job.sensitivity_template_type,
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

        if job.sensitivity_template_type == "finding":
            job.sensitivity_template_type = "observation"
            job.sensitivity_side = "left"
            job.sensitivity_record_index = 0
            job.sensitivity_field_index = 0
            job.sensitivity_hit_index = 0
            continue
        break

    job.sensitivity_phase_complete = True
    return None


def apply_sensitivity_decision(job: MergeJob, decision: dict[str, Any]) -> None:
    """Apply a sensitivity-review decision to the selected output record."""
    template_type = str(decision.get("template_type") or job.sensitivity_template_type or "finding")
    if template_type not in TEMPLATE_KINDS:
        raise WebMergeError("Unknown sensitivity decision template type.")
    side = str(decision.get("side", ""))
    records = {
        "left": _merged_for_kind(job, template_type, "left"),
        "right": _merged_for_kind(job, template_type, "right"),
    }.get(side)
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
    observations_left = [copy.deepcopy(item) for item in job.merged_observations_left]
    observations_right = [copy.deepcopy(item) for item in job.merged_observations_right]
    left, right = renumber_records(left, right, start_id=1)
    observations_left, observations_right = renumber_records(observations_left, observations_right, start_id=1)
    job.final_left = left
    job.final_right = right
    job.final_observations_left = observations_left
    job.final_observations_right = observations_right
    return MergeResult(
        left_records=[item.to_dict() for item in left],
        right_records=[item.to_dict() for item in right],
        left_observations=[item.to_dict() for item in observations_left],
        right_observations=[item.to_dict() for item in observations_right],
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
        updated_at = _human_file_mtime(job_path)
        try:
            job = job_from_dict(json.loads(job_path.read_text(encoding="utf-8")))
        except Exception as exc:
            jobs.append(
                PreviousJobItem(
                    job_id=job_dir.name,
                    phase="error",
                    matches=0,
                    completed_matches=0,
                    updated_at=updated_at,
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
                updated_at=updated_at,
                has_left_output=(job_dir / "left.json").exists(),
                has_right_output=(job_dir / "right.json").exists(),
                sync_results=job.sync_results,
            )
        )
    return jobs


def save_outputs(job: MergeJob, jobs_dir: Path, result: MergeResult) -> None:
    job_dir = _job_dir(jobs_dir, job.job_id)
    job_dir.mkdir(parents=True, exist_ok=True)
    left_output = _output_payload(result.left_records, result.left_observations)
    right_output = _output_payload(result.right_records, result.right_observations)
    (job_dir / "left.json").write_text(json.dumps(left_output, indent=2), encoding="utf-8")
    (job_dir / "right.json").write_text(json.dumps(right_output, indent=2), encoding="utf-8")


def job_summary(job: MergeJob) -> dict[str, int | bool | str]:
    summary = get_review_progress(job)
    summary.update({
        "job_id": job.job_id,
        "matches": len(job.matches),
        "observation_matches": len(job.observation_matches),
        "unmatched_left": len(job.unmatched_left),
        "unmatched_right": len(job.unmatched_right),
        "unmatched_observations_left": len(job.unmatched_observations_left),
        "unmatched_observations_right": len(job.unmatched_observations_right),
        "merged": len(job.merged_left),
        "merged_observations": len(job.merged_observations_left),
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
        "total_observation_matches": len(job.observation_matches),
        "completed_matches": len(job.merged_left),
        "completed_observation_matches": len(job.merged_observations_left),
        "current_field": job.field_index,
        "total_fields": len(_reviewable_field_defs(_active_conflict_kind(job) or "finding")),
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
    data["observation_matches"] = [
        {
            "left": _record_to_state(match["left"]),
            "right": _record_to_state(match["right"]),
            "score": match["score"],
            "auto_value": _record_to_state(match["auto_value"]),
            "auto_side": _winners_to_state(match["auto_side"]),
        }
        for match in job.observation_matches
    ]
    for key in ("unmatched_left", "unmatched_right", "merged_left", "merged_right", "final_left", "final_right"):
        value = getattr(job, key)
        data[key] = None if value is None else [_finding_to_state(item) for item in value]
    for key in (
        "unmatched_observations_left",
        "unmatched_observations_right",
        "merged_observations_left",
        "merged_observations_right",
        "final_observations_left",
        "final_observations_right",
    ):
        value = getattr(job, key)
        data[key] = None if value is None else [_observation_to_state(item) for item in value]
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
        observation_matches=[
            {
                "left": _observation_from_state(match["left"]),
                "right": _observation_from_state(match["right"]),
                "score": match["score"],
                "auto_value": _observation_from_state(match["auto_value"]),
                "auto_side": _winners_from_state(match["auto_side"]),
            }
            for match in data.get("observation_matches", [])
        ],
        unmatched_left=[_finding_from_state(item) for item in data["unmatched_left"]],
        unmatched_right=[_finding_from_state(item) for item in data["unmatched_right"]],
        merged_left=[_finding_from_state(item) for item in data["merged_left"]],
        merged_right=[_finding_from_state(item) for item in data["merged_right"]],
        unmatched_observations_left=[_observation_from_state(item) for item in data.get("unmatched_observations_left", [])],
        unmatched_observations_right=[_observation_from_state(item) for item in data.get("unmatched_observations_right", [])],
        merged_observations_left=[_observation_from_state(item) for item in data.get("merged_observations_left", [])],
        merged_observations_right=[_observation_from_state(item) for item in data.get("merged_observations_right", [])],
        match_index=data["match_index"],
        field_index=data["field_index"],
        finding_conflict_phase_complete=data.get("finding_conflict_phase_complete", data.get("conflict_phase_complete", False)),
        observation_match_index=data.get("observation_match_index", 0),
        observation_field_index=data.get("observation_field_index", 0),
        observation_conflict_phase_complete=data.get("observation_conflict_phase_complete", data.get("conflict_phase_complete", False)),
        conflict_phase_complete=data["conflict_phase_complete"],
        sensitivity_phase_complete=data["sensitivity_phase_complete"],
        sensitivity_template_type=data.get("sensitivity_template_type", "finding"),
        sensitivity_side=data["sensitivity_side"],
        sensitivity_record_index=data["sensitivity_record_index"],
        sensitivity_field_index=data["sensitivity_field_index"],
        sensitivity_hit_index=data.get("sensitivity_hit_index", 0),
        final_left=None if data["final_left"] is None else [_finding_from_state(item) for item in data["final_left"]],
        final_right=None if data["final_right"] is None else [_finding_from_state(item) for item in data["final_right"]],
        final_observations_left=None if data.get("final_observations_left") is None else [_observation_from_state(item) for item in data.get("final_observations_left", [])],
        final_observations_right=None if data.get("final_observations_right") is None else [_observation_from_state(item) for item in data.get("final_observations_right", [])],
        preview_acknowledged=data.get("preview_acknowledged", False),
        input_sources=data.get("input_sources", {"left": "file", "right": "file"}),
        sync_results=data.get("sync_results", {}),
        includes_observations=data.get("includes_observations", _state_includes_observations(data)),
    )


def _get_next_conflict_for_kind(job: MergeJob, kind: str) -> Optional[ConflictReviewItem]:
    """Return the next conflict for one template type, updating that type's state."""
    if _conflict_complete_for_kind(job, kind):
        return None

    matches = _matches_for_kind(job, kind)
    while _match_index_for_kind(job, kind) < len(matches):
        match = matches[_match_index_for_kind(job, kind)]
        field_defs = list(fields(TEMPLATE_MODELS[kind]))

        while _field_index_for_kind(job, kind) < len(field_defs):
            field_def = field_defs[_field_index_for_kind(job, kind)]
            _set_field_index_for_kind(job, kind, _field_index_for_kind(job, kind) + 1)
            if field_def.name in NON_REVIEWABLE_FIELDS:
                continue

            item = _prepare_conflict_for_field(kind, _match_index_for_kind(job, kind), match, field_def)
            if item is not None:
                return item

        _merged_for_kind(job, kind, "left").append(match["left"])
        _merged_for_kind(job, kind, "right").append(match["right"])
        _set_match_index_for_kind(job, kind, _match_index_for_kind(job, kind) + 1)
        _set_field_index_for_kind(job, kind, 0)
        job.preview_acknowledged = False

    _append_unmatched_records(job, kind)
    _set_conflict_complete_for_kind(job, kind, True)
    return None


def _prepare_conflict_for_field(kind: str, match_index: int, match: dict[str, Any], field_def: Any) -> Optional[ConflictReviewItem]:
    field_name = field_def.name
    if field_name in NON_REVIEWABLE_FIELDS:
        return None
    expected_type = get_type_as_str(field_def.type)
    left_value = getattr(match["left"], field_name, blank_for_type(expected_type))
    right_value = getattr(match["right"], field_name, blank_for_type(expected_type))
    offered_value = match["auto_value"].get(field_name)
    offered_side = match["auto_side"].get(field_name)

    if left_value == right_value:
        return None

    should_auto_accept, _, populated_value = get_single_sided_content_choice(left_value, right_value)
    if CONFIG.get("auto_accept_single_sided_content", False) and should_auto_accept:
        match["left"].set(field_name, populated_value)
        match["right"].set(field_name, populated_value)
        return None

    return ConflictReviewItem(
        template_type=kind,
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


def _append_unmatched_records(job: MergeJob, kind: str) -> None:
    if _conflict_complete_for_kind(job, kind):
        return
    unmatched_left = _unmatched_for_kind(job, kind, "left")
    unmatched_right = _unmatched_for_kind(job, kind, "right")
    merged_left = _merged_for_kind(job, kind, "left")
    merged_right = _merged_for_kind(job, kind, "right")
    for record in unmatched_left:
        normalise_finding_record(record)
        merged_left.append(record)
        merged_right.append(copy.deepcopy(record))
    for record in unmatched_right:
        normalise_finding_record(record)
        merged_left.append(copy.deepcopy(record))
        merged_right.append(record)


def _active_conflict_kind(job: MergeJob) -> Optional[str]:
    if not job.finding_conflict_phase_complete and job.match_index < len(job.matches):
        return "finding"
    if job.finding_conflict_phase_complete and not job.observation_conflict_phase_complete and job.observation_match_index < len(job.observation_matches):
        return "observation"
    return None


def _matches_for_kind(job: MergeJob, kind: str) -> list[dict[str, Any]]:
    return job.matches if kind == "finding" else job.observation_matches


def _unmatched_for_kind(job: MergeJob, kind: str, side: str) -> list[Finding] | list[Observation]:
    if kind == "finding":
        return job.unmatched_left if side == "left" else job.unmatched_right
    return job.unmatched_observations_left if side == "left" else job.unmatched_observations_right


def _merged_for_kind(job: MergeJob, kind: str, side: str) -> list[Finding] | list[Observation]:
    if kind == "finding":
        return job.merged_left if side == "left" else job.merged_right
    return job.merged_observations_left if side == "left" else job.merged_observations_right


def _match_index_for_kind(job: MergeJob, kind: str) -> int:
    return job.match_index if kind == "finding" else job.observation_match_index


def _set_match_index_for_kind(job: MergeJob, kind: str, value: int) -> None:
    if kind == "finding":
        job.match_index = value
    else:
        job.observation_match_index = value


def _field_index_for_kind(job: MergeJob, kind: str) -> int:
    return job.field_index if kind == "finding" else job.observation_field_index


def _set_field_index_for_kind(job: MergeJob, kind: str, value: int) -> None:
    if kind == "finding":
        job.field_index = value
    else:
        job.observation_field_index = value


def _conflict_complete_for_kind(job: MergeJob, kind: str) -> bool:
    return job.finding_conflict_phase_complete if kind == "finding" else job.observation_conflict_phase_complete


def _set_conflict_complete_for_kind(job: MergeJob, kind: str, value: bool) -> None:
    if kind == "finding":
        job.finding_conflict_phase_complete = value
    else:
        job.observation_conflict_phase_complete = value


def _reviewable_field_defs(kind: str) -> list[Any]:
    return [field_def for field_def in fields(TEMPLATE_MODELS[kind]) if field_def.name not in NON_REVIEWABLE_FIELDS]


def _finding_to_state(finding: Finding) -> dict[str, Any]:
    return asdict(finding)


def _finding_from_state(data: dict[str, Any]) -> Finding:
    return Finding(**data)


def _observation_to_state(observation: Observation) -> dict[str, Any]:
    return asdict(observation)


def _observation_from_state(data: dict[str, Any]) -> Observation:
    return Observation(**data)


def _record_to_state(record: Finding | Observation) -> dict[str, Any]:
    return asdict(record)


def _output_payload(findings: list[dict[str, Any]], observations: list[dict[str, Any]]) -> list[dict[str, Any]] | dict[str, list[dict[str, Any]]]:
    if observations:
        return {"findings": findings, "observations": observations}
    return findings


def _input_includes_observations(records: list[dict[str, Any]] | dict[str, list[dict[str, Any]]]) -> bool:
    return isinstance(records, dict) and "observations" in records


def _state_includes_observations(data: dict[str, Any]) -> bool:
    observation_keys = (
        "observation_matches",
        "unmatched_observations_left",
        "unmatched_observations_right",
        "merged_observations_left",
        "merged_observations_right",
        "final_observations_left",
        "final_observations_right",
    )
    return any(bool(data.get(key)) for key in observation_keys)


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


def _human_file_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


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

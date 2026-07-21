from __future__ import annotations

import copy
import difflib
import hashlib
import json
import secrets
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from globals import get_config
from matching import fuzzy_match_records
from merge import (
    ResolvedWinner,
    build_manual_match,
    get_compliance_reference_placeholder_choice,
    get_auto_suggest_values,
    get_single_sided_content_choice,
    normalise_merge_pair,
    reject_matched_record,
    reprocess_orphan_matches,
    renumber_records,
    set_record_pair_field_values,
)
from model import Finding, Observation, get_type_as_str, is_optional_field
from sensitivity import (
    apply_pre_match_sensitivity_replacements,
    apply_sensitive_replacement,
    check_for_sensitivities,
    empty_pre_match_sensitivity_stats,
)
from utils import (
    blank_for_type,
    extra_fields_for_comparison,
    normalise_finding_record,
    stringify_field,
    wrap_string,
)

CONFIG = get_config()
NON_REVIEWABLE_FIELDS = {"id"}
TEMPLATE_KINDS = ("finding", "observation")
TEMPLATE_MODELS = {"finding": Finding, "observation": Observation}
TEMPLATE_PLURALS = {"finding": "findings", "observation": "observations"}


def empty_sensitivity_review_stats() -> dict[str, int]:
    """Return fresh audit counters for the post-merge sensitivity stage."""
    return {
        "records_scanned": 0,
        "fields_scanned": 0,
        "hits_found": 0,
        "offered_replacements": 0,
        "custom_replacements": 0,
        "values_retained": 0,
    }


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
    output_approved: bool = False
    output_approved_at: Optional[str] = None
    output_preview_digest: Optional[str] = None
    output_preview_token: Optional[str] = None
    output_preview_generated_at: Optional[str] = None
    output_phase_complete: bool = False
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
    input_source_names: dict[str, str] = field(default_factory=dict)
    sync_results: dict[str, Any] = field(default_factory=dict)
    includes_observations: bool = False
    rejected_match_keys: list[str] = field(default_factory=list)
    finding_orphan_reprocessing_stopped: bool = False
    observation_orphan_reprocessing_stopped: bool = False
    finding_manual_matching_stopped: bool = False
    observation_manual_matching_stopped: bool = False
    manual_matching_token: Optional[str] = None
    sensitivity_snapshot_version: int = 0
    sensitivity_enabled: bool = False
    sensitivity_pre_match_enabled: bool = False
    sensitivity_terms: dict[str, Optional[str]] = field(default_factory=dict)
    sensitivity_terms_digest: Optional[str] = None
    sensitivity_terms_source: Optional[str] = None
    sensitivity_configuration_error: Optional[str] = None
    pre_match_sensitivity_stats: dict[str, dict[str, int]] = field(default_factory=dict)
    sensitivity_review_initialised: bool = False
    sensitivity_review_status: str = "pending"
    sensitivity_review_outcome: str = "pending"
    sensitivity_review_started_at: Optional[str] = None
    sensitivity_review_completed_at: Optional[str] = None
    sensitivity_review_stats: dict[str, int] = field(default_factory=empty_sensitivity_review_stats)
    sensitivity_decision_token: Optional[str] = None


@dataclass
class MatchPreviewItem:
    template_type: str
    match_index: int
    score: float
    origin: str
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
    input_sources: dict[str, str] = field(default_factory=dict)
    input_source_names: dict[str, str] = field(default_factory=dict)
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
            # Web workers have no analyst terminal. Invalid fields must return
            # to the browser as an error rather than opening an invisible TUI
            # correction prompt and blocking the request.
            finding = Finding.from_dict(record, allow_interactive_correction=False)
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
    sensitivity_snapshot: Optional[dict[str, Any]] = None,
    input_source_names: Optional[dict[str, str]] = None,
) -> MergeJob:
    """Create a merge job and run the existing fuzzy matching rounds."""
    includes_observations = _input_includes_observations(left_records) or _input_includes_observations(right_records)
    left_templates = split_template_records(left_records)
    right_templates = split_template_records(right_records)
    findings_left = parse_findings(left_templates["findings"])
    findings_right = parse_findings(right_templates["findings"])
    observations_left = parse_observations(left_templates["observations"])
    observations_right = parse_observations(right_templates["observations"])

    # Only new Web entry points provide a versioned snapshot. Direct service
    # callers and legacy persisted jobs retain version zero semantics until the
    # visible sensitivity milestone supplies an explicit migration path.
    snapshot = sensitivity_snapshot or {}
    snapshot_version = int(snapshot.get("version", 0))
    sensitivity_enabled = bool(snapshot.get("enabled", False))
    sensitivity_pre_match_enabled = bool(snapshot.get("pre_match_enabled", False))
    sensitivity_terms = dict(snapshot.get("terms") or {})
    pre_match_stats = {
        "finding_left": empty_pre_match_sensitivity_stats(),
        "finding_right": empty_pre_match_sensitivity_stats(),
        "observation_left": empty_pre_match_sensitivity_stats(),
        "observation_right": empty_pre_match_sensitivity_stats(),
    }

    if (
        snapshot_version >= 1
        and sensitivity_enabled
        and not snapshot.get("configuration_error")
        and sensitivity_pre_match_enabled
        and sensitivity_terms
    ):
        # Apply the same explicit-replacement policy used by the CLI before
        # fuzzy matching. Flag-only hits remain untouched for analyst review.
        pre_match_stats["finding_left"] = apply_pre_match_sensitivity_replacements(
            findings_left,
            sensitivity_terms,
        )
        pre_match_stats["finding_right"] = apply_pre_match_sensitivity_replacements(
            findings_right,
            sensitivity_terms,
        )
        pre_match_stats["observation_left"] = apply_pre_match_sensitivity_replacements(
            observations_left,
            sensitivity_terms,
        )
        pre_match_stats["observation_right"] = apply_pre_match_sensitivity_replacements(
            observations_right,
            sensitivity_terms,
        )

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
        input_source_names=dict(input_source_names or {}),
        includes_observations=includes_observations,
        sensitivity_snapshot_version=snapshot_version,
        sensitivity_enabled=sensitivity_enabled,
        sensitivity_pre_match_enabled=sensitivity_pre_match_enabled,
        sensitivity_terms=sensitivity_terms,
        sensitivity_terms_digest=snapshot.get("terms_digest"),
        sensitivity_terms_source=snapshot.get("terms_source"),
        sensitivity_configuration_error=snapshot.get("configuration_error"),
        pre_match_sensitivity_stats=pre_match_stats,
    )


def get_next_conflict(job: MergeJob) -> Optional[ConflictReviewItem]:
    """Return the next field-level conflict, auto-applying fields that do not need review."""
    item = _get_next_conflict_for_kind(job, "finding")
    if item is not None:
        return item
    if _has_pending_unmatched_review(job, "finding"):
        return None
    item = _get_next_conflict_for_kind(job, "observation")
    if item is not None:
        return item
    if _has_pending_unmatched_review(job, "observation"):
        return None

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
        if field_def.name == "extra_fields":
            left_value = extra_fields_for_comparison(left_value)
            right_value = extra_fields_for_comparison(right_value)
            offered_value = extra_fields_for_comparison(offered_value)
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

    rows.sort(key=lambda row: (0 if row["field_name"] == "title" else 1))

    return MatchPreviewItem(
        template_type=kind,
        match_index=_match_index_for_kind(job, kind),
        score=float(match["score"]),
        origin=str(match.get("origin", "automatic")),
        rows=rows,
    )


def get_active_conflict_position(job: MergeJob) -> tuple[Optional[str], int]:
    """Return the active template type and match index for preview transition checks."""
    kind = _active_conflict_kind(job)
    if kind is None:
        return None, -1
    return kind, _match_index_for_kind(job, kind)


def reset_match_to_preview(job: MergeJob, kind: str, match_index: int) -> None:
    """Rewind a newly reached match so the whole-record preview can be shown."""
    if kind not in TEMPLATE_KINDS:
        raise WebMergeError("Unknown match type.")
    _set_match_index_for_kind(job, kind, match_index)
    _set_field_index_for_kind(job, kind, 0)
    job.preview_acknowledged = False


def get_orphan_reprocessing_prompt(job: MergeJob) -> Optional[dict[str, Any]]:
    """Return prompt data when the user can choose another orphan matching pass."""
    kind = _pending_orphan_reprocessing_kind(job)
    if kind is None:
        return None
    return {
        "template_type": kind,
        "left_count": len(_unmatched_for_kind(job, kind, "left")),
        "right_count": len(_unmatched_for_kind(job, kind, "right")),
    }


def reprocess_orphans_for_current_kind(job: MergeJob) -> bool:
    """Run the user-requested orphan pass for the current template type."""
    kind = _pending_orphan_reprocessing_kind(job)
    if kind is None:
        raise WebMergeError("There are no orphan records available for reprocessing.")

    new_matches, unmatched_left, unmatched_right = reprocess_orphan_matches(
        list(_unmatched_for_kind(job, kind, "left")),
        list(_unmatched_for_kind(job, kind, "right")),
        list(CONFIG.get("fuzzy_match_threshold", [])),
        set(job.rejected_match_keys),
    )
    if not new_matches:
        _set_orphan_reprocessing_stopped_for_kind(job, kind, True)
        job.manual_matching_token = None
        return False

    for match in new_matches:
        normalise_merge_pair(match)
        auto_value, auto_side = get_auto_suggest_values(match["left"], match["right"])
        match["auto_value"] = auto_value
        match["auto_side"] = auto_side
        normalise_merge_pair(match)

    _replace_unmatched_for_kind(job, kind, "left", unmatched_left)
    _replace_unmatched_for_kind(job, kind, "right", unmatched_right)
    _matches_for_kind(job, kind).extend(new_matches)
    job.preview_acknowledged = False
    job.manual_matching_token = None
    return True


def stop_orphan_reprocessing_for_current_kind(job: MergeJob) -> None:
    """Stop fuzzy orphan passes and advance to optional manual matching."""
    kind = _pending_orphan_reprocessing_kind(job)
    if kind is None:
        raise WebMergeError("There are no orphan records waiting for reprocessing.")
    _set_orphan_reprocessing_stopped_for_kind(job, kind, True)
    job.manual_matching_token = None


def get_manual_matching_prompt(job: MergeJob) -> Optional[dict[str, Any]]:
    """Return the current server-derived manual-selection pools."""
    kind = _pending_manual_matching_kind(job)
    if kind is None:
        job.manual_matching_token = None
        return None
    if not job.manual_matching_token:
        job.manual_matching_token = secrets.token_urlsafe(32)
    return {
        "template_type": kind,
        "token": job.manual_matching_token,
        "left_records": _manual_matching_summaries(_unmatched_for_kind(job, kind, "left")),
        "right_records": _manual_matching_summaries(_unmatched_for_kind(job, kind, "right")),
    }


def create_manual_match(
    job: MergeJob,
    submitted_token: str,
    left_index: Any,
    right_index: Any,
) -> None:
    """Create one token-bound pair from the current protected unmatched pools."""
    # Authenticate the submitted selection before revealing or acting on the
    # current pool state. Consumed and stale forms therefore fail consistently.
    _validate_manual_matching_token(job, submitted_token)
    kind = _pending_manual_matching_kind(job)
    if kind is None:
        raise WebMergeError("There are no unmatched records available for manual matching.")
    try:
        selected_left_index = int(str(left_index))
        selected_right_index = int(str(right_index))
    except (TypeError, ValueError) as exc:
        raise WebMergeError("Select one record from each source.") from exc

    unmatched_left = _unmatched_for_kind(job, kind, "left")
    unmatched_right = _unmatched_for_kind(job, kind, "right")
    if not 0 <= selected_left_index < len(unmatched_left) or not 0 <= selected_right_index < len(unmatched_right):
        raise WebMergeError("Manual matching selection is no longer available. Reload the page and try again.")
    try:
        match = build_manual_match(
            unmatched_left[selected_left_index],
            unmatched_right[selected_right_index],
            set(job.rejected_match_keys),
        )
    except ValueError as exc:
        raise WebMergeError(str(exc)) from exc

    unmatched_left.pop(selected_left_index)
    unmatched_right.pop(selected_right_index)
    _matches_for_kind(job, kind).append(match)
    job.manual_matching_token = None
    job.preview_acknowledged = False


def stop_manual_matching_for_current_kind(job: MergeJob, submitted_token: str) -> None:
    """Finish one template type and copy any records the operator leaves unmatched."""
    _validate_manual_matching_token(job, submitted_token)
    kind = _pending_manual_matching_kind(job)
    if kind is None:
        raise WebMergeError("There are no unmatched records waiting for manual matching.")
    _set_manual_matching_stopped_for_kind(job, kind, True)
    job.manual_matching_token = None
    _append_unmatched_records(job, kind)
    _set_conflict_complete_for_kind(job, kind, True)
    job.preview_acknowledged = False


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
        set_record_pair_field_values(
            match["left"], match["right"], field_def.name, offered_value, offered_value,
        )

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
        set_record_pair_field_values(
            match["left"], match["right"], field_name, offered_value, offered_value,
        )
        applied += 1

    job.preview_acknowledged = True
    return applied


def reject_current_match(job: MergeJob) -> None:
    """Reject the current previewed match and return both records to unmatched pools."""
    kind = _active_conflict_kind(job)
    if kind is None:
        raise WebMergeError("There is no active match to reject.")
    if job.preview_acknowledged or _field_index_for_kind(job, kind) != 0:
        raise WebMergeError("Matches can only be rejected before field-level review starts.")

    match = _matches_for_kind(job, kind)[_match_index_for_kind(job, kind)]
    try:
        rejected_key = reject_matched_record(
            match,
            _unmatched_for_kind(job, kind, "left"),
            _unmatched_for_kind(job, kind, "right"),
        )
    except ValueError as exc:
        raise WebMergeError(str(exc)) from exc

    job.rejected_match_keys.append(rejected_key)
    _set_match_index_for_kind(job, kind, _match_index_for_kind(job, kind) + 1)
    _set_field_index_for_kind(job, kind, 0)
    job.preview_acknowledged = False


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
        if field_name == "extra_fields":
            value = extra_fields_for_comparison(value)
        set_record_pair_field_values(match["left"], match["right"], field_name, value, value)
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
    if field_name == "extra_fields":
        left_value = extra_fields_for_comparison(left_value)
        right_value = extra_fields_for_comparison(right_value)
        offered_value = extra_fields_for_comparison(offered_value)
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

    set_record_pair_field_values(match["left"], match["right"], field_name, new_left, new_right)
    _advance_field_after_decision(job, kind, field_name)


def initialise_sensitivity_review(
    job: MergeJob,
    terms: Optional[dict[str, Optional[str]]],
) -> None:
    """Initialise one auditable sensitivity pass without advancing its cursor."""
    if not job.conflict_phase_complete:
        raise WebMergeError("Conflict review must be complete before sensitivity review.")
    if job.sensitivity_phase_complete:
        job.sensitivity_review_initialised = True
        job.sensitivity_review_status = "complete"
        job.sensitivity_decision_token = None
        if job.sensitivity_review_outcome == "pending":
            job.sensitivity_review_outcome = "legacy_complete"
        return
    if job.sensitivity_review_initialised:
        return

    job.sensitivity_review_initialised = True
    job.sensitivity_review_started_at = _utc_state_timestamp()
    job.sensitivity_review_stats = empty_sensitivity_review_stats()

    sensitivity_enabled = (
        job.sensitivity_enabled
        if job.sensitivity_snapshot_version >= 1
        else terms is not None or bool(job.sensitivity_configuration_error)
    )
    if job.sensitivity_configuration_error:
        job.sensitivity_review_status = "configuration_error"
        job.sensitivity_review_outcome = "configuration_error"
        job.sensitivity_decision_token = None
        return
    if not sensitivity_enabled:
        job.sensitivity_review_status = "awaiting_acknowledgement"
        job.sensitivity_review_outcome = "disabled"
        job.sensitivity_decision_token = None
        return

    if terms is None:
        job.sensitivity_review_status = "configuration_error"
        job.sensitivity_review_outcome = "configuration_error"
        if not job.sensitivity_configuration_error:
            job.sensitivity_configuration_error = "Configured sensitive-term rules could not be loaded."
        job.sensitivity_decision_token = None
        return

    # Count the immutable starting workload once. Repeated GET requests can then
    # redisplay the same pending decision without inflating audit statistics.
    for template_type in TEMPLATE_KINDS:
        for side in ("left", "right"):
            for record in _merged_for_kind(job, template_type, side):
                job.sensitivity_review_stats["records_scanned"] += 1
                for field_def in fields(TEMPLATE_MODELS[template_type]):
                    if field_def.name == "id" or not record.get(field_def.name):
                        continue
                    job.sensitivity_review_stats["fields_scanned"] += 1
                    job.sensitivity_review_stats["hits_found"] += len(
                        check_for_sensitivities(record.get(field_def.name), terms)
                    )

    if job.sensitivity_review_stats["hits_found"]:
        job.sensitivity_review_status = "reviewing"
        job.sensitivity_review_outcome = "hits_found"
    else:
        job.sensitivity_review_status = "awaiting_acknowledgement"
        job.sensitivity_review_outcome = "no_hits"
        job.sensitivity_decision_token = None


def get_next_sensitivity_item(
    job: MergeJob,
    terms: Optional[dict[str, Optional[str]]],
) -> Optional[SensitivityReviewItem]:
    """Return the next post-merge sensitivity item that requires human review."""
    initialise_sensitivity_review(job, terms)
    if job.sensitivity_phase_complete:
        return None
    if job.sensitivity_review_status == "configuration_error":
        raise WebMergeError(job.sensitivity_configuration_error or "Sensitivity configuration is unavailable.")
    if job.sensitivity_review_outcome == "disabled" or not terms:
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
                        # The token binds one browser form to this persisted
                        # cursor. It is rotated after every accepted decision,
                        # so stale tabs and replayed requests fail closed.
                        if not job.sensitivity_decision_token:
                            job.sensitivity_decision_token = secrets.token_urlsafe(32)
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

    job.sensitivity_decision_token = None
    job.sensitivity_review_status = "awaiting_acknowledgement"
    return None


def apply_sensitivity_decision(
    job: MergeJob,
    decision: dict[str, Any],
    terms: Optional[dict[str, Optional[str]]] = None,
) -> None:
    """Apply one action to the server-derived pending sensitivity item.

    Record identity, field name, sensitive term, and offered replacement are
    deliberately ignored when supplied by a browser. Only the action, optional
    custom value, and one-time cursor token cross the trust boundary.
    """
    effective_terms = terms
    if effective_terms is None and job.sensitivity_snapshot_version >= 1:
        effective_terms = dict(job.sensitivity_terms)
    item = get_next_sensitivity_item(job, effective_terms)
    if item is None:
        raise WebMergeError("No sensitivity decision is currently pending.")

    submitted_token = str(decision.get("decision_token", ""))
    expected_token = job.sensitivity_decision_token or ""
    if not submitted_token or not secrets.compare_digest(submitted_token, expected_token):
        raise WebMergeError("Sensitivity decision is stale or invalid. Reload the review page and try again.")

    action = str(decision.get("action", ""))
    if action == "keep":
        job.sensitivity_review_stats["values_retained"] += 1
        job.sensitivity_hit_index += 1
        job.sensitivity_decision_token = None
        return
    if action == "offered":
        if item.offered is None:
            raise WebMergeError("The pending sensitivity term has no offered replacement.")
        replacement = item.offered
        job.sensitivity_review_stats["offered_replacements"] += 1
    elif action == "custom":
        replacement = str(decision.get("custom_value", ""))
        job.sensitivity_review_stats["custom_replacements"] += 1
    else:
        raise WebMergeError("Unsupported sensitivity decision.")

    records = _merged_for_kind(job, item.template_type, item.side)
    record = records[item.record_index]
    record.set(
        item.field_name,
        apply_sensitive_replacement(record.get(item.field_name), item.sensitive_term, replacement),
    )
    job.sensitivity_hit_index = 0
    job.sensitivity_decision_token = None


def acknowledge_sensitivity_review(job: MergeJob) -> None:
    """Complete sensitivity review only after its visible result is acknowledged."""
    if not job.conflict_phase_complete:
        raise WebMergeError("Conflict review must be complete before sensitivity review.")
    if job.sensitivity_review_status == "configuration_error" or job.sensitivity_configuration_error:
        raise WebMergeError("Sensitivity review cannot complete while its configuration is unavailable.")
    if job.sensitivity_review_status != "awaiting_acknowledgement":
        raise WebMergeError("Sensitivity review is not ready for acknowledgement.")

    job.sensitivity_phase_complete = True
    job.sensitivity_review_status = "complete"
    job.sensitivity_review_completed_at = _utc_state_timestamp()
    job.sensitivity_decision_token = None


def _renumbered_final_records(
    job: MergeJob,
) -> tuple[list[Finding], list[Finding], list[Observation], list[Observation]]:
    """Copy and renumber all reviewed collections without mutating the job."""
    if not job.conflict_phase_complete:
        raise WebMergeError("Conflict review must be complete before finalising output.")

    left = [copy.deepcopy(item) for item in job.merged_left]
    right = [copy.deepcopy(item) for item in job.merged_right]
    observations_left = [copy.deepcopy(item) for item in job.merged_observations_left]
    observations_right = [copy.deepcopy(item) for item in job.merged_observations_right]
    left, right = renumber_records(left, right, start_id=1)
    observations_left, observations_right = renumber_records(observations_left, observations_right, start_id=1)
    return left, right, observations_left, observations_right


def build_final_output(job: MergeJob) -> MergeResult:
    """Build the deterministic final payload without mutating or persisting the job."""
    left, right, observations_left, observations_right = _renumbered_final_records(job)
    return MergeResult(
        left_records=[item.to_dict() for item in left],
        right_records=[item.to_dict() for item in right],
        left_observations=[item.to_dict() for item in observations_left],
        right_observations=[item.to_dict() for item in observations_right],
    )


def finalise_job(job: MergeJob) -> MergeResult:
    """Renumber final records and attach them to the job for durable output."""
    left, right, observations_left, observations_right = _renumbered_final_records(job)
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


def _final_output_digest(result: MergeResult) -> str:
    """Return a stable digest binding approval to all four final collections."""
    canonical_payload = json.dumps(
        asdict(result),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical_payload).hexdigest()


def _attached_final_output(job: MergeJob) -> MergeResult:
    """Serialise final records already attached to a job."""
    if job.final_left is None or job.final_right is None:
        raise WebMergeError("Finalised merge output is incomplete.")
    observations_left = job.final_observations_left or []
    observations_right = job.final_observations_right or []
    return MergeResult(
        left_records=[item.to_dict() for item in job.final_left],
        right_records=[item.to_dict() for item in job.final_right],
        left_observations=[item.to_dict() for item in observations_left],
        right_observations=[item.to_dict() for item in observations_right],
    )


def prepare_output_preview(job: MergeJob) -> MergeResult:
    """Prepare an approval-bound preview without creating durable output files."""
    if not job.conflict_phase_complete or not job.sensitivity_phase_complete:
        raise WebMergeError("All review stages must be complete before previewing merged output.")

    result = build_final_output(job)
    digest = _final_output_digest(result)

    # Any change to the proposed payload invalidates an earlier browser form
    # and any approval recorded for different content.
    if not secrets.compare_digest(job.output_preview_digest or "", digest):
        job.output_preview_digest = digest
        job.output_preview_token = secrets.token_urlsafe(32)
        job.output_preview_generated_at = _utc_state_timestamp()
        job.output_approved = False
        job.output_approved_at = None
    elif not job.output_preview_token:
        # A fresh token permits an explicit retry after an interrupted or
        # failed write while keeping the already-recorded approval auditable.
        job.output_preview_token = secrets.token_urlsafe(32)

    return result


def approve_output_preview(job: MergeJob, submitted_token: str) -> MergeResult:
    """Approve the current server-derived preview and attach its final records."""
    result = prepare_output_preview(job)
    expected_token = job.output_preview_token or ""
    if not submitted_token or not secrets.compare_digest(str(submitted_token), expected_token):
        raise WebMergeError("Final output approval is stale or invalid. Reload the preview and try again.")

    # Rebuild through the existing finalisation boundary only after the exact
    # preview has been approved. The digest check in save_outputs protects
    # callers from substituting a different MergeResult afterwards.
    result = finalise_job(job)
    if not secrets.compare_digest(_final_output_digest(result), job.output_preview_digest or ""):
        raise WebMergeError("Final output changed during approval. Reload the preview and try again.")
    job.output_approved = True
    job.output_approved_at = _utc_state_timestamp()
    job.output_preview_token = None
    return result


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
    job = job_from_dict(data)
    _reconcile_output_state(job, data, job_path.parent)
    return job


def list_previous_jobs(jobs_dir: Path) -> list[PreviousJobItem]:
    """Return persisted jobs that can be resumed or downloaded from the home page."""
    if not jobs_dir.exists():
        return []

    jobs = []
    for job_path in sorted(jobs_dir.glob("*/job.json"), key=lambda path: path.stat().st_mtime, reverse=True):
        job_dir = job_path.parent
        updated_at = _human_file_mtime(job_path)
        try:
            data = json.loads(job_path.read_text(encoding="utf-8"))
            job = job_from_dict(data)
            _reconcile_output_state(job, data, job_dir)
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
                phase=str(progress["phase_label"]),
                matches=int(progress["total_matches"]),
                completed_matches=min(int(progress["completed_matches"]), int(progress["total_matches"])),
                updated_at=updated_at,
                has_left_output=(job_dir / "left.json").exists(),
                has_right_output=(job_dir / "right.json").exists(),
                input_sources=job.input_sources,
                input_source_names=job.input_source_names,
                sync_results=job.sync_results,
            )
        )
    return jobs


def save_outputs(job: MergeJob, jobs_dir: Path, result: MergeResult) -> None:
    """Persist both outputs before marking the merge output as ready."""
    if not job.conflict_phase_complete or not job.sensitivity_phase_complete:
        raise WebMergeError("All review stages must be complete before saving merged output.")
    if not job.output_approved or not job.output_approved_at:
        raise WebMergeError("Final output must be explicitly approved before it can be saved.")
    if not job.output_preview_digest or not secrets.compare_digest(
        _final_output_digest(result),
        job.output_preview_digest,
    ):
        raise WebMergeError("Approved final output does not match the output being saved.")
    attached_result = _attached_final_output(job)
    if not secrets.compare_digest(_final_output_digest(attached_result), job.output_preview_digest):
        raise WebMergeError("Finalised job records do not match the approved output.")
    job_dir = _job_dir(jobs_dir, job.job_id)
    job_dir.mkdir(parents=True, exist_ok=True)
    left_output = _output_payload(result.left_records, result.left_observations)
    right_output = _output_payload(result.right_records, result.right_observations)

    # Persist the incomplete marker first so a process interruption cannot leave a
    # stale completed state pointing at one old and one newly written output.
    job.output_phase_complete = False
    save_job(job, jobs_dir)
    try:
        _write_json_atomic(job_dir / "left.json", left_output)
        _write_json_atomic(job_dir / "right.json", right_output)
    except (OSError, TypeError, ValueError) as exc:
        raise WebMergeError(f"Merged output could not be written: {exc}") from exc
    job.output_phase_complete = True
    save_job(job, jobs_dir)


def finalised_job_result(job: MergeJob) -> MergeResult:
    """Return already-finalised output for download or outbound synchronisation."""
    if not job.output_approved or not job.output_phase_complete:
        raise WebMergeError("Merged output must be ready before outbound API synchronisation.")
    result = _attached_final_output(job)
    if job.output_preview_digest and not secrets.compare_digest(
        _final_output_digest(result),
        job.output_preview_digest,
    ):
        raise WebMergeError("Finalised merge output no longer matches its recorded approval.")
    return result


def job_summary(job: MergeJob) -> dict[str, Any]:
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
        "sensitivity_review_status": job.sensitivity_review_status,
        "sensitivity_review_outcome": job.sensitivity_review_outcome,
        "sensitivity_review_started_at": job.sensitivity_review_started_at,
        "sensitivity_review_completed_at": job.sensitivity_review_completed_at,
        "sensitivity_review_stats": dict(job.sensitivity_review_stats),
        "output_approved": job.output_approved,
        "output_approved_at": job.output_approved_at,
        "output_phase_complete": job.output_phase_complete,
        "sync_results": job.sync_results,
    })
    return summary


def sensitivity_audit_summary(job: MergeJob) -> dict[str, Any]:
    """Return template-safe sensitivity state without exposing snapshotted terms."""
    pre_match_totals = empty_pre_match_sensitivity_stats()
    for collection_stats in job.pre_match_sensitivity_stats.values():
        for key in pre_match_totals:
            pre_match_totals[key] += int(collection_stats.get(key, 0))

    return {
        "enabled": job.sensitivity_enabled if job.sensitivity_snapshot_version >= 1 else None,
        "status": job.sensitivity_review_status,
        "outcome": job.sensitivity_review_outcome,
        "terms_source": job.sensitivity_terms_source,
        "terms_digest": job.sensitivity_terms_digest,
        "configuration_error": job.sensitivity_configuration_error,
        "pre_match": pre_match_totals,
        "post_merge": dict(job.sensitivity_review_stats),
        "started_at": job.sensitivity_review_started_at,
        "completed_at": job.sensitivity_review_completed_at,
    }


def get_review_progress(job: MergeJob) -> dict[str, int | bool | str]:
    phase = "conflict_review"
    if job.conflict_phase_complete and not job.sensitivity_phase_complete:
        phase = "sensitivity_review"
    elif job.conflict_phase_complete and job.sensitivity_phase_complete and not job.output_phase_complete:
        phase = "ready_to_finalise"
    elif job.conflict_phase_complete and job.sensitivity_phase_complete and job.output_phase_complete:
        phase = "output_ready"

    phase_labels = {
        "conflict_review": "Match and field review",
        "sensitivity_review": "Sensitivity review",
        "ready_to_finalise": "Ready for final preview",
        "output_ready": "Merged output ready",
    }

    return {
        "phase": phase,
        "phase_label": phase_labels[phase],
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
            "origin": match.get("origin", "automatic"),
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
            "origin": match.get("origin", "automatic"),
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
                "origin": match.get("origin", "automatic"),
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
                "origin": match.get("origin", "automatic"),
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
        output_approved=bool(data.get("output_approved", False)),
        output_approved_at=(
            data.get("output_approved_at") if isinstance(data.get("output_approved_at"), str) else None
        ),
        output_preview_digest=(
            data.get("output_preview_digest") if isinstance(data.get("output_preview_digest"), str) else None
        ),
        output_preview_token=(
            data.get("output_preview_token") if isinstance(data.get("output_preview_token"), str) else None
        ),
        output_preview_generated_at=(
            data.get("output_preview_generated_at")
            if isinstance(data.get("output_preview_generated_at"), str)
            else None
        ),
        output_phase_complete=bool(data.get("output_phase_complete", False)),
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
        input_source_names=dict(data.get("input_source_names") or {}),
        sync_results=data.get("sync_results", {}),
        includes_observations=data.get("includes_observations", _state_includes_observations(data)),
        rejected_match_keys=list(data.get("rejected_match_keys", [])),
        finding_orphan_reprocessing_stopped=data.get(
            "finding_orphan_reprocessing_stopped",
            data.get("finding_orphan_reprocess_complete", False),
        ),
        observation_orphan_reprocessing_stopped=data.get(
            "observation_orphan_reprocessing_stopped",
            data.get("observation_orphan_reprocess_complete", False),
        ),
        finding_manual_matching_stopped=bool(data.get("finding_manual_matching_stopped", False)),
        observation_manual_matching_stopped=bool(data.get("observation_manual_matching_stopped", False)),
        manual_matching_token=(
            data.get("manual_matching_token") if isinstance(data.get("manual_matching_token"), str) else None
        ),
        sensitivity_snapshot_version=int(data.get("sensitivity_snapshot_version", 0)),
        sensitivity_enabled=bool(data.get("sensitivity_enabled", False)),
        sensitivity_pre_match_enabled=bool(data.get("sensitivity_pre_match_enabled", False)),
        sensitivity_terms=dict(data.get("sensitivity_terms") or {}),
        sensitivity_terms_digest=data.get("sensitivity_terms_digest"),
        sensitivity_terms_source=data.get("sensitivity_terms_source"),
        sensitivity_configuration_error=data.get("sensitivity_configuration_error"),
        pre_match_sensitivity_stats=dict(data.get("pre_match_sensitivity_stats") or {}),
        sensitivity_review_initialised=bool(
            data.get("sensitivity_review_initialised", data.get("sensitivity_phase_complete", False))
        ),
        sensitivity_review_status=data.get(
            "sensitivity_review_status",
            "complete" if data.get("sensitivity_phase_complete", False) else "pending",
        ),
        sensitivity_review_outcome=data.get(
            "sensitivity_review_outcome",
            "legacy_complete" if data.get("sensitivity_phase_complete", False) else "pending",
        ),
        sensitivity_review_started_at=data.get("sensitivity_review_started_at"),
        sensitivity_review_completed_at=data.get("sensitivity_review_completed_at"),
        sensitivity_review_stats={
            **empty_sensitivity_review_stats(),
            **dict(data.get("sensitivity_review_stats") or {}),
        },
        sensitivity_decision_token=data.get("sensitivity_decision_token"),
    )


def _reconcile_output_state(job: MergeJob, data: dict[str, Any], job_dir: Path) -> None:
    """Validate persisted completion against final data and both durable output files."""
    has_final_records = job.final_left is not None and job.final_right is not None
    has_output_files = (job_dir / "left.json").is_file() and (job_dir / "right.json").is_file()
    final_digest_matches = True
    if has_final_records and job.output_preview_digest:
        final_digest_matches = secrets.compare_digest(
            _final_output_digest(_attached_final_output(job)),
            job.output_preview_digest,
        )

    if "output_approved" in data:
        # Current jobs retain approval across a retryable output-write failure,
        # but cannot be considered ready until both output files also exist.
        job.output_approved = bool(data.get("output_approved")) and has_final_records and final_digest_matches
    else:
        # Legacy jobs pre-date explicit approval. Only already-complete jobs get
        # compatibility approval; incomplete legacy jobs still enter preview.
        job.output_approved = has_final_records and has_output_files
        if job.output_approved and not job.output_approved_at:
            job.output_approved_at = data.get("sensitivity_review_completed_at")

    if "output_phase_complete" in data:
        job.output_phase_complete = (
            bool(data.get("output_phase_complete"))
            and job.output_approved
            and has_final_records
            and has_output_files
        )
    else:
        # Jobs written before the explicit marker are complete only when their old
        # final arrays and both files provide equivalent durable evidence.
        job.output_phase_complete = job.output_approved and has_final_records and has_output_files


def _get_next_conflict_for_kind(job: MergeJob, kind: str) -> Optional[ConflictReviewItem]:
    """Return the next conflict for one template type, updating that type's state."""
    if _conflict_complete_for_kind(job, kind):
        return None

    matches = _matches_for_kind(job, kind)
    while _match_index_for_kind(job, kind) < len(matches):
        match = matches[_match_index_for_kind(job, kind)]
        field_defs = list(fields(TEMPLATE_MODELS[kind]))

        while _field_index_for_kind(job, kind) < len(field_defs):
            current_field_index = _field_index_for_kind(job, kind)
            field_def = field_defs[current_field_index]
            if field_def.name in NON_REVIEWABLE_FIELDS:
                _set_field_index_for_kind(job, kind, current_field_index + 1)
                continue

            item = _prepare_conflict_for_field(kind, _match_index_for_kind(job, kind), match, field_def)
            if item is not None:
                return item
            _set_field_index_for_kind(job, kind, current_field_index + 1)

        _merged_for_kind(job, kind, "left").append(match["left"])
        _merged_for_kind(job, kind, "right").append(match["right"])
        _set_match_index_for_kind(job, kind, _match_index_for_kind(job, kind) + 1)
        _set_field_index_for_kind(job, kind, 0)
        job.preview_acknowledged = False

    if _has_pending_unmatched_review(job, kind):
        return None

    _append_unmatched_records(job, kind)
    _set_conflict_complete_for_kind(job, kind, True)
    return None


def _advance_field_after_decision(job: MergeJob, kind: str, field_name: str) -> None:
    """Advance past the conflict field only after a submitted decision is applied."""
    field_defs = list(fields(TEMPLATE_MODELS[kind]))
    current_index = _field_index_for_kind(job, kind)
    if current_index < len(field_defs) and field_defs[current_index].name == field_name:
        _set_field_index_for_kind(job, kind, current_index + 1)


def _prepare_conflict_for_field(kind: str, match_index: int, match: dict[str, Any], field_def: Any) -> Optional[ConflictReviewItem]:
    field_name = field_def.name
    if field_name in NON_REVIEWABLE_FIELDS:
        return None
    expected_type = get_type_as_str(field_def.type)
    left_value = getattr(match["left"], field_name, blank_for_type(expected_type))
    right_value = getattr(match["right"], field_name, blank_for_type(expected_type))
    offered_value = match["auto_value"].get(field_name)
    offered_side = match["auto_side"].get(field_name)

    if field_name == "extra_fields":
        left_value = extra_fields_for_comparison(left_value)
        right_value = extra_fields_for_comparison(right_value)
        offered_value = extra_fields_for_comparison(offered_value)

    if left_value == right_value:
        return None

    should_auto_accept, _, populated_value = get_single_sided_content_choice(left_value, right_value)
    if CONFIG.get("auto_accept_single_sided_content", False) and should_auto_accept:
        set_record_pair_field_values(
            match["left"], match["right"], field_name, populated_value, populated_value,
        )
        return None

    should_accept_placeholder, _, placeholder_value = get_compliance_reference_placeholder_choice(left_value, right_value)
    if field_name == "extra_fields" and should_accept_placeholder:
        set_record_pair_field_values(
            match["left"], match["right"], field_name, placeholder_value, placeholder_value,
        )
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


def _pending_orphan_reprocessing_kind(job: MergeJob) -> Optional[str]:
    for kind in TEMPLATE_KINDS:
        if _should_offer_orphan_reprocessing(job, kind):
            return kind
    return None


def _pending_manual_matching_kind(job: MergeJob) -> Optional[str]:
    for kind in TEMPLATE_KINDS:
        if _should_offer_manual_matching(job, kind):
            return kind
    return None


def _has_pending_unmatched_review(job: MergeJob, kind: str) -> bool:
    return _should_offer_orphan_reprocessing(job, kind) or _should_offer_manual_matching(job, kind)


def _should_offer_orphan_reprocessing(job: MergeJob, kind: str) -> bool:
    if not CONFIG.get("orphan_reprocessing_enabled", True):
        return False
    if _conflict_complete_for_kind(job, kind):
        return False
    if _orphan_reprocessing_stopped_for_kind(job, kind):
        return False
    if _match_index_for_kind(job, kind) < len(_matches_for_kind(job, kind)):
        return False
    return bool(_unmatched_for_kind(job, kind, "left") and _unmatched_for_kind(job, kind, "right"))


def _should_offer_manual_matching(job: MergeJob, kind: str) -> bool:
    if _conflict_complete_for_kind(job, kind):
        return False
    if _manual_matching_stopped_for_kind(job, kind):
        return False
    if _match_index_for_kind(job, kind) < len(_matches_for_kind(job, kind)):
        return False
    if _should_offer_orphan_reprocessing(job, kind):
        return False
    return bool(_unmatched_for_kind(job, kind, "left") and _unmatched_for_kind(job, kind, "right"))


def _manual_matching_summaries(records: list[Finding] | list[Observation]) -> list[dict[str, Any]]:
    summaries = []
    for index, record in enumerate(records):
        summaries.append(
            {
                "index": index,
                "id": record.id,
                "title": record.title,
                "finding_type": getattr(record, "finding_type", ""),
                "severity": getattr(record, "severity", ""),
                "description": wrap_string(stringify_field(record.description), 160),
            }
        )
    return summaries


def _validate_manual_matching_token(job: MergeJob, submitted_token: str) -> None:
    """Reject stale manual-stage actions before consulting mutable pool state."""
    expected_token = job.manual_matching_token or ""
    if not submitted_token or not secrets.compare_digest(str(submitted_token), expected_token):
        raise WebMergeError("Manual matching selection is stale or invalid. Reload the page and try again.")


def _active_conflict_kind(job: MergeJob) -> Optional[str]:
    if not job.finding_conflict_phase_complete and job.match_index < len(job.matches):
        return "finding"
    if not job.observation_conflict_phase_complete and job.observation_match_index < len(job.observation_matches):
        return "observation"
    return None


def _matches_for_kind(job: MergeJob, kind: str) -> list[dict[str, Any]]:
    return job.matches if kind == "finding" else job.observation_matches


def _unmatched_for_kind(job: MergeJob, kind: str, side: str) -> list[Finding] | list[Observation]:
    if kind == "finding":
        return job.unmatched_left if side == "left" else job.unmatched_right
    return job.unmatched_observations_left if side == "left" else job.unmatched_observations_right


def _replace_unmatched_for_kind(job: MergeJob, kind: str, side: str, records: list[Finding] | list[Observation]) -> None:
    if kind == "finding" and side == "left":
        job.unmatched_left = records
    elif kind == "finding":
        job.unmatched_right = records
    elif side == "left":
        job.unmatched_observations_left = records
    else:
        job.unmatched_observations_right = records


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


def _orphan_reprocessing_stopped_for_kind(job: MergeJob, kind: str) -> bool:
    return job.finding_orphan_reprocessing_stopped if kind == "finding" else job.observation_orphan_reprocessing_stopped


def _set_orphan_reprocessing_stopped_for_kind(job: MergeJob, kind: str, value: bool) -> None:
    if kind == "finding":
        job.finding_orphan_reprocessing_stopped = value
    else:
        job.observation_orphan_reprocessing_stopped = value


def _manual_matching_stopped_for_kind(job: MergeJob, kind: str) -> bool:
    return job.finding_manual_matching_stopped if kind == "finding" else job.observation_manual_matching_stopped


def _set_manual_matching_stopped_for_kind(job: MergeJob, kind: str, value: bool) -> None:
    if kind == "finding":
        job.finding_manual_matching_stopped = value
    else:
        job.observation_manual_matching_stopped = value


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


def _utc_state_timestamp() -> str:
    """Return a stable UTC timestamp for persisted workflow audit state."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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

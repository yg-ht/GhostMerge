from utils import log, normalise_tags
from models import Finding

# ── ID Tracking ─────────────────────────────────────────────────────
class IDTracker:
    """
    Tracks and assigns unique IDs across a dataset.
    Ensures no collisions when new IDs are needed.
    """
    def __init__(self, prefix: str):
        self.prefix = prefix
        self.existing_ids = set()

    def register_existing(self, existing_id: str):
        self.existing_ids.add(existing_id)
        log("DEBUG", f"Registered existing ID: {existing_id}", prefix="IDTracker")

    def get_next_available_id(self) -> str:
        current = 1
        while True:
            candidate = f"{self.prefix}{current:03d}"
            if candidate not in self.existing_ids:
                self.existing_ids.add(candidate)
                log("DEBUG", f"Generated new ID: {candidate}", prefix="IDTracker")
                return candidate
            current += 1


# ── Conflict Resolution ─────────────────────────────────────────────
def resolve_conflict(value_from_a, value_from_b) -> str:
    """
    Resolves a conflict between two versions of a field.
    Preference is given to non-empty values, and if both are present,
    selects the one with more tokens, or the longer value if tied.
    """
    if value_from_a and not value_from_b:
        return value_from_a
    if value_from_b and not value_from_a:
        return value_from_b
    if not value_from_a and not value_from_b:
        return ""

    len_a, len_b = len(str(value_from_a)), len(str(value_from_b))
    tok_a, tok_b = len(str(value_from_a).split()), len(str(value_from_b).split())

    if tok_a > tok_b:
        return value_from_a
    elif tok_b > tok_a:
        return value_from_b
    else:
        return value_from_a if len_a >= len_b else value_from_b


# ── Finding Merge ───────────────────────────────────────────────────
def merge_individual_findings(finding_from_a: Finding, finding_from_b: Finding) -> dict:
    """
    Performs a detailed, field-by-field merge of two Finding objects.
    Tracks the source and embeds the provenance and change detection results
    directly into the output records for dataset A and B.
    Returns a dict with keys 'a' and 'b' representing the respective outputs.
    """
    log("INFO", f"Merging findings A:{finding_from_a.id} <-> B:{finding_from_b.id}", prefix="MERGE")

    merged_fields = {"a": {}, "b": {}}

    # Define all fields that must be considered for merging
    finding_fields_to_merge = [
        "severity", "cvss_score", "cvss_vector", "finding_type", "title", "description",
        "impact", "mitigation", "replication_steps", "host_detection_techniques",
        "network_detection_techniques", "references", "finding_guidance", "tags", "extra_fields"
    ]

    # Merge each field carefully, with logging and side-specific handling
    for field_name in finding_fields_to_merge:
        value_from_a = getattr(finding_from_a, field_name, None)
        value_from_b = getattr(finding_from_b, field_name, None)

        if field_name == "tags":
            normalised_tags_a = normalise_tags(" ".join(value_from_a or []))
            normalised_tags_b = normalise_tags(" ".join(value_from_b or []))
            merged_tags = list(set(normalised_tags_a + normalised_tags_b))
            merged_fields["a"][field_name] = merged_tags
            merged_fields["b"][field_name] = merged_tags
            log("DEBUG", f"Tags merged: A={normalised_tags_a}, B={normalised_tags_b}, Result={merged_tags}", prefix="MERGE")

        elif field_name == "extra_fields":
            resolved_extra_fields = {}
            combined_keys = set((value_from_a or {}).keys()) | set((value_from_b or {}).keys())
            for key in combined_keys:
                resolved_value = resolve_conflict((value_from_a or {}).get(key), (value_from_b or {}).get(key))
                resolved_extra_fields[key] = resolved_value
                log("DEBUG", f"Resolved extra field '{key}' → A:{(value_from_a or {}).get(key)} | B:{(value_from_b or {}).get(key)} → '{resolved_value}'", prefix="MERGE")
            merged_fields["a"][field_name] = resolved_extra_fields
            merged_fields["b"][field_name] = resolved_extra_fields

        else:
            resolved_value = resolve_conflict(value_from_a, value_from_b)
            merged_fields["a"][field_name] = resolved_value
            merged_fields["b"][field_name] = resolved_value
            log("DEBUG", f"Resolved field '{field_name}' → A:{value_from_a} | B:{value_from_b} → '{resolved_value}'", prefix="MERGE")

    # Assign IDs and embed provenance and change status
    merged_fields["a"].update({"id": finding_from_a.id, "source_id_a": finding_from_a.id, "source_id_b": finding_from_b.id, "reason": "unchanged"})
    merged_fields["b"].update({"id": finding_from_b.id, "source_id_a": finding_from_a.id, "source_id_b": finding_from_b.id, "reason": "unchanged"})

    # Change detection: if any field in merged != original, mark as updated
    for dataset_key, original_finding in [("a", finding_from_a), ("b", finding_from_b)]:
        for field_name in finding_fields_to_merge:
            original_value = getattr(original_finding, field_name, None)
            if field_name == "tags":
                original_value = normalise_tags(" ".join(original_value or []))
            elif field_name == "extra_fields":
                original_value = original_value or {}
            if merged_fields[dataset_key].get(field_name) != original_value:
                merged_fields[dataset_key]["reason"] = "updated"
                log("DEBUG", f"Change detected in '{field_name}' for side '{dataset_key}' — marked as updated.", prefix="MERGE")
                break
            else:
                log("DEBUG", f"No change in field '{field_name}' for side '{dataset_key}'", prefix="MERGE")

    log("INFO", f"Completed merge of A:{finding_from_a.id} and B:{finding_from_b.id}", prefix="MERGE")
    return merged_fields

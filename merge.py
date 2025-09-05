# external module imports
from imports import (dumps, Table, Any, Dict, List)
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()
# local module imports
from utils import log, normalise_tags, is_blank
from model import Finding
from sensitivity import load_sensitive_terms, check_finding_for_sensitivities

# ── Conflict Resolution ─────────────────────────────────────────────
def resolve_conflict(value_from_left, value_from_right) -> str:
    """
    Resolves a conflict between two versions of a field.
    Preference is given to non-empty values, and if both are present,
    selects the one with more tokens, or the longer value if tied.
    """
    if is_blank(value_from_left) and is_blank(value_from_right):
        return None
    if is_blank(value_from_left):
        return value_from_right
    if is_blank(value_from_right):
        return value_from_left

    len_left, len_right = len(str(value_from_left)), len(str(value_from_right))
    tok_left, tok_right = len(str(value_from_left).split()), len(str(value_from_right).split())

    if tok_left > tok_right:
        return value_from_left
    elif tok_right > tok_left:
        return value_from_right
    else:
        return value_from_left if len_left >= len_right else value_from_right


def stringify_for_diff(value: Any) -> str:
    if isinstance(value, dict):
        return dumps(value, indent=2, sort_keys=True)
    elif isinstance(value, list):
        return "\n".join(map(str, value))
    return str(value or "")

# ── Finding Merge ───────────────────────────────────────────────────
def merge_individual_findings(finding_from_left: Finding, finding_from_right: Finding) -> dict:
    """
    Performs a detailed, field-by-field merge of two Finding objects.
    Tracks the source and embeds the provenance and change detection results
    directly into the output records for dataset A and B.
    Returns a dict with keys 'a' and 'b' representing the respective outputs.
    """
    log("INFO", f"Merging findings Left:{finding_from_left.id} <-> Right:{finding_from_right.id}", prefix="MERGE")

    merged_fields = {"left": {}, "right": {}}

    # Define all fields that must be considered for merging
    finding_fields_to_merge = [
        "severity", "cvss_score", "cvss_vector", "finding_type", "title", "description",
        "impact", "mitigation", "replication_steps", "host_detection_techniques",
        "network_detection_techniques", "references", "finding_guidance", "tags", "extra_fields"
    ] #### QQQ

    # Merge each field carefully, with logging and side-specific handling
    for field_name in finding_fields_to_merge:
        value_from_left = getattr(finding_from_left, field_name, None)
        value_from_right = getattr(finding_from_right, field_name, None)

        if field_name == "tags":
            normalised_tags_left = normalise_tags(" ".join(value_from_left or []))
            normalised_tags_right = normalise_tags(" ".join(value_from_right or []))
            merged_tags = list(set(normalised_tags_left + normalised_tags_right))
            merged_fields["left"][field_name] = merged_tags
            merged_fields["right"][field_name] = merged_tags
            log("DEBUG", f"Tags merged: A={normalised_tags_left}, B={normalised_tags_right}, Result={merged_tags}", prefix="MERGE")

        elif field_name == "extra_fields":
            resolved_extra_fields = {}
            combined_keys = set((value_from_left or {}).keys()) | set((value_from_right or {}).keys())
            for key in combined_keys:
                resolved_value = resolve_conflict((value_from_left or {}).get(key), (value_from_right or {}).get(key))
                resolved_extra_fields[key] = resolved_value
                log("DEBUG", f"Resolved extra field '{key}' → Left:{(value_from_left or {}).get(key)} | Right:{(value_from_right or {}).get(key)} → '{resolved_value}'", prefix="MERGE")
            merged_fields["left"][field_name] = resolved_extra_fields
            merged_fields["right"][field_name] = resolved_extra_fields

        else:
            resolved_value = resolve_conflict(value_from_left, value_from_right)
            merged_fields["left"][field_name] = resolved_value
            merged_fields["right"][field_name] = resolved_value
            log("DEBUG", f"Resolved field '{field_name}' → Left:{value_from_left} | Right:{value_from_right} → '{resolved_value}'", prefix="MERGE")

    # Assign IDs and embed provenance and change status
    merged_fields["left"].update({"id": finding_from_left.id, "source_id_left": finding_from_left.id, "source_id_right": finding_from_right.id, "reason": "unchanged"})
    merged_fields["right"].update({"id": finding_from_right.id, "source_id_left": finding_from_left.id, "source_id_right": finding_from_right.id, "reason": "unchanged"})

    # Change detection: if any field in merged != original, mark as updated
    for dataset_key, original_finding in [("left", finding_from_left), ("right", finding_from_right)]:
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

    log("INFO", f"Completed merge of Left:{finding_from_left.id} and Right:{finding_from_right.id}", prefix="MERGE")
    return merged_fields

# ── Main merge logic ───────────────────────────────────────────────────
def interactive_merge(record_from_side_left: Finding, record_from_side_right: Finding) -> Finding:
    """Run automatic merge then solicit human confirmation/overrides.

    The *canonical* merge result produced by ``merge_individual_findings`` is
    treated as the default for every field.  The analyst sees a diff and may
    pick, such as:
    • **A** – keep the original value from side‑A.
    • **B** – keep the original value from side‑B.
    • **S** – accept the auto‑merge suggestion (default).
    • **E** – hand‑edit via ``$EDITOR`` seeded with the suggestion.
    """
    tui = get_tui()

    log(
        "INFO",
        f"interactive_merge(): {record_from_side_left.id} ↔ {record_from_side_right.id}",
        prefix="MERGE",
    )

    # Step 1 – Run the definitive merge algorithm to generate the offered suggestion.
    auto_merged_fields: Dict[str, Any] = merge_individual_findings(
        record_from_side_left, record_from_side_right
    )["left"]

    # Metadata fields that are not user‑editable.
    _NON_INTERACTIVE_FIELDS: List[str] = [
        "id",
        "source_id_left",
        "source_id_right",
        "reason",
    ]

    merged_record: Dict[str, Any] = {}

    # Iterate deterministically over field names.
    for field_name in auto_merged_fields.keys():
        if field_name in _NON_INTERACTIVE_FIELDS:
            merged_record[field_name] = auto_merged_fields[field_name]
            continue

        value_from_record_left: Any = getattr(record_from_side_left, field_name, None)
        value_from_record_right: Any = getattr(record_from_side_right, field_name, None)
        auto_offered_value: Any = auto_merged_fields[field_name]

        log(
            "DEBUG",
            f"Field '{field_name}': Left={value_from_record_left!r} | Right={value_from_record_right!r} | Auto={auto_offered_value!r}",
            prefix="MERGE",
        )

        # Fast‑path when both sides agree and match the offered suggestion.
        if (
            value_from_record_left == value_from_record_right == auto_offered_value
        ):
            merged_record[field_name] = auto_offered_value
            log(
                "DEBUG",
                f"Field '{field_name}' identical across both sides – auto‑accepted.",
                prefix="MERGE",
            )
            continue

        # ── Interactive resolution ──────────────────────────────────────────
        tui.render_diff_single_field(value_from_record_left, value_from_record_right, title=f"Field name: {field_name}")

        # Establish which option should be highlighted as the default.
        if auto_offered_value:
            default_choice: str = "o"
        else:
            default_choice: str = "e"

        analyst_choice = tui.render_user_choice('Choose:', ['Left', 'Right', 'Offered', 'Edit', 'Skip field'], default_choice,
                                                f'Field-level resolution: {field_name}')

        log(
            "DEBUG",
            f"User selection for '{field_name}' → {analyst_choice.upper()}",
            prefix="MERGE",
        )

        # Commit the chosen value into the merged record.
        if analyst_choice == "l":
            merged_record[field_name] = value_from_record_left
        elif analyst_choice == "r":
            merged_record[field_name] = value_from_record_right
        elif analyst_choice == "o":
            merged_record[field_name] = auto_offered_value
        elif analyst_choice == "s":
            log('WARN', 'User skipped field', 'MERGE')
            continue
        else:  # "e" – manual edit via external editor.
            merged_record[field_name] = tui.invoke_editor(str(auto_offered_value))

        # Sensitivity check inline per field
        if CONFIG['sensitivity_check_enabled']:
            sensitive_terms = load_sensitive_terms(CONFIG["sensitivity_check_terms_file"])
            temp_finding = Finding.from_dict({"id": record_from_side_left.id, field_name: merged_record[field_name]})
            sensitivity_hits = check_finding_for_sensitivities(temp_finding, sensitive_terms)

            if sensitivity_hits.get(field_name):
                for sensitive_term, offered in sensitivity_hits[field_name]:
                    prompt = f"[red]Sensitive term[/red] [yellow]{sensitive_term}[/yellow] in [bold]{field_name}[/bold]\n\n"
                    if offered:
                        prompt += f"Offered: [yellow]{sensitive_term}[/yellow] → [green]{offered}[/green]"
                        action_choices = ['Offered', 'Edit', 'Skip field']
                    else:
                        action_choices = ['Edit', 'Skip field']

                    action = tui.render_user_choice(prompt, options=action_choices, title=f"Field-level resolution: {field_name}")

                    if action == "l" and offered:
                        merged_record[field_name] = merged_record[field_name].replace(sensitive_term, offered)
                    elif action == "e":
                        merged_record[field_name] = tui.invoke_editor(merged_record[field_name])
                    elif action == "s":
                        log("WARN", "User skipped field.", prefix="MERGE")
                        continue

    # Step 2 – preview resolution before writing to object
    preview_table: Table = Table(
        title="Merged Finding (post‑manual)", box=None, show_lines=False
    )
    preview_table.add_column("Field", style="bold white")
    preview_table.add_column("Value", overflow="fold")
    for field_name, final_value in merged_record.items():
        preview_table.add_row(field_name, str(final_value))

    tui.update_data(preview_table, title='Preview')

    if tui.render_user_choice("Write this merged record?", ["yes", "no"], title="Confirm action") != "yes":
        log("WARN", "Merge aborted by user.", prefix="MERGE")
        raise SystemExit(1)

    log("INFO", "Merge finalised.", prefix="MERGE")
    return Finding.from_dict(merged_record)


''' # potentially unused code
    def diff(self, other: 'Finding') -> Dict[str, tuple[Any, Any]]:
        """
        Returns a dictionary of field names whose values differ between this and another Finding.
        Each key maps to a tuple: (self_value, other_value)
        """
        log("DEBUG", f"Diffing finding ID {self.id} against ID {other.id}", prefix="MODEL")
        differences = {}
        for field_name in self.__dataclass_fields__:
            val_self = getattr(self, field_name)
            val_other = getattr(other, field_name)
            log("DEBUG", f"Checking field '{field_name}': self='{val_self}' vs other='{val_other}'", prefix="MODEL")
            if val_self != val_other:
                differences[field_name] = (val_self, val_other)
        log("DEBUG", f"Differences found: {differences}", prefix="MODEL")
        return differences

    def merge_with(self, other: 'Finding', prefer: str = 'larger') -> 'Finding':
        """
        Merges this Finding with another, field by field. Preference is given based on:
        - 'filled' (prefer non-empty)
        - 'tokens' (prefer more words)
        - 'larger' (prefer longer strings)
        """
        log("DEBUG", f"Merging finding ID {self.id} with ID {other.id}", prefix="MODEL")

        merged_data = {}
        for field_name in self.__dataclass_fields__:
            val_a = getattr(self, field_name)
            val_b = getattr(other, field_name)
            log("DEBUG", f"Evaluating merge for field '{field_name}': val_a='{val_a}' val_b='{val_b}'", prefix="MODEL")

            if val_a == val_b:
                merged_data[field_name] = val_a  # identical, safe to use either
                log("DEBUG", f"Values identical. Using '{val_a}'", prefix="MODEL")
            elif not val_a:
                merged_data[field_name] = val_b  # prefer non-empty value
                log("DEBUG", f"val_a empty. Using val_b='{val_b}'", prefix="MODEL")
            elif not val_b:
                merged_data[field_name] = val_a  # prefer non-empty value
                log("DEBUG", f"val_b empty. Using val_a='{val_a}'", prefix="MODEL")
            elif isinstance(val_a, str) and isinstance(val_b, str):
                # For strings, use length or token-count preference
                if prefer == 'tokens':
                    merged = val_a if len(val_a.split()) > len(val_b.split()) else val_b
                else:
                    merged = val_a if len(val_a) > len(val_b) else val_b
                merged_data[field_name] = merged
                log("DEBUG", f"Merged string based on preference '{prefer}': '{merged}'", prefix="MODEL")
            elif isinstance(val_a, list) and isinstance(val_b, list):
                merged_data[field_name] = list(set(val_a + val_b))
                log("DEBUG", f"Merged list: {merged_data[field_name]}", prefix="MODEL")
            elif isinstance(val_a, dict) and isinstance(val_b, dict):
                merged = val_a.copy()
                merged.update(val_b)
                merged_data[field_name] = merged
                log("DEBUG", f"Merged dict: {merged_data[field_name]}", prefix="MODEL")
            else:
                merged_data[field_name] = val_a  # fallback: pick original
                log("DEBUG", f"Fallback merge strategy. Using val_a='{val_a}'", prefix="MODEL")

        merged_finding = Finding(**merged_data)
        log("DEBUG", f"Merged result: {merged_finding}", prefix="MODEL")
        return merged_finding
'''
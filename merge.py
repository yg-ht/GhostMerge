# external module imports
import model
from imports import (dumps, Table, Any, Dict, List, fields, Tuple)
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()
# local module imports
from utils import log, normalise_tags, is_blank, blank_for_type
from model import Finding, is_optional_field, get_type_as_str
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
def get_auto_suggest_values(finding_from_left: Finding, finding_from_right: Finding) -> dict:
    """
    Performs a detailed, field-by-field selection process of two Finding objects to determine an auto-suggest value.
    """
    log("INFO", f"Determining auto-value for findings: {finding_from_left.id} (Left) <-> {finding_from_right.id} (Right)", prefix="MERGE")

    auto_fields = {}

    # Define all fields that must be considered for auto-value
    finding_fields_to_get_auto_value = [
        "severity", "cvss_score", "cvss_vector", "finding_type", "title", "description",
        "impact", "mitigation", "replication_steps", "host_detection_techniques",
        "network_detection_techniques", "references", "finding_guidance", "tags", "extra_fields"
    ] # TODO: change this logic to iterate over the model not a List

    # Get auto-value for each field
    for field_name in finding_fields_to_get_auto_value:
        value_from_left = getattr(finding_from_left, field_name, None)
        value_from_right = getattr(finding_from_right, field_name, None)

        if field_name == "tags":
            normalised_tags_left = normalise_tags(" ".join(value_from_left or []))
            normalised_tags_right = normalise_tags(" ".join(value_from_right or []))
            auto_fields["tags"] = list(set(normalised_tags_left + normalised_tags_right))
            log("DEBUG", f"Tags normalised and merged for auto-value", prefix="MERGE")

        elif field_name == "extra_fields":
            resolved_extra_fields = {}
            combined_keys = set((value_from_left or {}).keys()) | set((value_from_right or {}).keys())
            for key in combined_keys:
                resolved_value = resolve_conflict((value_from_left or {}).get(key), (value_from_right or {}).get(key))
                resolved_extra_fields[key] = resolved_value
                log("DEBUG", f"Resolved extra field '{key}' → Left:{(value_from_left or {}).get(key)} | Right:{(value_from_right or {}).get(key)} → '{resolved_value}'", prefix="MERGE")
            auto_fields["extra_fields"] = resolved_extra_fields

        else: # all str / int etc fields should resolve using the resolve_conflict function
            resolved_value = resolve_conflict(value_from_left, value_from_right)
            auto_fields[field_name] = resolved_value
            log("DEBUG", f"Resolved field '{field_name}' → Left:{value_from_left} | Right:{value_from_right} → '{resolved_value}'", prefix="MERGE")

    log("INFO", f"Gathered the auto-complete values for Left (ID #{finding_from_left.id}) and Right (ID #{finding_from_right.id})", prefix="MERGE")
    return auto_fields

# ── Main merge logic ───────────────────────────────────────────────────
def merge_main(finding_record_pair: Dict[str,Finding|float]) -> Tuple[Finding,Finding]:
    """Run automatic merge then solicit human confirmation/overrides.

    The *canonical* merge result produced by ``merge_individual_findings`` is
    treated as the default for every field.  The analyst sees a diff and may
    pick, such as:
    """
    tui = get_tui()

    finding_left_side = finding_record_pair['left']
    finding_right_side = finding_record_pair['right']
    score = finding_record_pair['score']
    merged_record_left = Finding(finding_left_side.id)
    merged_record_right = Finding(finding_right_side.id)


    log("INFO", f"Starting merge_main for: {finding_left_side.id} ↔ {finding_right_side.id}", prefix="MERGE")

    # Step 1 – Generate the auto-offered suggestions
    auto_value_fields: Dict[str, Any] = get_auto_suggest_values(finding_left_side, finding_right_side)

    # Iterate deterministically over field names.
    for field in fields(Finding):
        if field.name is "id":
            merged_record_left.id = finding_left_side.id
            merged_record_right.id = finding_right_side.id
            continue

        # get the expected type once for future efforts
        expected_type_str = get_type_as_str(field.type)

        value_from_left: Any = getattr(finding_left_side, field.name, blank_for_type(get_type_as_str(field.type)))
        value_from_right: Any = getattr(finding_right_side, field.name, blank_for_type(get_type_as_str(field.type)))
        auto_value: Any = auto_value_fields[field.name]

        log("DEBUG",f"Field '{field}': Left={value_from_left!r} "
                    f"| Right={value_from_right!r} | Auto={auto_value!r}",prefix="MERGE",)

        # Fast‑path when both sides agree and match the offered suggestion.
        if (value_from_left == value_from_right == auto_value):
            #merged_record_left[field.name] = auto_value
            setattr(merged_record_left, field.name, auto_value)
#            merged_record_right[field.name] = auto_value
            setattr(merged_record_right, field.name, auto_value)
            log("DEBUG",f"Field '{field}' identical across both sides – auto‑accepted.",prefix="MERGE",)
            continue

        # ── Interactive resolution ──────────────────────────────────────────
        tui.render_left_and_right_record(finding_record_pair)
        log('WARN', 'Difference detected, please review ready for merge actions', 'MERGE')

        tui.render_user_choice('Waiting for user to complete data review')

        tui.render_diff_single_field(value_from_left, value_from_right, title=f"Field diff for {field}")

        # Establish which option should be highlighted as the default.
        if auto_value:
            default_choice: str = "o"
        else:
            default_choice: str = "e"

        analyst_options = ['Keep both', 'Left only', 'Right only', 'Offered']
        # If the field is permitted to be blank, add this as an option
        is_optional = is_optional_field(expected_type_str)
        if is_optional:
            analyst_options.append(f'Blank')

        analyst_choice = tui.render_user_choice('Choose:', analyst_options, default_choice,
                                                f'Field-level resolution: {field}')

        log(
            "DEBUG",
            f"User selection for '{field}' → {analyst_choice.upper()}",
            prefix="MERGE",
        )

        # Commit the chosen value into the merged record.
        if analyst_choice == "b" and is_optional:
            merged_record_left['left'][field.name] = blank_for_type(expected_type_str)
            merged_record_left['right'][field.name] = blank_for_type(expected_type_str)
        if analyst_choice == "k":
            merged_record_left['left'][field.name] = value_from_left
            merged_record_left['right'][field.name] = value_from_right
        elif analyst_choice == "l":
            merged_record_left['left'][field.name] = value_from_left
            merged_record_left['right'][field.name] = value_from_left
        elif analyst_choice == "r":
            merged_record_left['left'][field.name] = value_from_right
            merged_record_left['right'][field.name] = value_from_right
        elif analyst_choice == "o":
            merged_record_left['left'][field.name] = auto_value
            merged_record_left['right'][field.name] = auto_value

        # Sensitivity check inline per field
        if CONFIG['sensitivity_check_enabled']:
            sensitive_terms = load_sensitive_terms(CONFIG["sensitivity_check_terms_file"])
            temp_finding = Finding.from_dict({"id": finding_left_side.id, field: merged_record_left[field.name]})
            sensitivity_hits = check_finding_for_sensitivities(temp_finding, sensitive_terms)

            if sensitivity_hits.get(field.name):
                action_choices = ['Edit', 'Keep']
                for sensitive_term, offered in sensitivity_hits[field.name]:
                    prompt = f"Sensitive term [yellow]{sensitive_term}[/yellow] in [bold]{field}[/bold]\n\n"
                    if offered:
                        prompt += f"Offered: [yellow]{sensitive_term}[/yellow] → [green]{offered}[/green]"
                        action_choices.append('Offered')

                    action = tui.render_user_choice(prompt, options=action_choices, title=f"Field-level resolution: {field.name}")

                    if action == "o" and offered:
                        merged_record_left[field.name] = merged_record_left[field.name].replace(sensitive_term, offered)
                    elif action == "e":
                        merged_record_left[field.name] = tui.invoke_editor(merged_record_left[field.name])
                    elif action == "k":
                        log("WARN", "Keep field as is", prefix="MERGE")
                        continue

    log("INFO", "This record's merge is finalised.", prefix="MERGE")
    return tuple([Finding.from_dict(merged_record_left), Finding.from_dict(merged_record_right)])
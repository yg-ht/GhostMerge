# external module imports
import model
from imports import (Any, Dict, fields, Tuple)
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()
# local module imports
from utils import log, normalise_tags, is_blank, blank_for_type
from model import Finding, is_optional_field, get_type_as_str
from sensitivity import sensitivities_checker_single_field

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

# ── Finding Merge ───────────────────────────────────────────────────
def get_auto_suggest_values(finding_from_left: Finding, finding_from_right: Finding) -> Finding:
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
            log("DEBUG", f"Tags normalised and combined for auto-value", prefix="MERGE")

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
    return Finding.from_dict(auto_fields)

# ── Main merge logic ───────────────────────────────────────────────────
def merge_main(finding_pair: Dict[str, Finding | float]) -> Tuple[Finding,Finding]:
    """Run automatic merge then solicit human confirmation/overrides.

    finding_record_pair has this structure:
    {
        'left': finding_record_pair['left'],
        'right': finding_record_pair['right'],
        'score': finding_record_pair['score']
    }

    auto_value_fields: has this structure:
    Dict[str, Any] = get_auto_suggest_values(finding_record_pair['left'], finding_record_pair['right'])

    """
    tui = get_tui()

    log("INFO", f"Starting merge_main for: {finding_pair['left'].id} ↔ {finding_pair['right'].id}", prefix="MERGE")

    # Step 1 – Generate the auto-offered suggestions
    finding_pair.update({'auto': get_auto_suggest_values(finding_pair['left'], finding_pair['right'])})

    different_fields = ' | '
    # Iterate deterministically over field names.
    for field in fields(Finding):
        if field.name is "id":
            # we retain these IDs so can just skip
            continue

        # get the expected type once for future efforts
        expected_type_str = get_type_as_str(field.type)

        value_from_left: Any = getattr(finding_pair.get('left'), field.name, blank_for_type(get_type_as_str(field.type)))
        value_from_right: Any = getattr(finding_pair.get('right'), field.name, blank_for_type(get_type_as_str(field.type)))
        auto_value: Any = finding_pair.get('auto').get(field.name)

        log("DEBUG",f"Field '{field}': Left={value_from_left!r} "
                    f"| Right={value_from_right!r} | Auto={auto_value!r}",prefix="MERGE",)

        # Fast‑path when both sides agree and match the offered suggestion.
        if (value_from_left == value_from_right):
            finding_pair['left'].set(field.name, auto_value)
            finding_pair['right'].set(field.name, auto_value)
            log("DEBUG",f"Field '{field}' identical across both sides – auto‑accepted.",prefix="MERGE",)
            continue
        else:
            different_fields = different_fields + field.name + ' | '

        # ── Interactive resolution ──────────────────────────────────────────
        log('WARN', f'Difference detected in: {different_fields}', 'MERGE')
        tui.render_left_and_right_record(finding_pair, different_fields)
        log('WARN', 'Please review above, ready for merge actions', 'MERGE')

        tui.render_user_choice('Waiting for user to complete data review')

        tui.render_diff_single_field(value_from_left, value_from_right, auto_value, title=f"Field diff for {field.name}")

        analyst_options = ['Keep both', 'Left only', 'Right only', 'Merge (left + right)']

        # Establish which option should be highlighted as the default.
        default_choice = ''
        if not auto_value:
            log("DEBUG", "Offered / auto_value is blank, not adding option")
        else:
            if field.name == 'tags':
                analyst_options.append(f'Offered (combine all tags)')
            elif field.name == 'extra_fields':
                analyst_options.append(f'Offered (combine all fields)')
            else:
                analyst_options.append(f'Offered')
            default_choice: str = 'o'

        # If the field is permitted to be blank, add this as an option
        is_optional = is_optional_field(expected_type_str)
        if is_optional:
            analyst_options.append(f'Blank')

        analyst_choice = tui.render_user_choice('Choose:', analyst_options, default_choice,
                                                f"Field-level resolution")

        log(
            "DEBUG",
            f"User selection for '{field}' → {analyst_choice.upper()}",
            prefix="MERGE",
        )

        # Commit the chosen value into the merged record.
        if analyst_choice == "b" and is_optional:
            finding_pair['left'].set(field.name, blank_for_type(expected_type_str))
            finding_pair['right'].set(field.name, blank_for_type(expected_type_str))
        if analyst_choice == "k":
            finding_pair['left'].set(field.name, value_from_left)
            finding_pair['right'].set(field.name, value_from_right)
        elif analyst_choice == "l":
            finding_pair['left'].set(field.name, value_from_left)
            finding_pair['right'].set(field.name, value_from_left)
        elif analyst_choice == "m":
            finding_pair['left'].set(field.name, f"{value_from_left} {value_from_right}")
            finding_pair['right'].set(field.name, f"{value_from_left} {value_from_right}")
        elif analyst_choice == "r":
            finding_pair['left'].set(field.name, value_from_right)
            finding_pair['right'].set(field.name, value_from_right)
        elif analyst_choice == "o" and auto_value:
            finding_pair['left'].set(field.name, auto_value)
            finding_pair['right'].set(field.name, auto_value)

    log("INFO", "This record's merge is finalised.", prefix="MERGE")
    return tuple([finding_pair['left'], finding_pair['right']])
# external module imports
from imports import (Any, auto, Dict, Enum, fields, key, List, md5, Tuple)
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()
# local module imports
from utils import log, normalise_tags, is_blank, blank_for_type
from model import Finding, is_optional_field, get_type_as_str

class ResolvedWinner(Enum):
    NONE = auto()
    LEFT = auto()
    RIGHT = auto()

# ── Conflict Resolution ─────────────────────────────────────────────
def resolve_conflict(value_from_left, value_from_right) -> Tuple[ResolvedWinner, str | None]:
    """
    Resolves a conflict between two versions of a field.
    Preference is given to non-empty values, and if both are present,
    selects the one with more tokens, or the longer value if tied.
    """
    if is_blank(value_from_left) and is_blank(value_from_right):
        return ResolvedWinner.NONE,None
    if is_blank(value_from_left):
        return ResolvedWinner.RIGHT,value_from_right
    if is_blank(value_from_right):
        return ResolvedWinner.LEFT,value_from_left

    len_left, len_right = len(str(value_from_left)), len(str(value_from_right))
    tok_left, tok_right = len(str(value_from_left).split()), len(str(value_from_right).split())

    if tok_left > tok_right:
        return ResolvedWinner.LEFT,value_from_left
    elif tok_right > tok_left:
        return ResolvedWinner.RIGHT,value_from_right
    elif len_left >= len_right:
        return ResolvedWinner.LEFT,value_from_left
    else:
        return ResolvedWinner.RIGHT,value_from_right

# ── Finding Merge ───────────────────────────────────────────────────
def get_auto_suggest_values(finding_from_left: Finding, finding_from_right: Finding) -> Tuple[Finding, dict[str, ResolvedWinner]]:
    """
    Performs a detailed, field-by-field selection process of two Finding objects to determine an auto-suggest value.
    """
    log("INFO", f"Determining auto-value for findings: {finding_from_left.id} (Left) <-> {finding_from_right.id} (Right)", prefix="MERGE")

    auto_fields_values = Finding()
    auto_fields_winner = dict[str, ResolvedWinner | dict[str, ResolvedWinner]]()

    # Get auto-value for each field
    for field_def in fields(Finding):
        field_name = field_def.name
        auto_fields_values[field_name] = {}
        value_from_left = getattr(finding_from_left, field_name, None)
        value_from_right = getattr(finding_from_right, field_name, None)

        if field_name == "tags":
            normalised_tags_left = normalise_tags(" ".join(value_from_left or []))
            normalised_tags_right = normalise_tags(" ".join(value_from_right or []))
            auto_fields_values["tags"] = list(set(normalised_tags_left + normalised_tags_right))
            log("DEBUG", f"Tags normalised and combined for auto-value", prefix="MERGE")

        elif field_name == "extra_fields":
            if not value_from_left or not value_from_right:
                if value_from_left:
                    auto_fields_winner["extra_fields"] = ResolvedWinner.LEFT
                    auto_fields_values["extra_fields"] = value_from_left
                else:
                    auto_fields_winner["extra_fields"] = ResolvedWinner.RIGHT
                    auto_fields_values["extra_fields"] = value_from_right
                continue

            resolved_extra_fields = {}
            resolved_extra_winner = {}
            combined_keys = set((value_from_left or {}).keys()) | set((value_from_right or {}).keys())
            for key in combined_keys:
                resolved_side, resolved_value = resolve_conflict((value_from_left or {}).get(key), (value_from_right or {}).get(key))
                resolved_extra_winner[key] = resolved_side
                resolved_extra_fields[key] = resolved_value
                log("DEBUG", f"Resolved extra field '{key}' → Left:{(value_from_left or {}).get(key)} | Right:{(value_from_right or {}).get(key)} → '{resolved_side}'", prefix="MERGE")
            auto_fields_values["extra_fields"] = resolved_extra_fields
            auto_fields_winner["extra_fields"] = resolved_extra_winner

        else: # all str / int etc fields should resolve using the resolve_conflict function
            resolved_side, resolved_value = resolve_conflict(value_from_left, value_from_right)
            auto_fields_winner[field_name] = resolved_side
            auto_fields_values[field_name] = resolved_value
            log("DEBUG", f"Resolved field '{field_name}' → Left:{value_from_left} | Right:{value_from_right} → '{resolved_value}'", prefix="MERGE")

    log("DEBUG", f"Gathered the auto-complete values for Left (ID #{finding_from_left.id}) and Right (ID #{finding_from_right.id})", prefix="MERGE")
    return auto_fields_values, auto_fields_winner

def renumber_findings(
    left_findings: List[Finding],
    right_findings: List[Finding],
    start_id: int = 1,
) -> tuple[List[Finding], List[Finding]]:
    """
    Reassign IDs so that each pair of left/right findings share a new, unique ID.
    IDs are allocated sequentially starting at start_id.
    """
    if len(left_findings) != len(right_findings):
        # This really should not happen with your current merge logic
        raise ValueError(
            f"Cannot renumber findings, length mismatch: "
            f"left={len(left_findings)} right={len(right_findings)}"
        )

    current = start_id
    for left, right in zip(left_findings, right_findings):
        left.id = current
        right.id = current
        current += 1

    return left_findings, right_findings

# ── Main merge logic ───────────────────────────────────────────────────
def merge_main(finding_pair: Dict[str, Finding | float | Dict[str, ResolvedWinner]]) -> Tuple[Finding,Finding]:
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

    # Generate the auto-offered suggestions
    auto_suggest_values, auto_suggest_winner = get_auto_suggest_values(finding_pair['left'], finding_pair['right'])
    # Update the finding pair to make it a trio
    finding_pair.update({'auto_value': auto_suggest_values})
    finding_pair.update({'auto_side': auto_suggest_winner})

    different_fields = ' | '
    # Iterate deterministically over field names to identify differences
    for field in fields(Finding):
        if field.name == "id":
            # we retain these IDs so can just skip
            continue

        # get the expected type once for future efforts
        expected_type_str = get_type_as_str(field.type)

        left_value: Any = getattr(finding_pair.get('left'), field.name, blank_for_type(expected_type_str))
        right_value: Any = getattr(finding_pair.get('right'), field.name, blank_for_type(expected_type_str))
        auto_value: Any = finding_pair.get('auto_value')
        auto_side: dict[str, ResolvedWinner] = finding_pair.get('auto_side')

        log("DEBUG",f"Field '{field.name}': Left={left_value!r} "
                    f"| Right={right_value!r} | Auto={auto_side!r}",prefix="MERGE",)

        # Fast‑path when both sides agree and match the offered suggestion.
        if left_value == right_value:
            finding_pair['left'].set(field.name, auto_value.get(field.name))
            finding_pair['right'].set(field.name, auto_value.get(field.name))
            log("DEBUG",f"Field '{field.name}' identical across both sides – auto‑accepted.",prefix="MERGE")
            continue
        else:
            different_fields = different_fields + field.name + ' | '

    log('DEBUG', f'Difference detected in: {different_fields}', 'MERGE')

    # Iterate deterministically over field names to process differences
    for field in fields(Finding):
        if field.name in different_fields:
            # get the expected type once for future efforts
            expected_type_str = get_type_as_str(field.type)
            log('DEBUG', f'Data type is expected to be: {expected_type_str}', prefix='TUI')

            left_value: Any = getattr(finding_pair.get('left'), field.name,
                                           blank_for_type(get_type_as_str(field.type)))
            right_value: Any = getattr(finding_pair.get('right'), field.name,
                                            blank_for_type(get_type_as_str(field.type)))
            auto_value: Any = finding_pair.get('auto_value').get(field.name)
            auto_side: Any = finding_pair.get('auto_side').get(field.name)

            left_hash = md5(str(left_value).encode("utf-8")).hexdigest()
            right_hash = md5(str(right_value).encode("utf-8")).hexdigest()

            log('INFO', f'Field: {field.name} with hashes | Left: {left_hash} | Right: {right_hash}', prefix='TUI')


            # ── Interactive resolution ──────────────────────────────────────────
            if CONFIG['interactive_mode'] or not auto_value or not auto_side:
                tui.render_left_and_right_whole_finding_record(finding_pair, different_fields)
                log('WARN', 'Please review above, ready for merge actions', 'MERGE')

                tui.render_user_choice('Waiting for user to complete data review')

                tui.render_diff_single_field(left_value, right_value, auto_value, auto_side, title=f"Field diff for {field.name}")

                analyst_options = ['Keep Left and Right intact (▲ key)', 'Left only (◀️ key)', 'Right only (▶️ key)']

                # Establish which option should be highlighted as the default.
                default_choice = ''
                if not auto_value:
                    log("DEBUG", "Offered / auto_value is blank, not adding option")
                else:
                    if field.name == 'tags':
                        analyst_options.append(f'Offered (spacebar) (combine all tags)')
                    elif field.name == 'extra_fields':
                        analyst_options.append(f'Offered (spacebar) (combine all fields)')
                    else:
                        analyst_options.append(f'Offered (spacebar)')
                    default_choice: str = 'o'

                if 'str' in expected_type_str:
                    analyst_options.append('Merge Left + Right together')

                # If the field is permitted to be blank, add this as an option
                is_optional = is_optional_field(expected_type_str)
                enable_down_key = False
                if is_optional:
                    analyst_options.append(f'Blank (▼ key)')
                    enable_down_key = True

                analyst_choice = tui.render_user_choice('Choose:', analyst_options, default_choice, f"Field-level resolution",
                                                        arrows_enabled={'UP': True, 'DOWN': enable_down_key, 'LEFT': True, 'RIGHT': True})

                analyst_choice_debug_out = None
                if analyst_choice not in [key.UP, key.DOWN, key.LEFT, key.RIGHT]:
                    analyst_choice_debug_out = analyst_choice
                else:
                    if analyst_choice == key.UP:
                        analyst_choice_debug_out = 'Up'
                    if analyst_choice == key.DOWN:
                        analyst_choice_debug_out = 'Down'
                    if analyst_choice == key.LEFT:
                        analyst_choice_debug_out = 'Left'
                    if analyst_choice == key.RIGHT:
                        analyst_choice_debug_out = 'Right'

                log(
                    "DEBUG",
                    f"User selection for '{field.name}' → {analyst_choice_debug_out.upper()}",
                    prefix="MERGE",
                )

                # Commit the chosen value into the merged record.
                if (analyst_choice == "b" or analyst_choice == key.DOWN) and is_optional:
                    finding_pair['left'].set(field.name, blank_for_type(expected_type_str))
                    finding_pair['right'].set(field.name, blank_for_type(expected_type_str))
                elif analyst_choice == "k" or analyst_choice == key.UP:
                    finding_pair['left'].set(field.name, left_value)
                    finding_pair['right'].set(field.name, right_value)
                elif analyst_choice == "l" or analyst_choice == key.LEFT:
                    finding_pair['left'].set(field.name, left_value)
                    finding_pair['right'].set(field.name, left_value)
                elif analyst_choice == "m":
                    finding_pair['left'].set(field.name, f"{left_value} {right_value}")
                    finding_pair['right'].set(field.name, f"{left_value} {right_value}")
                elif analyst_choice == "r" or analyst_choice == key.RIGHT:
                    finding_pair['left'].set(field.name, right_value)
                    finding_pair['right'].set(field.name, right_value)
                elif analyst_choice == "o" and auto_value:
                    finding_pair['left'].set(field.name, auto_value)
                    finding_pair['right'].set(field.name, auto_value)
            else:
                # We are auto-accepting the auto-offered values if we are configured not to use interactive mode and
                # the auto-value / auto-side variables are populated.  This is perfectly valid, but will result in "best
                # guess" scenarios that will likely not be as desired.
                finding_pair['left'].set(field.name, auto_value)
                finding_pair['right'].set(field.name, auto_value)

    log("INFO", "This record's merge is finalised.", prefix="MERGE")
    return finding_pair['left'], finding_pair['right']
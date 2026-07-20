# external module imports
from imports import (Any, BeautifulSoup, Dict, fields, key, List, NavigableString, os, re, Tuple, Optional)
from hashlib import sha256
import json
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()
# local module imports
from utils import log, stringify_field, apply_configured_normalisation, _normalise_sensitive_term_for_matching
from model import Finding


def empty_pre_match_sensitivity_stats() -> Dict[str, int]:
    """Return a fresh counter set for one pre-match record collection."""
    return {
        "records_scanned": 0,
        "fields_scanned": 0,
        "hits_found": 0,
        "replacements_applied": 0,
        "flag_only_hits_deferred": 0,
    }


def sensitive_terms_digest(terms: Dict[str, Optional[str]]) -> str:
    """Return a stable digest without exposing configured terms in diagnostics."""
    canonical_terms = json.dumps(terms, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(canonical_terms.encode("utf-8")).hexdigest()

def _opening_tag_name(tag_text: str) -> Optional[str]:
    """Return the element name if tag_text is an opening HTML tag."""
    tag_text = tag_text.strip()
    match = re.fullmatch(r"<\s*([A-Za-z][A-Za-z0-9:_-]*)\b[^<>]*>", tag_text)
    if not match:
        return None
    if re.match(r"<\s*/", tag_text):
        return None
    if re.search(r"/\s*>$", tag_text):
        return None
    return match.group(1).lower()

def _find_matching_closing_tag(text: str, opening_end: int, tag_name: str) -> Optional[Tuple[int, int]]:
    """Find the closing tag paired with an opening sensitive-term tag."""
    tag_pattern = re.compile(
        rf"<\s*(/?)\s*{re.escape(tag_name)}\b[^<>]*?>",
        flags=re.IGNORECASE,
    )
    depth = 1

    for match in tag_pattern.finditer(text, opening_end):
        tag_text = match.group(0)
        is_closing = bool(match.group(1))
        is_self_closing = bool(re.search(r"/\s*>$", tag_text))

        if is_self_closing:
            continue

        if is_closing:
            depth -= 1
            if depth == 0:
                return match.span()
        else:
            depth += 1

    return None

def _replacement_closing_tag(opening_replacement: str) -> Optional[str]:
    """Return the closing tag implied by an opening replacement tag."""
    replacement_tag = _opening_tag_name(opening_replacement)
    if replacement_tag is None:
        return None
    return f"</{replacement_tag}>"

def _replace_literal_or_opening_tag_pair(field_value: str, sensitive_term: str, replacement: str) -> str:
    """Replace literal sensitive terms while preserving paired HTML tag safety.

    HTML formatting rewrites are configured separately, but this fallback keeps
    older local sensitive-term files from producing dangling closing tags.
    """
    tag_name = _opening_tag_name(sensitive_term)
    if tag_name is None:
        return re.sub(re.escape(sensitive_term), replacement, field_value, flags=re.IGNORECASE)

    closing_replacement = _replacement_closing_tag(replacement) or ""
    sensitive_pattern = re.compile(re.escape(sensitive_term), flags=re.IGNORECASE)
    result_parts = []
    cursor = 0

    for match in sensitive_pattern.finditer(field_value):
        if match.start() < cursor:
            continue

        closing_span = _find_matching_closing_tag(field_value, match.end(), tag_name)
        if closing_span is None:
            result_parts.append(field_value[cursor:match.start()])
            result_parts.append(replacement)
            cursor = match.end()
            continue

        closing_start, closing_end = closing_span
        result_parts.append(field_value[cursor:match.start()])
        result_parts.append(replacement)
        result_parts.append(field_value[match.end():closing_start])
        result_parts.append(closing_replacement)
        cursor = closing_end

    if cursor == 0:
        return field_value

    result_parts.append(field_value[cursor:])
    return "".join(result_parts)

def load_sensitive_terms(filename: str, filepath: str) -> Dict[str, Optional[str]] | None:
    """Parses a file of sensitive terms and optional replacements."""
    sensitive_terms_filepaths = [
                                str(filename),
                                f"{filename}.local",
                                os.path.join(str(filepath), str(filename)),
                                os.path.join(str(filepath), f"{filename}.local"),
                               ]

    sensitive_terms_file = None
    for sensitive_terms_filepath in sensitive_terms_filepaths:
        try:
            with open(sensitive_terms_filepath) as f:
                sensitive_terms_file = sensitive_terms_filepath
        except FileNotFoundError:
            log('DEBUG', f'No sensitive terms file found at {sensitive_terms_filepath}', prefix="SENSITIVITY")
    if sensitive_terms_file is None:
        log('WARN', f'No sensitive terms file found - unable to check for sensitive terms!', prefix="SENSITIVITY")
        return None

    terms = {}
    try:
        log("DEBUG", f"Opening sensitivity terms file at: {sensitive_terms_file}", prefix="SENSITIVITY")
        with open(sensitive_terms_file, 'r', encoding='utf-8') as f:
            for line_number, line in enumerate(f, start=1):
                original_line = line.strip()
                if not original_line or original_line.startswith("#"):
                    log("DEBUG", f"Skipping comment/empty line {line_number}", prefix="SENSITIVITY")
                    continue
                if " => " in original_line:
                    term, replacement = map(str.strip, original_line.split(" => ", 1))
                    # Rule values can themselves be sensitive, so diagnostics
                    # identify only the rule shape and source line.
                    log("DEBUG", f"Parsed replacement rule on line {line_number}", prefix="SENSITIVITY")
                    normalised_term = _normalise_sensitive_term_for_matching(term).lower()
                    terms[normalised_term] = replacement
                else:
                    log("DEBUG", f"Parsed flag-only rule on line {line_number}", prefix="SENSITIVITY")
                    normalised_term = _normalise_sensitive_term_for_matching(original_line).lower()
                    terms[normalised_term] = None
        log("DEBUG", f"Loaded {len(terms)} sensitive terms", prefix="SENSITIVITY")
    except Exception as e:
        log("ERROR", "Failed to load sensitive terms file, unable to continue", prefix="SENSITIVITY", exception=e)
        return None
    return terms

def remove_double_spaces_from_string(input_string: str) -> str:
    result = re.sub(r' {2,}', ' ', input_string)
    if result != input_string:
        log("DEBUG", "Double spaces collapsed", prefix="UTILS")
    else:
        log("DEBUG", "No double spaces to collapse", prefix="UTILS")
    return result

def check_for_sensitivities(field, terms) -> List[Tuple[str, Optional[str]]]:
    """Returns List of [(found_term, optional suggested_replacement)...] if sensitivities are found, else []."""
    results = []
    field = apply_configured_normalisation(field)
    stringified_field = stringify_field(field)
    if not stringified_field or not isinstance(stringified_field, str):
        log("DEBUG", "Skipping empty sensitivity-check field", prefix="SENSITIVITY")
        return results
    else:
        lowered = stringified_field.lower()
        log("DEBUG", f"Scanning text ({len(stringified_field)} chars) for {len(terms)} terms", prefix="SENSITIVITY")
        for term, replacement in terms.items():
            if term in lowered:
                # Record the event without copying source content, rules, or
                # proposed replacements into application logs.
                log("INFO", "Sensitive term match found", prefix="SENSITIVITY")
                results.append((term, replacement))
    return results

def apply_sensitive_replacement(field_value: Any, sensitive_term: str, replacement: str) -> Any:
    """Replace a sensitive term using literal, case-insensitive matching.

    Formatting-only HTML rewrites are handled by configured normalisation, but
    opening-tag replacements still remove the paired closing tag for backward
    compatibility with older local sensitive-term files.
    """
    field_value = apply_configured_normalisation(field_value)
    if not isinstance(field_value, str):
        log(
            "WARN",
            f"Cannot safely replace sensitive term in non-string field value of type {type(field_value).__name__}",
            prefix="SENSITIVITY",
        )
        return field_value

    if replacement is None:
        replacement = ""

    replaced = _replace_literal_or_opening_tag_pair(field_value, sensitive_term, replacement)
    return apply_configured_normalisation(replaced)


def apply_pre_match_sensitivity_replacements(
    records: List[Any],
    terms: Dict[str, Optional[str]],
) -> Dict[str, int]:
    """Apply explicit replacements before matching and return non-sensitive counters.

    Flag-only terms deliberately remain unchanged for the later analyst review.
    Records are updated in place so callers can continue through their existing
    matching pipeline without converting model objects a second time.
    """
    stats = empty_pre_match_sensitivity_stats()
    if not terms:
        return stats

    for record in records:
        stats["records_scanned"] += 1
        for field_def in fields(record):
            if field_def.name == "id":
                continue

            field_value = record.get(field_def.name)
            if not field_value:
                continue

            stats["fields_scanned"] += 1
            for sensitive_term, offered in check_for_sensitivities(field_value, terms):
                stats["hits_found"] += 1
                if offered is None:
                    stats["flag_only_hits_deferred"] += 1
                    continue

                current_value = record.get(field_def.name)
                replaced_value = apply_sensitive_replacement(current_value, sensitive_term, offered)
                if replaced_value != current_value:
                    record.set(field_def.name, replaced_value)
                    stats["replacements_applied"] += 1

    return stats

def sensitivities_checker_records(
    records: List[Finding],
    field_side: str,
    terms: Dict[str, Optional[str]],
    interactive_override: Optional[bool] = None,
    prompt_for_flag_only: bool = True,
) -> List[Finding]:
    return [
        sensitivities_checker_single_record(
            record,
            field_side,
            terms,
            interactive_override=interactive_override,
            prompt_for_flag_only=prompt_for_flag_only,
        )
        for record in records
    ]

def sensitivities_checker_single_field(field_name: str, record: Finding, field_side: str, terms: Dict[str, Optional[str]], interactive_override: Optional[bool] = None, prompt_for_flag_only: bool = True) -> Finding:
    tui = get_tui()
    sensitivity_hits = check_for_sensitivities(record.get(field_name), terms)

    if len(sensitivity_hits) > 0:
        interactive_mode = (
            CONFIG['interactive_mode']
            if interactive_override is None
            else interactive_override
        )
        action_choices = ['Edit (▲ key)', 'Keep (▼ key)']
        for sensitive_term, offered in sensitivity_hits:
            if offered is None and not prompt_for_flag_only:
                log(
                    'DEBUG',
                    'Skipping flag-only sensitive term during non-interactive sensitivity pass',
                    prefix="SENSITIVITY",
                )
                continue
            if interactive_mode or offered is None:
                tui.blank_data()
                tui.render_single_whole_finding_record(record, sensitive_term, field_name)
                prompt = (f"Sensitive term [bold red]{sensitive_term}[/bold red] in [bold yellow]{field_name}[/bold yellow]"
                          f" field [bold]{record.get(field_name)[:25]}[/bold] on {field_side} record set\n\n")
                default_choice = ''
                if offered is not None:
                    prompt += f"Offered: [bold red]{sensitive_term}[/bold red] → [green]{offered}[/green]"
                    action_choices.append('Offered (spacebar)')
                    default_choice: str = 'o'

                action = tui.render_user_choice(prompt, options=action_choices,
                                                title=f"Field-level sensitive term resolution: {field_name}",
                                                default=default_choice,
                                                arrows_enabled={'UP': True, 'DOWN': True, 'LEFT': False, 'RIGHT': False})

                analyst_choice_debug_out = None
                if action not in [key.UP, key.DOWN, key.LEFT, key.RIGHT]:
                    analyst_choice_debug_out = action
                else:
                    if action == key.UP:
                        analyst_choice_debug_out = 'Up'
                    if action == key.DOWN:
                        analyst_choice_debug_out = 'Down'
                    if action == key.LEFT:
                        analyst_choice_debug_out = 'Left'
                    if action == key.RIGHT:
                        analyst_choice_debug_out = 'Right'

                if action == "o" and offered is not None:
                    log('DEBUG', 'User chose the offered sensitivity replacement', prefix="SENSITIVITY")
                    result = apply_sensitive_replacement(record.get(field_name), sensitive_term, offered)
                    record.set(field_name, result)
                elif action == "e" or action == key.UP:
                    edited_term = tui.invoke_editor(record.get(field_name))
                    log('DEBUG', 'User supplied a custom sensitivity replacement', prefix="SENSITIVITY")
                    result = apply_sensitive_replacement(record.get(field_name), sensitive_term, edited_term)
                    record.set(field_name, result)
                elif action == "k" or action == key.DOWN:
                    log("WARN", "User chose to Keep field as is", prefix="SENSITIVITY")
                    continue
            else:
                # We are auto-accepting the auto-offered values if we are configured not to use interactive mode and
                # the offered variable is populated.  This is perfectly valid, but will result in "best
                # guess" scenarios that will likely not be as desired.
                log('DEBUG', 'Auto-accepted the offered sensitivity replacement', prefix="SENSITIVITY")
                result = apply_sensitive_replacement(record.get(field_name), sensitive_term, offered)
                record.set(field_name, result)

    return record

def sensitivities_checker_single_record(
    record: Finding,
    field_side: str,
    terms: Dict[str, Optional[str]],
    interactive_override: Optional[bool] = None,
    prompt_for_flag_only: bool = True,
) -> Finding:
    if terms:
        for field in fields(Finding):
            log('DEBUG', f'Checking {field.name} for sensitive terms', prefix="SENSITIVITY")

            if field.name == "id":
                # We retain these IDs, so skip them.
                continue

            if record.get(field.name):
                result_sensitivities = sensitivities_checker_single_field(
                    field.name,
                    record,
                    field_side,
                    terms,
                    interactive_override=interactive_override,
                    prompt_for_flag_only=prompt_for_flag_only,
                )

                if result_sensitivities:
                    log(
                        'DEBUG',
                        f'Sensitivity check of "{field.name}" completed with a result',
                        prefix="SENSITIVITY",
                    )

    return record

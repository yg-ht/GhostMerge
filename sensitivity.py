# external module imports
from os import close

from imports import (Dict, fields, List, os, re, Tuple, Optional)
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()
# local module imports
from utils import log, stringify_field
from model import Finding

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
                f.close()
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
                if "=>" in original_line:
                    term, replacement = map(str.strip, original_line.split("=>", 1))
                    log("DEBUG", f"Parsed replacement line {line_number}: '{term}' => '{replacement}'", prefix="SENSITIVITY")
                    terms[term.lower()] = replacement
                else:
                    log("DEBUG", f"Parsed flag-only line {line_number}: '{original_line}'", prefix="SENSITIVITY")
                    terms[original_line.lower()] = None
        log("DEBUG", f"Loaded {len(terms)} sensitive terms", prefix="SENSITIVITY")
    except Exception as e:
        log("ERROR", "Failed to load sensitive terms file, unable to continue", prefix="SENSITIVITY", exception=e)
        return None
    return terms

def check_for_sensitivities(field, terms) -> List[Tuple[str, Optional[str]]]:
    """Returns List of [(found_term, optional suggested_replacement)...] if sensitivities are found, else None."""

    results = []
    stringified_field = stringify_field(field)
    log("DEBUG", f'Checking content starting: "{stringified_field[:50]}" for sensitive content', prefix="SENSITIVITY")
    if not stringified_field or not isinstance(stringified_field, str):
        log("DEBUG", f"Skipping field '{field}' (empty or non-string)", prefix="SENSITIVITY")
        return results
    else:
        lowered = stringified_field.lower()
        log("DEBUG", f"Scanning text ({len(stringified_field)} chars) for {len(terms)} terms", prefix="SENSITIVITY")
        for term, replacement in terms.items():
            if term in lowered:
                log("INFO", f"Sensitive term found: '{term}' → Suggested: '{replacement}'", prefix="SENSITIVITY")
                results.append((term, replacement))
    return results

def sensitivities_checker_single_field(field_name: str, record: Finding, field_side: str, terms: Dict[str, Optional[str]]) -> Finding:
    tui = get_tui()
    sensitivity_hits = check_for_sensitivities(record.get(field_name), terms)

    if len(sensitivity_hits) > 0:
        action_choices = ['Edit', 'Keep']
        for sensitive_term, offered in sensitivity_hits:
            tui.blank_data()
            tui.render_single_whole_finding_record(record, sensitive_term, field_name)
            prompt = (f"Sensitive term [bold red]{sensitive_term}[/bold red] in [bold yellow]{field_name}[/bold yellow]"
                      f" field [bold]{record.get(field_name)[:25]}[/bold] on {field_side} record set\n\n")
            if offered:
                prompt += f"Offered: [bold red]{sensitive_term}[/bold red] → [green]{offered}[/green]"
                action_choices.append('Offered')

            action = tui.render_user_choice(prompt, options=action_choices,
                                            title=f"Field-level resolution: {field_name}")

            if action == "o" and offered:
                log('DEBUG', f'User chose Offered solution: "{offered}"', prefix="SENSITIVITY")
                result = re.sub(sensitive_term, offered, record.get(field_name), flags=re.IGNORECASE)
                record.set(field_name, result)
            elif action == "e":
                edited_term = tui.invoke_editor(record.get(field_name))
                log('DEBUG', f'User chose to edit and set: "{edited_term}"', prefix="SENSITIVITY")
                result = re.sub(sensitive_term, edited_term, record.get(field_name), flags=re.IGNORECASE)
                record.set(field_name, result)
            elif action == "k":
                log("WARN", "User chose to Keep field as is", prefix="SENSITIVITY")
                continue

    return record

def sensitivities_checker_single_record(record: Finding, field_side: str, terms: Dict[str, Optional[str]]) -> Finding:
    if terms:
        for field in fields(Finding):
            log('DEBUG', f'Checking {field.name} for sensitive terms', prefix="SENSITIVITY")
            if field.name is "id":
                # we retain these IDs so can just skip
                continue

            if record.get(field.name):
                # Sensitivity check inline per field
                result_sensitivities = sensitivities_checker_single_field(field.name, record, field_side, terms)
                if result_sensitivities:
                    log('DEBUG', f'Sensitivity check of "{field.name}" resulted in: "{str(result_sensitivities.get(field.name))[:30]}"', prefix="SENSITIVITY")
                record.set(field.name, result_sensitivities.get(field.name))

    return record
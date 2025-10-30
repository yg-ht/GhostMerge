# external module imports
from imports import (Dict, List, Tuple, Optional)
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()
# local module imports
from utils import log, stringify_field
from model import Finding

def load_sensitive_terms(path: str) -> Dict[str, Optional[str]]:
    """Parses a file of sensitive terms and optional replacements."""
    terms = {}
    try:
        log("DEBUG", f"Opening sensitivity terms file at: {path}", prefix="SENSITIVITY")
        with open(path, 'r', encoding='utf-8') as f:
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
        log("INFO", f"Loaded {len(terms)} sensitive terms", prefix="SENSITIVITY")
    except Exception as e:
        log("ERROR", "Failed to load sensitive terms file", prefix="SENSITIVITY", exception=e)
        raise
    return terms

def check_for_sensitivities(field) -> List[Tuple[str, Optional[str]]]:
    """Returns List of [(found_term, optional suggested_replacement)...] if sensitivities are found, else None."""
    terms = load_sensitive_terms(CONFIG["sensitivity_check_terms_file"])

    results = []
    stringified_field = stringify_field(field)
    log("DEBUG", f"Checking content starting: {stringified_field:50} for sensitive content", prefix="SENSITIVITY")
    if not stringified_field or not isinstance(stringified_field, str):
        log("DEBUG", f"Skipping field '{field}' (empty or non-string)", prefix="SENSITIVITY")
        return None
    else:
        lowered = stringified_field.lower()
        log("DEBUG", f"Scanning text ({len(stringified_field)} chars) for {len(terms)} terms", prefix="SENSITIVITY")
        for term, replacement in terms.items():
            if term in lowered:
                log("DEBUG", f"Sensitive term found: '{term}' → Suggested: '{replacement}'", prefix="SENSITIVITY")
                results.append((term, replacement))
    return results

def main_sensitivities_checker(field_value: str, field_side: str) -> str | None:
    sensitivity_hits = check_for_sensitivities(field_value)
    tui = get_tui()

    result = None

    if len(sensitivity_hits) > 0:
        action_choices = ['Edit', 'Keep']
        for sensitive_term, offered in sensitivity_hits:
            prompt = f"Sensitive term [yellow]{sensitive_term}[/yellow] in [bold]{field_value}[/bold] on {field_side}\n\n"
            if offered:
                prompt += f"Offered: [yellow]{sensitive_term}[/yellow] → [green]{offered}[/green]"
                action_choices.append('Offered')

            action = tui.render_user_choice(prompt, options=action_choices,
                                            title=f"Field-level resolution: {field_value.name}")

            if action == "o" and offered:
                result = field_value.replace(sensitive_term, offered)
            elif action == "e":
                edited_term = tui.invoke_editor(field_value)
                result = field_value.replace(sensitive_term, edited_term)
            elif action == "k":
                log("WARN", "Keep field as is", prefix="MERGE")
                continue

    return result
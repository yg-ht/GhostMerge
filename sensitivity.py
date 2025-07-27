# external module imports
from imports import (Dict, List, Tuple, Optional)
# get global state objects (CONFIG and TUI)
from globals import get_config
CONFIG = get_config()
# local module imports
from utils import log
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

def scan_for_sensitive_terms(text: str, terms: Dict[str, Optional[str]]) -> List[Tuple[str, Optional[str]]]:
    """Scans a string for known sensitive terms. Returns list of (term, suggestion)."""
    found = []
    lowered = text.lower()
    log("DEBUG", f"Scanning text of length {len(text)} for {len(terms)} terms", prefix="SENSITIVITY")

    for term, replacement in terms.items():
        if term in lowered:
            log("DEBUG", f"Match found: '{term}' → Suggested: '{replacement}'", prefix="SENSITIVITY")
            found.append((term, replacement))
    return found

def check_finding_for_sensitivities(finding: Finding, terms: Dict[str, Optional[str]]) -> Dict[str, List[Tuple[str, Optional[str]]]]:
    """Returns dict of field -> [(term, suggestion)...] if sensitivities are found."""
    results = {}
    fields_to_check = [
        "description", "impact", "mitigation", "replication_steps",
        "references", "finding_guidance"
    ]
    log("DEBUG", f"Checking finding ID: {finding.id} for sensitive content", prefix="SENSITIVITY")
    for field in fields_to_check:
        content = getattr(finding, field, None)
        if not content or not isinstance(content, str):
            log("DEBUG", f"Skipping field '{field}' (empty or non-string)", prefix="SENSITIVITY")
            continue
        matches = scan_for_sensitive_terms(content, terms)
        if matches:
            log("INFO", f"Sensitive terms found in '{field}': {matches}", prefix="SENSITIVITY")
            results[field] = matches
    return results

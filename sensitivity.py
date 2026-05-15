# external module imports

from imports import (Any, BeautifulSoup, Dict, fields, key, List, NavigableString, os, re, Tuple, Optional)
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

def remove_double_spaces_from_string(input_string: str) -> str:
    result = re.sub(r' {2,}', ' ', input_string)
    if result != input_string:
        log("DEBUG", "Double spaces collapsed", prefix="UTILS")
    else:
        log("DEBUG", "No double spaces to collapse", prefix="UTILS")
    return result

def _opening_tag_name(tag_text: str) -> Optional[str]:
    """Return the element name if tag_text is an opening HTML tag, otherwise None."""
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
    """Find the closing tag span paired with an opening tag ending at opening_end.

    This is intentionally small and HTML-ish rather than a full parser. It only
    tracks tags with the same element name, which is enough to avoid deleting the
    first unrelated </tag> when same-named elements are nested.
    """
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

def apply_configured_normalisation(value: Any) -> Any:
    """
    Apply configured normalisation recursively to strings, lists, and dictionaries.
    Non-string scalar values are returned unchanged.
    """
    if isinstance(value, str):
        return apply_configured_string_normalisation(value)
    if isinstance(value, list):
        return [apply_configured_normalisation(item) for item in value]
    if isinstance(value, tuple):
        return tuple(apply_configured_normalisation(item) for item in value)
    if isinstance(value, dict):
        return {
            key: apply_configured_normalisation(item)
            for key, item in value.items()
        }
    return value

def _replacement_closing_tag(opening_replacement: str) -> Optional[str]:
    """Return the closing tag needed by an opening replacement.

    None means the replacement is not itself an opening tag and any matched closing
    tag for the sensitive opening tag should be removed.
    """
    replacement_tag = _opening_tag_name(opening_replacement)
    if replacement_tag is None:
        return None
    return f"</{replacement_tag}>"

def _replace_sensitive_opening_tag_with_closing_pair(field_value: str, sensitive_term: str, replacement: str) -> str:
    """Replace an opening tag term and its paired closing tag.

    Examples:
      - <mark> =>            removes both <mark> and </mark>
      - <b> => <strong>      replaces </b> with </strong>
      - <p style="x"> => <p> keeps the paired </p> as </p>
    """
    tag_name = _opening_tag_name(sensitive_term)
    if tag_name is None:
        sensitive_pattern = re.escape(sensitive_term)
        return re.sub(sensitive_pattern, replacement, field_value, flags=re.IGNORECASE)

    closing_replacement = _replacement_closing_tag(replacement)
    if closing_replacement is None:
        closing_replacement = ""

    sensitive_pattern = re.compile(re.escape(sensitive_term), flags=re.IGNORECASE)
    result_parts = []
    cursor = 0
    replacement_count = 0

    for match in sensitive_pattern.finditer(field_value):
        if match.start() < cursor:
            continue

        closing_span = _find_matching_closing_tag(field_value, match.end(), tag_name)
        if closing_span is None:
            result_parts.append(field_value[cursor:match.start()])
            result_parts.append(replacement)
            cursor = match.end()
            replacement_count += 1
            continue

        closing_start, closing_end = closing_span
        result_parts.append(field_value[cursor:match.start()])
        result_parts.append(replacement)
        result_parts.append(field_value[match.end():closing_start])
        result_parts.append(closing_replacement)
        cursor = closing_end
        replacement_count += 1

    if replacement_count == 0:
        return field_value

    result_parts.append(field_value[cursor:])
    log(
        "DEBUG",
        f"Sensitive opening tag replacement also handled {replacement_count} closing tag(s) for </{tag_name}>",
        prefix="SENSITIVITY",
    )
    return "".join(result_parts)

def _normalise_sensitive_term_for_matching(term: str) -> str:
    """Normalise a sensitive-term key without deleting empty HTML tags.

    Record fields are normalised before sensitivity checks. Term keys need the
    same harmless whitespace and tag-spacing cleanup so entries such as
    "<mark > =>" still match "<mark>" in the cleaned record. Do not run
    remove_pointless_html_tags here, because an empty tag in a terms file is the
    thing to match, not pointless content to discard.
    """
    normalised = term

    if CONFIG.get('normalise_line_endings', False):
        normalised = normalised.replace("\r\n", "\n").replace("\r", "\n")
        normalised = normalised.replace(">\n<", "><")

    if CONFIG.get('remove_double_spaces', False):
        normalised = re.sub(r' {2,}', ' ', normalised)

    if CONFIG.get('remove_lead_and_trail_whitespace', False):
        normalised = normalised.strip()

    if CONFIG.get('remove_pointless_html_tags', False) or CONFIG.get('normalise_line_endings', False):
        normalised = normalise_html_tag_spacing(normalised)

    return normalised

def apply_configured_normalisation(value: Any) -> Any:
    """
    Apply configured normalisation recursively to strings, lists, and dictionaries.
    Non-string scalar values are returned unchanged.
    """
    if isinstance(value, str):
        return apply_configured_string_normalisation(value)
    if isinstance(value, list):
        return [apply_configured_normalisation(item) for item in value]
    if isinstance(value, tuple):
        return tuple(apply_configured_normalisation(item) for item in value)
    if isinstance(value, dict):
        return {
            key: apply_configured_normalisation(item)
            for key, item in value.items()
        }
    return value

def normalise_html_tag_spacing(input_string: str) -> str:
    """
    Normalise semantically irrelevant HTML syntax noise without removing content.

    This targets cases that otherwise create noisy field diffs, such as:
      - <p > versus <p>
      - <ul > versus <ul>
      - <pre spellcheck="false" > versus <pre spellcheck="false">
      - style="text-align: justify;" versus style="text-align: justify"
    """
    normalised = input_string

    # Remove whitespace immediately before the closing bracket of real HTML tags.
    normalised = re.sub(
        r'<(/?[A-Za-z][A-Za-z0-9:_-]*)([^<>]*?)\s+>',
        r'<\1\2>',
        normalised,
    )

    # Normalise single spaces or newlines between adjacent tags.
    normalised = re.sub(r'>[ \t]+<', '><', normalised)
    normalised = re.sub(r'>\n+<', '><', normalised)

    # A trailing semicolon in an inline style attribute is not semantically meaningful.
    normalised = re.sub(r'(style="[^"]*?);+"', r'\1"', normalised)
    normalised = re.sub(r"(style='[^']*?);+'", r"\1'", normalised)

    if normalised != input_string:
        log("DEBUG", "HTML tag spacing normalised", prefix="UTILS")

    return normalised

def remove_pointless_html_tags(input_string: str) -> str:
    """
       Remove pointless empty HTML wrappers such as:
         - <span></span>
         - <p></p>
         - <p>   </p>
         - <span>&nbsp;</span>
       anywhere in the string.

       A tag is removed if:
         - it has no child tags, and
         - all its text content is whitespace only (including non breaking spaces).

       Structural void elements (br, img, hr, etc.) are never removed.
       """
    soup = BeautifulSoup(input_string, "html.parser")

    # Process children first so parents see already cleaned content
    all_tags = soup.find_all(True)
    void_elements = {
        "br", "img", "hr", "input", "meta", "link", "source",
        "area", "embed", "col", "track", "wbr"
    }

    for tag in reversed(all_tags):
        # Never treat void elements as pointless
        if tag.name in void_elements:
            continue

        # If the tag has any child elements, it is not considered pointless
        # We only want to kill wrappers with no nested tags and no real text
        child_tags = [c for c in tag.children if not isinstance(c, NavigableString)]
        if child_tags:
            continue

        # Inspect text-only content
        has_meaningful_text = False
        for child in tag.children:
            if tag.attrs:
                has_meaningful_text = True
            if isinstance(child, NavigableString):
                text = str(child).replace("\xa0", " ")
                if text.strip():
                    has_meaningful_text = True
                    break

        if not has_meaningful_text:
            # No nested tags and no non whitespace text: pointless wrapper
            tag.decompose()

    # Normalise leading/trailing whitespace and harmless tag formatting differences.
    return normalise_html_tag_spacing(str(soup).strip())

def normalise_line_endings(input_string: str) -> str:
    normalised = input_string

    if "\r\n" in normalised:
        log("DEBUG", "Found Windows line endings that need to be normalised", prefix="UTILS")
        normalised = normalised.replace("\r\n", "\n")

    if "\r" in normalised:
        log("DEBUG", "Found MacOS line endings that need to be normalised", prefix="UTILS")
        normalised = normalised.replace("\r", "\n")

    if ">\n<" in normalised:
        log("DEBUG", "Found line endings between HTML tags that need to be removed", prefix="UTILS")
        normalised = normalised.replace(">\n<", "><")

    if "> <" in normalised:
        log("DEBUG", "Found single spaces between HTML tags that need to be removed", prefix="UTILS")
        normalised = normalised.replace("> <", "><")

    normalised = normalise_html_tag_spacing(normalised)

    if normalised == input_string:
        log("DEBUG", "No line endings identified that need to be normalised", prefix="UTILS")

    return normalised

def apply_configured_string_normalisation(input_string: str) -> str:
    """
    Apply every string-level normalisation enabled in config.

    This is called while raw JSON records are converted into Finding objects,
    before sensitivity checks, after sensitivity replacements, and immediately
    before fuzzy matching. Keep matching code using Finding fields, not raw JSON,
    so comparisons are always made against these configured normalised values.
    """
    normalised = input_string

    if CONFIG.get('normalise_line_endings', False):
        normalised = normalise_line_endings(normalised)

    if CONFIG.get('remove_double_spaces', False):
        normalised = remove_double_spaces_from_string(normalised)

    if CONFIG.get('remove_lead_and_trail_whitespace', False):
        stripped = normalised.strip()
        if stripped != normalised:
            log("DEBUG", "Leading or trailing whitespace stripped", prefix="UTILS")
        normalised = stripped

    if CONFIG.get('remove_pointless_html_tags', False):
        normalised = remove_pointless_html_tags(normalised)

    # Run tag-spacing cleanup last as replacements and BeautifulSoup serialisation
    # can both leave harmless formatting differences behind.
    if CONFIG.get('remove_pointless_html_tags', False) or CONFIG.get('normalise_line_endings', False):
        normalised = normalise_html_tag_spacing(normalised)

    return normalised

def check_for_sensitivities(field, terms) -> List[Tuple[str, Optional[str]]]:
    """Returns List of [(found_term, optional suggested_replacement)...] if sensitivities are found, else []."""
    results = []
    field = apply_configured_normalisation(field)
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

def apply_sensitive_replacement(field_value: Any, sensitive_term: str, replacement: str) -> Any:
    """Replace a sensitive term using literal, case-insensitive matching.

    When the sensitive term is an opening HTML tag, also remove or replace the
    corresponding closing tag so replacements such as "<mark> =>" do not leave
    dangling "</mark>" fragments behind.
    """
    if not isinstance(field_value, str):
        log(
            "WARN",
            f"Cannot safely replace sensitive term in non-string field value of type {type(field_value).__name__}",
            prefix="SENSITIVITY",
        )
        return field_value

    if replacement is None:
        replacement = ""

    replaced = _replace_sensitive_opening_tag_with_closing_pair(field_value, sensitive_term, replacement)
    return apply_configured_normalisation(replaced)

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
                    f'Skipping flag-only sensitive term "{sensitive_term}" during non-interactive sensitivity pass',
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
                    log('DEBUG', f'User chose Offered solution: "{offered}"', prefix="SENSITIVITY")
                    result = apply_sensitive_replacement(record.get(field_name), sensitive_term, offered)
                    record.set(field_name, result)
                elif action == "e" or action == key.UP:
                    edited_term = tui.invoke_editor(record.get(field_name))
                    log('DEBUG', f'User chose to edit and set: "{edited_term}"', prefix="SENSITIVITY")
                    result = apply_sensitive_replacement(record.get(field_name), sensitive_term, edited_term)
                    record.set(field_name, result)
                elif action == "k" or action == key.DOWN:
                    log("WARN", "User chose to Keep field as is", prefix="SENSITIVITY")
                    continue
            else:
                # We are auto-accepting the auto-offered values if we are configured not to use interactive mode and
                # the offered variable is populated.  This is perfectly valid, but will result in "best
                # guess" scenarios that will likely not be as desired.
                log('DEBUG', f'Auto-accepted Offered solution: "{offered}"', prefix="SENSITIVITY")
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
                        f'Sensitivity check of "{field.name}" resulted in: "{str(result_sensitivities.get(field.name))[:30]}"',
                        prefix="SENSITIVITY",
                    )

    return record
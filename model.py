# external module imports
from imports import (ast, dataclass, field, Any, Dict, List, Optional, Union, get_origin, get_args)
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()
# local module imports
from utils import log, is_blank

"""
This class is here to enable sensible handling of unexpected types.
"""

@dataclass
class Finding:
    """
    Represents a single GhostWriter finding with all defined fields and helpers.
    """
    id: int
    severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    finding_type: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    mitigation: Optional[str] = None
    replication_steps: Optional[str] = None
    host_detection_techniques: Optional[str] = None
    network_detection_techniques: Optional[str] = None
    references: Optional[str] = None
    finding_guidance: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    extra_fields: Optional[Dict[str, Any]] = field(default_factory=dict)


    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding' or None:
        """
        Convert a raw dict (e.g., from JSON) into a Finding instance, validating and coercing fields
        with interactive user prompting when mismatches occur.
        """
        try:
            log("DEBUG", f"Parsing finding from data: {data}", prefix="MODEL")
            coerced_data = {}

            for field_name, field_def in cls.__dataclass_fields__.items():
                expected_type = field_def.type
                raw_value = data.get(field_name, None)

                try:
                    coerced = coerce_value(raw_value, expected_type, field_name)
                    if isinstance(coerced, str):
                        coerced = coerced.strip()
                    coerced_data[field_name] = coerced
                except Exception:
                    expected_str = get_clean_type_string(expected_type)
                    log("DEBUG",
                        f"Field '{field_name}' expected {expected_str} but got type {type(raw_value).__name__}: \"{raw_value}\"",
                        prefix="MODEL")
                    correction = prompt_user_to_fix_field(field_name, expected_type, raw_value)
                    if correction[0] == 0:
                        coerced_data[field_name] = correction[1]
                    elif correction[0] == 1:
                        return None
                    else:
                        exit()

            # Validate severity
            allowed_severities = CONFIG.get("allowed_severities")
            severity = coerced_data.get("severity", "Unknown")
            if severity not in allowed_severities:
                log("ERROR", f"Invalid severity '{severity}'. Allowed: {allowed_severities}", prefix="MODEL")
                raise ValueError(f"Invalid severity level '{severity}'.")

            finding = cls(**coerced_data)
            log("DEBUG", f"Created Finding object: {finding}", prefix="MODEL")
            return finding

        except Exception as e:
            log("ERROR", f"Failed to parse finding from dict", prefix="MODEL", exception=e)
            raise


    def to_dict(self) -> dict:
        """
        Serialises this Finding instance back into a dictionary suitable for JSON output.
        """
        log("DEBUG", f"Serialising finding ID {self.id} to dict", prefix="MODEL")
        return {
            "id": self.id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "finding_type": self.finding_type,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "mitigation": self.mitigation,
            "replication_steps": self.replication_steps,
            "host_detection_techniques": self.host_detection_techniques,
            "network_detection_techniques": self.network_detection_techniques,
            "references": self.references,
            "finding_guidance": self.finding_guidance,
            "tags": self.tags,
            "extra_fields": self.extra_fields,
        }

def prompt_user_to_fix_field(field_name: str, expected_type: Any, current_value: Any) -> tuple[int, Any]:
    """Prompt user to correct an invalid field inline"""
    tui = get_tui()

    is_optional = False
    valid_choices = ["f", "s", "a"]
    origin = get_origin(expected_type)
    args = get_args(expected_type)

    prompt = (f"[red]Invalid value[/red] [yellow]'{current_value}' ({get_clean_type_string(type(current_value))})[/yellow] in "
              f"[bold]{field_name}[/bold] and we need a [bold]{get_clean_type_string(expected_type)}[/bold] to fix it.\n")

    options = ['Fix', 'Skip whole record', 'Abort']
    # Detect Optional[T] (Union[..., NoneType])
    if origin is Union and type(None) in args:
        is_optional = True
        options.append("Remove value")

    action = tui.render_user_choice(prompt, options, default=None,
                                            title=f'Field-level resolution: {field_name}')

    if action == "r" and is_optional:
        log("DEBUG", f"User chose to remove value for {field_name}", prefix="MODEL")
        return [0, None]
    elif action == "f":
        new_value = tui.render_user_choice(f"Enter corrected value for [bold]{field_name}[/bold]", multi_char=True)
        # this should result in it being recursive until a valid value is provided or skipped, or aborted
        try:
            casted = coerce_value(new_value, expected_type, field_name)
            return [0, casted]
        except (ValueError, TypeError):
            return prompt_user_to_fix_field(field_name, expected_type, new_value)

    elif action == "s":
        log("WARN", f"User skipped this whole finding", prefix="MODEL")
        return [1, None]

    else:  # action == "a"
        log("ERROR", "User aborted the merge.", prefix="MODEL")
        exit()


def coerce_value(value: Any, expected_type: Any, field_name: Optional[str] = None) -> Any:
    log("DEBUG", f"Attempting to coerce field '{field_name}' with value: {repr(value)} to type: {expected_type}",
        prefix="MODEL")

    if (isinstance(value, str) and value.strip() == "") or value is None:
        return None

    origin = get_origin(expected_type)
    args = get_args(expected_type)

    # Special: tags
    if field_name == "tags":
        log("DEBUG", f"Special handling for 'tags' field with value: {repr(value)}", prefix="MODEL")
        if is_blank(value):
            log("WARN", f"Blank tags found, coercing to empty List", prefix="MODEL")
            return []
        if isinstance(value, str):
            result = [x.strip().lower() for x in value.replace(",", " ").split()]
            log("DEBUG", f"Parsed tags from string: {result}", prefix="MODEL")
            return result
        if isinstance(value, list):
            result = [str(x).strip().lower() for x in value]
            log("DEBUG", f"Parsed tags from list: {result}", prefix="MODEL")
            return result
        raise TypeError("Invalid tags format")

    # Special: extra_fields
    if field_name == "extra_fields":
        log("DEBUG", f"Special handling for 'extra_fields' with value: {repr(value)}", prefix="MODEL")
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = ast.literal_eval(value)
                if isinstance(parsed, dict):
                    log("DEBUG", f"Parsed extra_fields from string: {parsed}", prefix="MODEL")
                    return parsed
            except Exception as e:
                log("WARN", f"Failed to parse extra_fields from string: {value}", prefix="MODEL", exception=e)
        raise TypeError("Invalid extra_fields format")

    # Handle Optional[T]
    if origin is Union and type(None) in args:
        non_none_type = [t for t in args if t is not type(None)][0]
        log("DEBUG", f"Detected Optional[...] — coercing using non-None type: {non_none_type}", prefix="MODEL")
        return coerce_value(value, non_none_type, field_name)

    # Base types
    if expected_type in [int, float, str, bool]:
        log("DEBUG", f"Coercing scalar to {expected_type.__name__}", prefix="MODEL")
        result = expected_type(value)
        log("DEBUG", f"Successfully coerced to: {result}", prefix="MODEL")
        return result

    # List[T]
    if origin is list:
        inner_type = args[0] if args else str
        log("DEBUG", f"Handling list of {inner_type}", prefix="MODEL")
        if isinstance(value, str):
            try:
                value = ast.literal_eval(value)
                log("DEBUG", f"Parsed list from string: {value}", prefix="MODEL")
            except Exception as e:
                log("WARN", f"Failed to parse list from string: {value}", prefix="MODEL", exception=e)
                raise ValueError(f"Could not parse list from string: {value}")
        if not isinstance(value, list):
            raise TypeError(f"Expected list, got {type(value)}")
        coerced_list = [coerce_value(v, inner_type, field_name) for v in value]
        log("DEBUG", f"Coerced list values: {coerced_list}", prefix="MODEL")
        return coerced_list

    # Dict[K, V]
    if origin is dict:
        key_type, val_type = args if args else (str, str)
        log("DEBUG", f"Handling dict of {key_type}:{val_type}", prefix="MODEL")
        if isinstance(value, str):
            try:
                value = ast.literal_eval(value)
                log("DEBUG", f"Parsed dict from string: {value}", prefix="MODEL")
            except Exception as e:
                log("WARN", f"Failed to parse dict from string: {value}", prefix="MODEL", exception=e)
                raise ValueError(f"Could not parse dict from string: {value}")
        if not isinstance(value, dict):
            raise TypeError(f"Expected dict, got {type(value)}")
        coerced_dict = {
            coerce_value(k, key_type, field_name): coerce_value(v, val_type, field_name)
            for k, v in value.items()
        }
        log("DEBUG", f"Coerced dict values: {coerced_dict}", prefix="MODEL")
        return coerced_dict

    # Already correct
    if isinstance(value, expected_type):
        log("DEBUG", f"Value already of correct type: {type(value)}", prefix="MODEL")
        return value

    # Fallback
    try:
        result = expected_type(value)
        log("DEBUG", f"Fallback coercion to {expected_type} succeeded: {result}", prefix="MODEL")
        return result
    except Exception as e:
        log("WARN", f"Fallback coercion failed for value: {value}", prefix="MODEL", exception=e)
        raise

def get_clean_type_string(t: Any) -> str:
    origin = get_origin(t)
    args = get_args(t)

    if origin is Union:
        # Optional[...] is Union[X, NoneType]
        readable = [get_clean_type_string(a) for a in args]
        return " or ".join(readable)
    elif origin is list:
        inner = get_clean_type_string(args[0]) if args else "Any"
        return f"List[{inner}]"
    elif origin is dict:
        key_str = get_clean_type_string(args[0]) if args else "Any"
        val_str = get_clean_type_string(args[1]) if args else "Any"
        return f"Dict[{key_str}, {val_str}]"
    elif hasattr(t, "__name__"):
        return t.__name__
    elif isinstance(t, type):
        return t.__name__
    else:
        return str(t)
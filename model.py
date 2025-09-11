# external module imports
from imports import (ast, dataclass, field, Any, Dict, List, Optional, Union, get_origin, get_args, re, json)
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
    severity: Optional[str] = None
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
    extra_fields: Dict[str, Any] = field(default_factory=dict)


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
                    expected_str = get_expected_type(expected_type)
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

    if 'Optional' in get_expected_type(expected_type):
        is_optional = True
        log('DEBUG', 'Optional field detected', prefix="MODEL")
    else:
        is_optional = False
        log('DEBUG', 'Mandatory field detected', prefix="MODEL")

    origin = get_origin(expected_type)
    args = get_args(expected_type)

    prompt = (f"[red]Invalid value[/red] [yellow]'{current_value}' ({get_expected_type(type(current_value))})[/yellow] in "
              f"[bold]{field_name}[/bold] and we need a [bold]{get_expected_type(expected_type)}[/bold] to fix it.\n")

    options = ['Fix', 'Skip whole record']
    # Detect Optional[T] (Union[..., NoneType])
    if is_optional:
        options.append(f'Empty') ######

    action = tui.render_user_choice(prompt, options, default=None,
                                            title=f'Field-level resolution: {field_name}')

    if action == "e" and is_optional:
        log("DEBUG", f"User chose to use empty value for {field_name}", prefix="MODEL")
        if expected_type == str:
            return [0, None]
        if expected_type == list:
            return [0, []]
        if expected_type == dict:
            return [0, {}]
    elif action == "f":
        new_value = tui.render_user_choice(f"Enter corrected value for [bold]{field_name}[/bold]", multi_char=True)
        # this should result in it being recursive until a valid value is provided or skipped
        try:
            casted = coerce_value(new_value, expected_type, field_name)
            return [0, casted]
        except (ValueError, TypeError):
            return prompt_user_to_fix_field(field_name, expected_type, new_value)
    elif action == "s":
        log("WARN", f"User skipped this whole finding", prefix="MODEL")
        return [1, None]
    elif action == "e":
        if expected_type == list:
            return []
        if expected_type == dict:
            return {}

    return None

def coerce_value(value: Any, expected_type: Any, field_name: Optional[str] = None) -> Any:
    """
    Safely coerce arbitrary values to runtime types described by typing annotations.

    Supported:
      - Optional[T] and general Union[..., ...]
      - list[T]
      - dict[K, V]
      - int, float, str, bool
      - passthrough for values already matching the runtime type

    Notes:
      - Handles blank values early for Optional and containers
      - Avoids isinstance on typing.Union
      - Never calls typing aliases as constructors
    """
    #def _typename(tp: Any) -> str:
    #    try:
    #        return tp.__name__
    #    except AttributeError:
    #        return get_expected_type(tp)

    origin = get_origin(expected_type)
    args = get_args(expected_type)
    # Collapse typing origin to a runtime class when available
    runtime_type = origin or expected_type


    log("DEBUG", f"Attempting to coerce field '{field_name}' with value: {repr(value)} to type: {get_expected_type(expected_type)}",
        prefix="MODEL")

    # Handle Union and Optional first
    if origin is Union:
        non_none = [t for t in args if t is not type(None)]
        if type(None) in args and len(non_none) == 1:
            # Optional[T]
            if is_blank(value):
                log("DEBUG", f"Optional value is blank, returning None", prefix="MODEL")
                return None
            log("DEBUG", f"Optional detected, coercing to non None member {get_expected_type(non_none[0])}", prefix="MODEL")
            return coerce_value(value, non_none[0], field_name)

        # General Union: try each member in order
        last_err = None
        for member in args:
            try:
                return coerce_value(value, member, field_name)
            except Exception as e:
                last_err = e
                continue
        log("WARN", f"Value did not match any Union member types {tuple(get_expected_type(a) for a in args)}", prefix="MODEL", exception=last_err)
        raise last_err if last_err else TypeError(f"Value {value!r} does not match {runtime_type}")

    # Already correct type
    try:
        if isinstance(value, runtime_type):
            log("DEBUG", f"Value already of correct type: {type(value)}", prefix="MODEL")
            return value
    except TypeError:
        # runtime_type may not be a proper class, ignore
        pass

    # Blank handling for non containers
    if is_blank(value):
        log("DEBUG", f"Blank value found", prefix="MODEL")
        if runtime_type is list:
            return []
        if runtime_type is dict:
            return {}
        if runtime_type in (float,int):
            return None
        if runtime_type is str:


    # Booleans
    if runtime_type is bool:
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            s = value.strip().lower()
            if s in {"true", "1", "yes", "y", "on"}:
                return True
            if s in {"false", "0", "no", "n", "off"}:
                return False
        raise ValueError(f"Cannot coerce to bool: {value!r}")

    # List[T]
    if runtime_type is list:
        inner = args[0] if args else Any
        # if it is blank,
        if is_blank(value):
            log("DEBUG", "Blank List found, coercing to empty list", prefix="MODEL")
            return []
        # if it is currently a str
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return []
            parsed = None
            # If this looks like a structured literal, try proper parsing first
            if s[:1] in "[(" or s[:1] == "{" or s[:1] == '"':
                # tolerate both JSON and Pythonic quoting
                try:
                    parsed = json.loads(s)
                except Exception as e:
                    parsed = ast.literal_eval(s)
                    log("WARN", f"Failed to parse list-ish string structurally: {s!r}", prefix="MODEL", exception=e)
            if parsed is None:
                # Heuristic: split delimited strings, otherwise treat as single tag
                # commas, semicolons, or pipes as delimiters
                parts = [p.strip() for p in re.split(r"[;,|]", s) if p.strip()]
                parsed = parts if parts else [s]
            # Normalise tuple to list in case "(a, b)"
            if isinstance(parsed, tuple):
                parsed = list(parsed)
            value = parsed
        # if it still isn't a list
        if not isinstance(value, list):
            log("DEBUG", f"Expected list, got {type(value)} with value {value!r}", prefix="MODEL")
            raise TypeError(f"Expected List, got {type(value)}")

        coerced_list = [coerce_value(v, inner, field_name) for v in value]
        log("DEBUG", f"Coerced list values: {coerced_list!r}", prefix="MODEL")
        return coerced_list

    # dict[K, V]
    if runtime_type is dict:
        key_t, val_t = args if len(args) == 2 else (Any, Any)
        if is_blank(value):
            log("INFO", f"Blank Dict found, coercing to empty dict", prefix="MODEL")
            return {}
        if isinstance(value, str):
            try:
                parsed = ast.literal_eval(value)
                value = parsed
                log("DEBUG", f"Parsed dict from string: {value!r}", prefix="MODEL")
            except Exception as e:
                log("WARN", f"Failed to parse dict from string: {value!r}", prefix="MODEL", exception=e)
                return None
        if not isinstance(value, dict):
            log("DEBUG", f"Expected dict, got {type(value)}", prefix="MODEL")
            raise TypeError(f"Expected Dict, got {type(value)}")
        coerced = {}
        for k, v in value.items():
            ck = coerce_value(k, key_t, field_name)
            # Enforce basic hashability for keys
            if not isinstance(ck, (str, int, float, bool, tuple, type(None))):
                raise TypeError(f"Coerced key is unhashable: {ck!r}")
            coerced[ck] = coerce_value(v, val_t, field_name)
        log("DEBUG", f"Coerced dict values: {coerced!r}", prefix="MODEL")
        return coerced

    # Scalars
    if runtime_type in (int, float):
        try:
            result = runtime_type(value)
            log("DEBUG", f"Coerced scalar to {runtime_type.__name__}: {result!r}", prefix="MODEL")
            return result
        except Exception as e:
            log("WARN", f"Failed scalar coercion to {runtime_type.__name__} for value {value!r}", prefix="MODEL", exception=e)
            raise ValueError(f"Failed scalar coercion to {runtime_type.__name__} for value {value!r}")

    # Unsupported typing artefact
    raise TypeError(f"Unsupported expected_type for coercion: {expected_type!r}")

def get_expected_type(t: Any) -> str:
    """
    Return a human-readable name for a typing annotation or runtime type.

    Behavior
    - Union/Optional: returns "A or B" (e.g., Optional[int] -> "int or NoneType").
    - List[T]: returns "List[T]" with T formatted recursively.
    - Dict[K, V]: returns "Dict[K, V]" with K and V formatted recursively.
    - Named/built-in types: uses the type's __name__ (e.g., str -> "str").
    - Fallback: returns str(t) if no clearer representation is available.

    Notes
    - Uses typing.get_origin/get_args and recurses for nested composite types.
    - Handles both typing annotations and concrete classes/instances gracefully.
    """

    origin = get_origin(t)
    args = get_args(t)

    if origin is Union:
        # Optional[...] is Union[X, NoneType]
        readable = [get_expected_type(a) for a in args]
        return " or ".join(readable)
    elif origin is list:
        inner = get_expected_type(args[0]) if args else "Any"
        return f"List[{inner}]"
    elif origin is dict:
        key_str = get_expected_type(args[0]) if args else "Any"
        val_str = get_expected_type(args[1]) if args else "Any"
        return f"Dict[{key_str}, {val_str}]"
    elif hasattr(t, "__name__"):
        return t.__name__
    elif isinstance(t, type):
        return t.__name__
    else:
        return str(t)
# external module imports
from types import NoneType

from imports import dataclass, field, fields, Any, Dict, List, Optional, Union, re, json, get_origin, get_args, get_type_hints
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()
# local module imports
from utils import log, is_blank, is_optional_field, blank_for_type, get_type_as_str

"""
This class is here to enable sensible handling of unexpected types.
"""

@dataclass
class Finding:
    """
    Represents a single GhostWriter finding with all defined fields and helpers.
    """
    id: Optional[int] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    finding_type: Optional[str] = None
    title: str = None
    description: Optional[str] = None
    impact: Optional[str] = None
    mitigation: Optional[str] = None
    replication_steps: Optional[str] = None
    host_detection_techniques: Optional[str] = None
    network_detection_techniques: Optional[str] = None
    references: Optional[str] = None
    finding_guidance: Optional[str] = None
    tags: Optional[List[str]] = field(default_factory=list)
    extra_fields: Optional[Dict[str, Any]] = field(default_factory=dict)


    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding' or None:
        """
        Convert a raw dict (e.g., from JSON) into a Finding instance, validating and coercing fields
        with interactive user prompting when mismatches occur.
        """
        tui = get_tui()
        try:
            log("DEBUG", f"Parsing finding from data: {data}", prefix="MODEL")
            coerced_data = {}

            # Resolve annotations once so we do not see unevaluated strings or typing artefacts
            hints = get_type_hints(cls)

            for field_def in fields(Finding):
                field_name = field_def.name
                # Use the resolved hint, not field.type
                field_type = hints.get(field_name, Any)
                expected_type_str = get_type_as_str(field_type)
                raw_value = data.get(field_name, None)

                log('DEBUG', f'Checking "{field_name}" if data type is as expected. Currently {type(raw_value)}',
                    prefix='MODEL')

                # Decide if the raw value already matches at a shallow level
                matches = False
                origin = get_origin(field_type)
                args = get_args(field_type)

                if field_type in (Any, object):
                    matches = True
                elif origin is None:
                    # Plain class, safe for isinstance
                    try:
                        matches = isinstance(raw_value, field_type)
                    except TypeError:
                        # Some hints can still be non-runtime-checkable, allow through
                        matches = True
                elif origin is Union:
                    # Build a tuple of runtime bases from the union arms
                    bases = tuple((get_origin(a) or a) for a in args)
                    bases = tuple(b for b in bases if isinstance(b, type))
                    matches = isinstance(raw_value, bases) if bases else True
                else:
                    # Generic containers like list[T], dict[K, V], tuple[...], set[T], etc.
                    try:
                        matches = isinstance(raw_value, origin)
                    except TypeError:
                        matches = True

                if matches:
                    log('DEBUG', 'Field is correct type', prefix='MODEL')
                    coerced_data[field_name] = raw_value
                else:
                    try:
                        log('DEBUG', f'Attempting to coerce {field_name} to {expected_type_str}', prefix='MODEL')
                        coerced = coerce_value(raw_value, field_type, field_name)
                        if isinstance(coerced, str):
                            coerced = coerced.strip()
                        coerced_data[field_name] = coerced
                    except TypeError as e:
                        log('ERROR', f"Encountered unexpected required type, aborting", prefix="MODEL")
                        exit()
                    except ValueError as e:
                        log('WARN', f'Failed to coerce {field_name} to {expected_type_str}', prefix='MODEL')
                        log("DEBUG",
                            f"Field '{field_name}' expected {expected_type_str} but got type {get_type_as_str(type(raw_value))}: \"{raw_value}\" error is:\n{e}",
                            prefix="MODEL")
                        tui.render_single_partial_dict_record(data)
                        correction_status, correction_data = prompt_user_to_fix_field(field_name, field_type, raw_value)
                        if correction_status == 0:
                            log('DEBUG', f"User prompt to resolve successful", prefix="MODEL")
                            coerced_data[field_name] = correction_data
                        elif correction_status == 1:
                            log('INFO', f"User prompt to resolve not successful", prefix="MODEL")
                            return None
                        else:
                            log('ERROR', f"User prompt to resolve field type mismatch not successful for "
                                         f"unknown reason - aborting", prefix="MODEL")
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
            exit()


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

    def __getitem__(self, key: str) -> Any:
        value = self.get(key, default=None)
        if value is None and not hasattr(self, key) and key not in (self.extra_fields or {}):
            raise KeyError(key)
        return value

    def __setitem__(self, key: str, value: Any) -> None:
        ok = self.set(key, value)
        if not ok:
            # push unknowns into extra_fields
            if self.extra_fields is None:
                self.extra_fields = {}
            self.extra_fields[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """
        Mimics dict.get() for dataclass attributes.
        Returns the attribute if it exists, otherwise the default.
        """
        if isinstance(key, NoneType):
            log("WARN", f"Attempted and failed to get attribute with key: {key} that has a NoneType", prefix="MODEL")
            return False
        else:
            if hasattr(self, key):
                return getattr(self, key)
            return self.extra_fields.get(key, default) if self.extra_fields else default

    def set(self, key: str, value: Any = None) -> Any:
        """
        Mimics dict.set() for dataclass attributes.
        Returns True if successful, otherwise False.
        """
        if not key or key == '':
            log("WARN", f'Attempted and failed to set attribute with blank or non-str key: "{str(key)}"', prefix='MODEL')
        elif not hasattr(self, key):
            log("WARN", f'Attempted and failed to set non-existant key: "{str(key)}"', prefix='MODEL')
        else:
            setattr(self, key, value)
            return True
        # if not definitively successful, return False
        return False

def prompt_user_to_fix_field(field_name: str, expected_type: type, current_value: Any) -> tuple[int, Any]:
    """Prompt user to correct an invalid field inline"""
    tui = get_tui()
    expected_type_str = get_type_as_str(expected_type)

    prompt = (f"Invalid value '{current_value}' ({get_type_as_str(type(current_value))}) in "
              f"{field_name} and we need a {get_type_as_str(expected_type)} to fix it.\n")
    log('DEBUG', f"Prompt is:\n{prompt}", prefix="MODEL")

    options = ['Fix', 'Skip whole record']
    log("DEBUG", f"Options are: {options}")
    # Detect Optional[T] (Union[..., NoneType])
    is_optional = is_optional_field(expected_type)
    action = tui.render_user_choice(prompt, options, default=None,
                                            title=f'Field-level resolution: {field_name}', is_optional=is_optional)

    if action == "b" and is_optional:
        log("DEBUG", f"User chose to use blank value for optional field '{field_name}'", prefix="MODEL")
        blank_return_type = blank_for_type(expected_type_str)
        return 0, blank_return_type
    elif action == "f":
        new_value = tui.render_user_choice(f"Enter corrected value for [bold]{field_name}[/bold]", multi_char=True)
        # this should result in it being recursive until a valid value is provided or skipped
        try:
            casted = coerce_value(new_value, expected_type, field_name)
            return 0, casted
        except (ValueError, TypeError):
            return prompt_user_to_fix_field(field_name, expected_type, new_value)
    elif action == "s":
        log("WARN", f"User skipped this whole finding", prefix="MODEL")
        return 1, None

    # We shouldn't ever get to this, so the return statement below is belt and braces
    return 1, None

def coerce_value(value: Any, expected_type: type, field_name: Optional[str] = None) -> Any:
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

    origin_type = get_origin(expected_type)
    type_args = get_args(expected_type)
    expected_type_as_str = get_type_as_str(expected_type)
    # Collapse typing origin to a runtime class when available
    origin_or_expected_type = origin_type or expected_type

    # Already correct type
    try:
        if isinstance(value, expected_type):
            log("DEBUG", f"Value already of correct type: {type(value)}", prefix="MODEL")
            return value
    except TypeError:
        # runtime_type may not be a proper class, ignore
        pass

    # Blank handling for non containers
    if is_blank(value):
        log("DEBUG", f"Blank value found", prefix="MODEL")
        return blank_for_type(expected_type_as_str)

    # Handle Union
    if origin_or_expected_type is Union:
        log(
            "DEBUG",
            f"Union type expected | field={field_name} | value_preview={repr(value)[:200]} | "
            f"expected_type={getattr(expected_type, '__name__', str(expected_type))}",
            prefix="MODEL",
        )
        non_none = [t for t in type_args if t is not type(None)]
        log(
            "DEBUG",
            "Computed non-None Union members | "
            f"union_members={tuple(get_type_as_str(a) for a in type_args)} | "
            f"non_none_members={tuple(get_type_as_str(a) for a in non_none)} | "
            f"member_count={len(type_args)}",
            prefix="MODEL",
        )

        # General Union: try each member in order
        last_err = None
        for type_member in type_args:
            if type_member in non_none:
                try:
                    log(
                        "DEBUG",
                        f"Attempting coercion against current Union member | "
                        f"member_type={get_type_as_str(type_member)} | field={field_name}",
                        prefix="MODEL",
                    )
                    union_coerced_value = coerce_value(value, type_member, field_name)
                    log(
                        "DEBUG",
                        f"Coercion succeeded for current Union member | "
                        f"result_type={type(union_coerced_value).__name__}",
                        prefix="MODEL",
                    )
                    return union_coerced_value
                except Exception as e:
                    log(
                        "DEBUG",
                        f"Value did not match current Union member type | "
                        f"member_type={get_type_as_str(type_member)} | "
                        f"exception_type={type(e).__name__} | exception_msg={str(e)}",
                        prefix="MODEL",
                        exception=e,
                    )
                    last_err = e
                    continue
        log(
            "DEBUG",
            "Value did not match any Union member types | "
            f"field={field_name} | value_preview={repr(value)[:50]} | "
            f"union_members={tuple(get_type_as_str(a) for a in type_args)} | "
            f"attempted_members={tuple(get_type_as_str(a) for a in non_none)} | "
            f"attempt_count={len(non_none)} | had_exception={last_err is not None}",
            prefix="MODEL",
            exception=last_err,
        )
        raise last_err if last_err else ValueError(f"Value {value!r} does not match {expected_type}")

    # Booleans
    if origin_or_expected_type is bool:
        log("DEBUG", "Boolean type expected", prefix="MODEL")
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
    if origin_or_expected_type is list:
        log("DEBUG", "List type expected", prefix="MODEL")
        inner = type_args[0] if type_args else Any
        # if it is blank,
        if is_blank(value):
            log("DEBUG", "Blank List found, coercing to empty list", prefix="MODEL")
            return []
        # if it is currently a str
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return []
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
    if origin_or_expected_type is dict:
        log(
            "DEBUG",
            f"Dict type expected | field={field_name} | value_preview={repr(value)[:50]} | "
            f"type_args={tuple(get_type_as_str(a) for a in type_args) if type_args else '()'}",
            prefix="MODEL",
        )
        key_t, val_t = type_args if len(type_args) == 2 else (Any, Any)
        log(
            "DEBUG",
            f"Resolved dict generics | key_t={get_type_as_str(key_t)} | val_t={get_type_as_str(val_t)}",
            prefix="MODEL",
        )

        if is_blank(value):
            log("INFO", f"Blank Dict found, coercing to empty dict | field={field_name}", prefix="MODEL")
            return {}

        if isinstance(value, str):
            try:
                parsed = json.loads(value) if isinstance(value, str) else value

                if isinstance(parsed, dict):
                    dict_data = parsed
                    log('DEBUG', f'Parsed JSON data is already a Dict', prefix="MODEL")
                elif isinstance(parsed, list):
                    # normalise from a List to a single Dict
                    if len(parsed) != 1 or not isinstance(parsed[0], dict):
                        log('ERROR', f'Expected a single Dict inside the List', prefix="MODEL")
                    dict_data = parsed[0]
                    log('DEBUG', f'Removed outer List structure from inner Dict', prefix="MODEL")
                else:
                    raise TypeError(f"Expected the JSON parsed data to be a Dict or List of Dicts, got {type(parsed)}")

                for key, value in dict_data.items():
                    log('DEBUG', f'Key found: "{key}" with value: "{value}"', prefix="MODEL")

                return dict_data

            except ValueError as e:
                log(
                    "ERROR",
                    f"Failed to parse dict from string | field={field_name} | value_preview={repr(value)[:50]} | "
                    f"exception_type={type(e).__name__} | exception_msg={str(e)}",
                    prefix="MODEL",
                    exception=e,
                )
                return None

        if not isinstance(value, dict):
            log("WARN", f"Expected dict, got {type(value)} | field={field_name}", prefix="MODEL")
            raise TypeError(f"Expected Dict, got {type(value)}")


        coerced = {}
        for key, v in value.items():
            log(
                "DEBUG",
                f"Coercing dict entry | raw_key_preview={repr(key)[:50]} | raw_val_preview={repr(v)[:50]}",
                prefix="MODEL",
            )
            coerced_key = str(key)
            # Enforce basic hashability for keys
            if not isinstance(coerced_key, (str, int, float, bool, tuple, type(None))):
                log(
                    "WARN",
                    f"Coerced key is unhashable | coerced_key_preview={repr(coerced_key)[:50]} | type={type(coerced_key)}",
                    prefix="MODEL",
                )
                raise TypeError(f"Coerced key is unhashable: {coerced_key!r}")
            coerced_value = coerce_value(v, val_t, field_name)
            coerced[coerced_key] = coerced_value
            log(
                "DEBUG",
                f"Coerced dict entry | key_type={type(coerced_key).__name__} | val_type={type(coerced_value).__name__}",
                prefix="MODEL",
            )
        log("DEBUG", f"Coerced dict values: {coerced!r}", prefix="MODEL")
        return coerced

    # Scalars
    if (origin_or_expected_type is int) or (origin_or_expected_type is float):
        log("DEBUG", "Int or Float type expected", prefix="MODEL")
        try:
            result = expected_type(value)
            log("DEBUG", f"Coerced scalar to {get_type_as_str(expected_type)}: {result!r}", prefix="MODEL")
            return result
        except ValueError:
            log("WARN", f"Failed scalar coercion to {get_type_as_str(expected_type)} for value {value!r}", prefix="MODEL")
            raise ValueError(f"Failed scalar coercion to {get_type_as_str(expected_type)} for value {value!r}")

    # Unsupported typing artefact
    raise TypeError(f"Unsupported expected_type for coercion: {expected_type!r}")

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from rich.prompt import Prompt
from rich.console import Console
from utils import log, load_config, CONFIG

"""
This class is here to enable sensible handling of unexpected types.
"""
class InvalidFieldValue(Exception):
    def __init__(self, field, value, message, finding_id):
        super().__init__(f"[Finding ID {finding_id}] Invalid '{field}': '{value}' – {message}")
        self.field = field
        self.value = value
        self.message = message
        self.finding_id = finding_id

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
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """
        Convert a raw dict (e.g., from JSON) into a Finding instance, validating and normalising fields.
        """
        try:
            log("DEBUG", f"Parsing finding from data: {data}", prefix="MODEL")

            # Normalise tags to list[str]
            tags = data.get("tags", [])
            if isinstance(tags, str):  # handle comma or space-separated string input
                tags = [tag.strip().lower() for tag in tags.replace(',', ' ').split()]
            elif not isinstance(tags, list):  # if not a list or str, fallback to empty list
                tags = []
            log("DEBUG", f"Normalised tags: {tags}", prefix="MODEL")

            # Ensure cvss_score is float or None and raise exception accordingly
            raw_score = data.get("cvss_score")
            score = None
            if raw_score not in (None, "", "None"):
                try:
                    score = float(raw_score)
                except (ValueError, TypeError):
                    raise InvalidFieldValue("cvss_score", raw_score, "Expected a numeric CVSS score (e.g. 7.5)", data.get("id"))
            log("DEBUG", f"Normalised CVSS score: {score}", prefix="MODEL")

            # Type checks
            assert isinstance(data.get("title"), str), "Title must be a string"

            if CONFIG.get("auto_coerce_fields", False):
                # Coerce and strip values that can be strings or None
                for field in ["cvss_vector", "finding_type", "description", "impact", "mitigation", "replication_steps", "host_detection_techniques", "network_detection_techniques", "references", "finding_guidance"]:
                    val = data.get(field)
                    if val is not None:
                        if not isinstance(val, str):
                            try:
                                log("WARN", f"Field '{field}' expected str. Coercing from {type(val).__name__}", prefix="MODEL")
                                val = str(val)
                            except Exception:
                                log("ERROR", f"Field '{field}' must be str or None. Found: {type(val).__name__}", prefix="MODEL")
                                raise TypeError(f"Field '{field}' must be str or None")
                        val = val.strip()  # Always strip leading/trailing whitespace
                        data[field] = val  # Replace cleaned value back into data
            for field in ["cvss_vector", "finding_type", "description", "impact", "mitigation", "replication_steps", "host_detection_techniques", "network_detection_techniques", "references", "finding_guidance"]:
                val = data.get(field)
                if val is not None and not isinstance(val, str):
                    log("ERROR", f"Field '{field}' must be str or None. Found: {type(val).__name__}", prefix="MODEL")
                    raise TypeError(f"Field '{field}' must be str or None")

            # Validate severity against config enum
            allowed_severities = CONFIG.get("allowed_severities", ["Low", "Medium", "High", "Critical"])
            severity = data.get("severity", "Unknown")
            if severity not in allowed_severities:
                log("ERROR", f"Invalid severity '{severity}' detected. Must be one of {allowed_severities}", prefix="MODEL")
                raise ValueError(f"Invalid severity level '{severity}'. Allowed: {allowed_severities}")

            finding = cls(
                id=int(data["id"]),  # convert ID to int regardless of input type
                severity=severity,
                cvss_score=score,
                cvss_vector=data.get("cvss_vector"),
                finding_type=data.get("finding_type"),
                title=data.get("title"),
                description=data.get("description"),
                impact=data.get("impact"),
                mitigation=data.get("mitigation"),
                replication_steps=data.get("replication_steps"),
                host_detection_techniques=data.get("host_detection_techniques"),
                network_detection_techniques=data.get("network_detection_techniques"),
                references=data.get("references"),
                finding_guidance=data.get("finding_guidance"),
                tags=tags,
                extra_fields=data.get("extra_fields", {})
            )
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

    def diff(self, other: 'Finding') -> Dict[str, tuple[Any, Any]]:
        """
        Returns a dictionary of field names whose values differ between this and another Finding.
        Each key maps to a tuple: (self_value, other_value)
        """
        log("DEBUG", f"Diffing finding ID {self.id} against ID {other.id}", prefix="MODEL")
        differences = {}
        for field_name in self.__dataclass_fields__:
            val_self = getattr(self, field_name)
            val_other = getattr(other, field_name)
            log("DEBUG", f"Checking field '{field_name}': self='{val_self}' vs other='{val_other}'", prefix="MODEL")
            if val_self != val_other:
                differences[field_name] = (val_self, val_other)
        log("DEBUG", f"Differences found: {differences}", prefix="MODEL")
        return differences

    def merge_with(self, other: 'Finding', prefer: str = 'larger') -> 'Finding':
        """
        Merges this Finding with another, field by field. Preference is given based on:
        - 'filled' (prefer non-empty)
        - 'tokens' (prefer more words)
        - 'larger' (prefer longer strings)
        """
        log("DEBUG", f"Merging finding ID {self.id} with ID {other.id}", prefix="MODEL")

        merged_data = {}
        for field_name in self.__dataclass_fields__:
            val_a = getattr(self, field_name)
            val_b = getattr(other, field_name)
            log("DEBUG", f"Evaluating merge for field '{field_name}': val_a='{val_a}' val_b='{val_b}'", prefix="MODEL")

            if val_a == val_b:
                merged_data[field_name] = val_a  # identical, safe to use either
                log("DEBUG", f"Values identical. Using '{val_a}'", prefix="MODEL")
            elif not val_a:
                merged_data[field_name] = val_b  # prefer non-empty value
                log("DEBUG", f"val_a empty. Using val_b='{val_b}'", prefix="MODEL")
            elif not val_b:
                merged_data[field_name] = val_a  # prefer non-empty value
                log("DEBUG", f"val_b empty. Using val_a='{val_a}'", prefix="MODEL")
            elif isinstance(val_a, str) and isinstance(val_b, str):
                # For strings, use length or token-count preference
                if prefer == 'tokens':
                    merged = val_a if len(val_a.split()) > len(val_b.split()) else val_b
                else:
                    merged = val_a if len(val_a) > len(val_b) else val_b
                merged_data[field_name] = merged
                log("DEBUG", f"Merged string based on preference '{prefer}': '{merged}'", prefix="MODEL")
            elif isinstance(val_a, list) and isinstance(val_b, list):
                merged_data[field_name] = list(set(val_a + val_b))
                log("DEBUG", f"Merged list: {merged_data[field_name]}", prefix="MODEL")
            elif isinstance(val_a, dict) and isinstance(val_b, dict):
                merged = val_a.copy()
                merged.update(val_b)
                merged_data[field_name] = merged
                log("DEBUG", f"Merged dict: {merged_data[field_name]}", prefix="MODEL")
            else:
                merged_data[field_name] = val_a  # fallback: pick original
                log("DEBUG", f"Fallback merge strategy. Using val_a='{val_a}'", prefix="MODEL")

        merged_finding = Finding(**merged_data)
        log("DEBUG", f"Merged result: {merged_finding}", prefix="MODEL")
        return merged_finding

    def prompt_user_to_fix_field(finding_dict: dict, error: InvalidFieldValue) -> int:
        """Prompt user to correct an invalid field inline, with styled Prompt.ask and action tokens."""
        field = error.field
        value = error.value
        finding_id = error.finding_id

        prompt = f"[red]Invalid value[/red] [yellow]{value}[/yellow] in [bold]{field}[/bold] (ID: {finding_id})"
        prompt += ". Action: [bold]F[/]ix/[bold]S[/]kip whole record/[bold]A[/]bort"
        action = Prompt.ask(
            prompt,
            choices=["f", "s", "a"],
            show_choices=False
        ).lower()

        if action == "f":
            new_value = Prompt.ask(f"Enter corrected value for [bold]{field}[/bold]")
            finding_dict[field] = new_value
            return 0

        elif action == "s":
            log("WARN", f"User skipped finding ID {finding_id}", prefix="Model")
            return 1

        else:  # action == "a"
            log("INFO", "User aborted the merge.", prefix="Model")
            return 2
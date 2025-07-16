# ── Standard library ────────────────────────────────────────────────
from __future__ import annotations
import difflib
import os
import subprocess
import tempfile
from json import dumps
from typing import Any, Dict, List

# ── Third‑party ─────────────────────────────────────────────────────
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

# ── Local project ───────────────────────────────────────────────────
from model import Finding
from merge import merge_individual_findings
from sensitivity import check_finding_for_sensitivities, load_sensitive_terms
from utils import CONFIG, log

__all__ = ["interactive_merge"]

# A dedicated Rich console means escape codes and progress bars do not clash
# with whatever stdout redirection the caller may have configured.
console: Console = Console()

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def render_diff_single_field(value_from_side_a: Any, value_from_side_b: Any) -> Columns:
    """Return two side‑by‑side *Panels* that highlight differences.

    Complex structures (``dict``/``list``) are serialised into pretty strings
    before diffing so the user sees exactly what will be written to disk.
    """

    log(
        "DEBUG",
        f"render_diff(): A‑type={type(value_from_side_a)}, B‑type={type(value_from_side_b)}",
        prefix="TUI",
    )

    # Serialise non‑scalar data for human‑readable diff output.
    if isinstance(value_from_side_a, dict) and isinstance(value_from_side_b, dict):
        value_from_side_a, value_from_side_b = (
            dumps(value_from_side_a, indent=2),
            dumps(value_from_side_b, indent=2),
        )
    elif isinstance(value_from_side_a, list) and isinstance(value_from_side_b, list):
        value_from_side_a, value_from_side_b = (
            "\n".join(map(str, value_from_side_a)),
            "\n".join(map(str, value_from_side_b)),
        )
    else:
        value_from_side_a, value_from_side_b = (
            str(value_from_side_a or ""),
            str(value_from_side_b or ""),
        )

    # Build Rich *Text* fragments with colour annotations.
    diff_for_side_a: Text = Text()
    diff_for_side_b: Text = Text()

    for line in difflib.ndiff(
        value_from_side_a.splitlines(), value_from_side_b.splitlines()
    ):
        change_code, line_content = line[:2], line[2:]
        if change_code == "- ":  # Present only in A – mark red in A panel.
            diff_for_side_a.append(line_content + "\n", style="bold red")
        elif change_code == "+ ":  # Present only in B – mark green in B panel.
            diff_for_side_b.append(line_content + "\n", style="bold green")
        else:  # Unchanged or intraline hint – copy to both panels.
            diff_for_side_a.append(line_content + "\n")
            diff_for_side_b.append(line_content + "\n")

    log("DEBUG", "_render_diff(): diff construction complete", prefix="TUI")

    return Columns(
        [
            Panel(diff_for_side_a or Text("<empty>"), title="A", padding=(0, 1)),
            Panel(diff_for_side_b or Text("<empty>"), title="B", padding=(0, 1)),
        ],
        equal=True,
        expand=True,
    )


def _invoke_editor(seed_text: str) -> str:
    """Launch ``$EDITOR`` (defaulting to *nano*) seeded with *seed_text*.

    Returns the edited contents with surrounding whitespace stripped.  DEBUG
    logs track the temporary file lifecycle so any residue can be investigated
    if the subprocess crashes.
    """

    chosen_editor: str = os.getenv("EDITOR", "nano")
    log("DEBUG", f"_invoke_editor(): Using editor '{chosen_editor}'", prefix="TUI")

    with tempfile.NamedTemporaryFile(
        "w+", delete=False, suffix=".tmp", encoding="utf‑8"
    ) as temporary_file:
        temporary_file.write(seed_text)
        temporary_file.flush()
        temporary_path: str = temporary_file.name

    log("DEBUG", f"_invoke_editor(): Temporary file created at {temporary_path}", prefix="TUI")

    try:
        subprocess.call([chosen_editor, temporary_path])  # Blocks until editor exits.
        with open(temporary_path, "r", encoding="utf‑8") as opened_file:
            edited_text: str = opened_file.read()
            log("DEBUG", f"_invoke_editor(): Edited text length={len(edited_text)}", prefix="TUI")
    finally:
        os.unlink(temporary_path)
        log("DEBUG", f"_invoke_editor(): Temporary file {temporary_path} deleted", prefix="TUI")

    return edited_text.strip()

def interactive_merge(record_from_side_a: Finding, record_from_side_b: Finding) -> Finding:
    """Run automatic merge then solicit human confirmation/overrides.

    The *canonical* merge result produced by ``merge_individual_findings`` is
    treated as the default for every field.  The analyst sees a diff and may
    pick:
    • **A** – keep the original value from side‑A.
    • **B** – keep the original value from side‑B.
    • **S** – accept the auto‑merge suggestion (default).
    • **E** – hand‑edit via ``$EDITOR`` seeded with the suggestion.
    """

    log(
        "INFO",
        f"interactive_merge(): {record_from_side_a.id} ↔ {record_from_side_b.id}",
        prefix="TUI",
    )

    # Step 1 – Run the definitive merge algorithm to generate the suggestion.
    auto_merged_fields: Dict[str, Any] = merge_individual_findings(
        record_from_side_a, record_from_side_b
    )["a"]

    # Metadata fields that are not user‑editable.
    _NON_INTERACTIVE_FIELDS: List[str] = [
        "id",
        "source_id_a",
        "source_id_b",
        "reason",
    ]

    merged_record: Dict[str, Any] = {}

    # Iterate deterministically over field names.
    for field_name in auto_merged_fields.keys():
        if field_name in _NON_INTERACTIVE_FIELDS:
            merged_record[field_name] = auto_merged_fields[field_name]
            continue

        value_from_record_a: Any = getattr(record_from_side_a, field_name, None)
        value_from_record_b: Any = getattr(record_from_side_b, field_name, None)
        auto_suggested_value: Any = auto_merged_fields[field_name]

        log(
            "DEBUG",
            f"Field '{field_name}': A={value_from_record_a!r} | B={value_from_record_b!r} | S={auto_suggested_value!r}",
            prefix="TUI",
        )

        # Fast‑path when both sides agree and match the suggestion.
        if (
            value_from_record_a == value_from_record_b == auto_suggested_value
        ):
            merged_record[field_name] = auto_suggested_value
            log(
                "DEBUG",
                f"Field '{field_name}' identical across both sides – auto‑accepted.",
                prefix="TUI",
            )
            continue

        # ── Interactive resolution ──────────────────────────────────────────
        console.rule(f"[bold cyan]{field_name}")
        console.print(render_diff_single_field(value_from_record_a, value_from_record_b))
        console.print(
            "[grey italic]Option S uses the auto‑merged suggestion.[/grey italic]"
        )

        # Establish which option should be highlighted as the default.
        if auto_suggested_value == value_from_record_a:
            default_choice: str = "a"
        elif auto_suggested_value == value_from_record_b:
            default_choice: str = "b"
        else:
            default_choice: str = "s"

        analyst_choice: str = (
            Prompt.ask(
                "Choose [bold]A[/]/[bold]B[/]/[bold]S[/]uggest/[bold]E[/]dit",
                choices=["a", "b", "s", "e"],
                default=default_choice,
                show_choices=False,
            )
        ).lower()
        log(
            "DEBUG",
            f"User selection for '{field_name}' → {analyst_choice.upper()}",
            prefix="TUI",
        )

        # Commit the chosen value into the merged record.
        if analyst_choice == "a":
            merged_record[field_name] = value_from_record_a
        elif analyst_choice == "b":
            merged_record[field_name] = value_from_record_b
        elif analyst_choice == "s":
            merged_record[field_name] = auto_suggested_value
        else:  # "e" – manual edit via external editor.
            merged_record[field_name] = _invoke_editor(str(auto_suggested_value))

        # Sensitivity check inline per field
        if CONFIG['sensitivity_check_enabled']:
            sensitive_terms = load_sensitive_terms(CONFIG["sensitivity_check_terms_file"])
            temp_finding = Finding.from_dict({"id": record_from_side_a.id, field_name: merged_value})
            sensitivity_hits = check_finding_for_sensitivities(temp_finding, sensitive_terms)

            if sensitivity_hits.get(field_name):
                for sensitive_term, suggestion in sensitivity_hits[field_name]:
                    prompt = f"[red]Sensitive term[/red] [yellow]{sensitive_term}[/yellow] in [bold]{field_name}[/bold]"
                    if suggestion:
                        prompt += f" → [green]{suggestion}[/green]"
                        prompt += ". Action: [bold]A[/]pply/[bold]E[/]dit/[bold]S[/]kip"
                        action_choices = ["a", "e", "s"]
                    else:
                        prompt += ". Action: [bold]E[/]dit/[bold]S[/]kip"
                        action_choices = ["e", "s"]

                    action = Prompt.ask(
                        prompt,
                        choices=action_choices,
                        show_choices=False
                    ).lower()

                    if action == "a" and suggestion:
                        merged_value = merged_value.replace(sensitive_term, suggestion)
                    elif action == "e":
                        merged_value = _invoke_editor(merged_value)

    # Step 2 – Show a final preview before writing. ---------------------------
    preview_table: Table = Table(
        title="Merged Finding (post‑manual)", box=None, show_lines=False
    )
    preview_table.add_column("Field", style="bold white")
    preview_table.add_column("Value", overflow="fold")
    for field_name, final_value in merged_record.items():
        preview_table.add_row(field_name, str(final_value))

    console.rule("[bold green]Preview")
    console.print(preview_table)

    if not Confirm.ask("Write this merged record?", default=True):
        console.print("[yellow]Merge aborted by user.[/]")
        log("WARN", "Interactive merge aborted by analyst.", prefix="TUI")
        raise SystemExit(1)

    log("INFO", "Interactive merge finalised.", prefix="TUI")
    return Finding.from_dict(merged_record)

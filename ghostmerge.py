# import via the common imports route
from imports import (Path, Optional, typer)
# initialise global objects
from globals import get_config
CONFIG = get_config()
from tui import TUI
TUI()
# local module imports
from utils import load_config, log, load_json, write_json
from model import Finding
from matching import fuzzy_match_findings
from merge import interactive_merge

# run the app
app = typer.Typer()

@app.command()
def ghostmerge(
    file_in_a: Path = typer.Option(..., "--file-a", "-a", exists=True, help="Input JSON file A"),
    file_in_b: Path = typer.Option(..., "--file-b", "-b", exists=True, help="Input JSON file B"),
    file_out_a: Path = typer.Option(None, "--out-a", help="Output JSON file A"),
    file_out_b: Path = typer.Option(None, "--out-b", help="Output JSON file B"),
    config: Optional[Path] = typer.Option(None, "--config", help="Override config file path"),
    debug: bool = typer.Option(False, "--debug", help="Enable verbose logging")
):
    """
    Merge two GhostWriter finding library JSON files and output cleaned, ID-safe results.
    """

    # Load config
    if config:
        log("DEBUG", f"Loading user-specified config from: {config}", prefix="CLI")
        load_config(config)
    else:
        load_config()

    TUI.start()

    if debug:
        CONFIG["log_verbosity"] = "DEBUG"

    log("DEBUG", f"Args: file_in_a={file_in_a},\n"
                 f"     file_in_b={file_in_b},\n"
                 f"     file_out_a={file_out_b},\n"
                 f"     file_out_b={file_out_b},\n"
                 f"     config={config},\n"
                 f"     debug={debug}",
        prefix="CLI")

    log("INFO", "Starting merge operation", prefix="CLI")

    findings_a = [Finding.from_dict(f) for f in load_json(file_in_a)]
    findings_b = [Finding.from_dict(f) for f in load_json(file_in_b)]

    if file_out_a is None:
        file_out_a = str(file_in_a) + CONFIG['default_output_filename_append']

    if file_out_b is None:
        file_out_b = str(file_in_a) + CONFIG['default_output_filename_append']

    matches, unmatched_a, unmatched_b = fuzzy_match_findings(findings_a, findings_b)

    merged_a, merged_b = [], []
    for idx, (finding_a, finding_b, score) in enumerate(matches):
        log("INFO", f"Processing matched pair #{idx}: ID A={finding_a.id} ↔ ID B={finding_b.id} (score: {score:.2f})", prefix="CLI")

        # Separate merge decisions for each side
        result_a = interactive_merge(finding_a, finding_b)
        result_b = interactive_merge(finding_b, finding_a)

        merged_a.append(result_a)
        merged_b.append(result_b)

    write_json(file_out_a, [f.to_dict() for f in merged_a])
    write_json(file_out_b, [f.to_dict() for f in merged_b])
    log("INFO", f"Written merged files to {file_out_a} and {file_out_b}", prefix="CLI")

if __name__ == "__main__":
    app()

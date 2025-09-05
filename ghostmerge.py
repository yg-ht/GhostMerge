# import via the common imports route
from imports import (Path, Optional, typer)
# initialise global objects
from globals import get_config, get_tui
CONFIG = get_config()
from tui import TUI
tui = TUI()
# local module imports
from utils import load_config, log, load_json, write_json, return_ASCII_art, setup_signal_handlers
from model import Finding
from matching import fuzzy_match_findings
from merge import interactive_merge

# run the app
app = typer.Typer()

@app.command()
def ghostmerge(
    file_in_left: Path = typer.Option(..., "--file-left", "-left", exists=True, help="Input JSON file Left"),
    file_in_right: Path = typer.Option(..., "--file-right", "-right", exists=True, help="Input JSON file Right"),
    file_out_left: Path = typer.Option(None, "--out-left", help="Output JSON file Left"),
    file_out_right: Path = typer.Option(None, "--out-right", help="Output JSON file Right"),
    config: Optional[Path] = typer.Option(None, "--config", help="Override config file path"),
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

    get_tui().start()

    tui.update_data(return_ASCII_art(), 'white', 'Welcome to GhostMerge')
    log("INFO", "\n"
                          "[bold] ____  _               _   __  __                      [/bold]\n"                     
                          "[bold]/ ___|| |__   ___  ___| |_|  \/  | ___ _ __ __ _  ___  [/bold]\n" 
                          "[bold]| | __| '_ \ / _ \/ __| __| |\/| |/ _ \ '__/ _` |/ _ \ [/bold]\n"
                          "[bold]| |_| | | | | (_) \__ \ |_| |  | |  __/ | | (_| |  __/ [/bold]\n"
                          "[bold]\_____|_| |_|\___/|___/\__|_|  |_|\___|_|  \__, |\___| [/bold]\n"
                          "[bold]                                           |___/       [/bold]starting...\n",
        prefix='CLI' )

    log("DEBUG", f"Args: file_in_left={file_in_left},\n"
                 f"     file_in_right={file_in_right},\n"
                 f"     file_out_left={file_out_right},\n"
                 f"     file_out_right={file_out_right},\n"
                 f"     config={config}",
        prefix="CLI")

    log("INFO", "Starting merge operation", prefix="CLI")

    findings_left = [Finding.from_dict(f) for f in load_json(file_in_left)]
    findings_right = [Finding.from_dict(f) for f in load_json(file_in_right)]

    if file_out_left is None:
        file_out_left = str(file_in_left) + CONFIG['default_output_filename_append']

    if file_out_right is None:
        file_out_right = str(file_in_left) + CONFIG['default_output_filename_append']

    matches, unmatched_left, unmatched_right = fuzzy_match_findings(findings_left, findings_right)

    merged_left, merged_right = [], []
    for idx, (finding_left, finding_right, score) in enumerate(matches):
        log("INFO", f"Processing matched pair #{idx}: ID A={finding_left.id} ↔ ID B={finding_right.id} (score: {score:.2f})", prefix="CLI")

        # Separate merge decisions for each side
        result_left = interactive_merge(finding_left, finding_right)
        result_right = interactive_merge(finding_right, finding_left)

        merged_left.append(result_left)
        merged_right.append(result_right)

    write_json(file_out_left, [f.to_dict() for f in merged_left])
    write_json(file_out_right, [f.to_dict() for f in merged_right])
    log("INFO", f"Written merged files to {file_out_left} and {file_out_right}", prefix="CLI")

if __name__ == "__main__":
    app()

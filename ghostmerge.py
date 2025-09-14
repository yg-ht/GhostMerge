# import via the common imports route
from operator import indexOf

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
from merge import merge_main

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

    matches = []
    unmatched_left = findings_left
    unmatched_right = findings_right
    for fuzzy_threshold in CONFIG['fuzzy_match_threshold']:
        log('INFO', f'Performing fuzzy matching at {fuzzy_threshold}% match threshold','CLI')
        new_matches, unmatched_left, unmatched_right = fuzzy_match_findings(unmatched_left, unmatched_right, fuzzy_threshold)
        matches.extend(new_matches)

    log("INFO", f"After all fuzzy matching there are {len(unmatched_left)} unmatched findings from left", prefix="CLI")
    log("INFO", f"After all fuzzy matching there are {len(unmatched_right)} unmatched findings from right", prefix="CLI")

    log("INFO", f"Starting interactive merge for {len(matches)} fuzzy matched findings", prefix="CLI")
    merged_left, merged_right = [], []
    for match in matches:
        log("INFO", f"Processing matched pair #{matches.index(match)}: ID Left={match('left')['id']} ↔ ID Right={match('right')['id']} (score: {match('score'):.2f})", prefix="CLI")

        # Separate merge decisions for each side
        result_left, result_right = merge_main(match("left"), match("right"), score=match("score"), side='Left')

        merged_left.append(result_left)
        merged_right.append(result_right)

    # TODO: deal with unmatched findings
    #matches.extend(unmatched_left)
    #matches.extend(unmatched_right)

    write_json(file_out_left, [f.to_dict() for f in merged_left])
    write_json(file_out_right, [f.to_dict() for f in merged_right])
    log("INFO", f"Written merged files to {file_out_left} and {file_out_right}", prefix="CLI")

if __name__ == "__main__":
    app()

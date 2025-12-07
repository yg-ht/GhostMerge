# import via the common imports route
from operator import indexOf

from imports import (Path, Optional, List, Dict, typer)
# initialise global objects
from globals import get_config, get_tui
CONFIG = get_config()
from tui import TUI
tui = TUI()
# local module imports
from utils import load_config, log, load_json, write_json, return_ASCII_art, Aborting
from model import Finding
from matching import fuzzy_match_findings
from merge import merge_main
from sensitivity import sensitivities_checker_single_record, load_sensitive_terms

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
    tui.resize_splits()
    tui.blank_input()

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
                 f"     file_out_left={file_out_left},\n"
                 f"     file_out_right={file_out_right},\n"
                 f"     config={config}",
        prefix="CLI")

    log("INFO", "Starting merge operation", prefix="CLI")

    #findings_left = [Finding.from_dict(f) for f in load_json(file_in_left)]
    #findings_right = [Finding.from_dict(f) for f in load_json(file_in_right)]

    findings_left = []
    json_left = load_json(file_in_left)
    for finding_json_blob in json_left:
        finding_left_temp = Finding.from_dict(finding_json_blob)
        if finding_left_temp is not None:
            findings_left.append(finding_left_temp)

    findings_right = []
    json_right = load_json(file_in_right)
    for finding_json_blob in json_right:
        finding_right_temp = Finding.from_dict(finding_json_blob)
        if finding_right_temp is not None:
            findings_right.append(finding_right_temp)

    if file_out_left is None:
        file_out_left = str(file_in_left).replace('.json', CONFIG['default_output_filename_append'])

    if file_out_right is None:
        file_out_right = str(file_in_right).replace('.json', CONFIG['default_output_filename_append'])

    matches: List[Dict[str,Finding|float]] = []
    unmatched_left = findings_left
    unmatched_right = findings_right
    next_id = 1
    for fuzzy_threshold in CONFIG['fuzzy_match_threshold']:
        log('INFO', f'Performing fuzzy matching at {fuzzy_threshold}% match threshold','CLI')
        new_matches, unmatched_left, unmatched_right = fuzzy_match_findings(unmatched_left, unmatched_right, fuzzy_threshold, next_id=next_id)
        log('DEBUG', f'Updating matches dictionary with any new matches', 'CLI')
        matches.extend(new_matches)
        log('DEBUG', f'Matches dictionary now contains {len(matches)}', 'CLI')
        next_id = next_id + len(matches)

    log("INFO", f"After all fuzzy matching there are {len(unmatched_left)} unmatched findings from left", prefix="CLI")
    log("INFO", f"After all fuzzy matching there are {len(unmatched_right)} unmatched findings from right", prefix="CLI")

    log("INFO", f"Starting interactive merge for {len(matches)} fuzzy matched findings", prefix="CLI")

    merged_left, merged_right = [], []
    for match in matches:
        log("INFO", f"Processing matched pair: ID Left={match['left'].id} ↔ ID Right={match['right'].id} (score: {match['score']:.2f})", prefix="CLI")

        # Separate merge decisions for each side
        result_left, result_right = merge_main(match)

        merged_left.append(result_left)
        merged_right.append(result_right)

    unmatched_records_appended = 0
    log("DEBUG", f"Appending {len(unmatched_left)} unmatched records from Left", prefix="CLI")
    for unmatched_left_record in unmatched_left:
        merged_left.append(unmatched_left_record)
        merged_right.append(unmatched_left_record)
        unmatched_records_appended += 1
    log("DEBUG", f"Appending {len(unmatched_right)} unmatched records from Right", prefix="CLI")
    for unmatched_right_record in unmatched_right:
        merged_left.append(unmatched_right_record)
        merged_right.append(unmatched_right_record)
        unmatched_records_appended += 1
    log("INFO", f"Successfully appended {unmatched_records_appended} unmatched records to both Left and Right", prefix="CLI")

    final_left, final_right = [], []
    # Sensitivity check inline per field for all records
    if CONFIG['sensitivity_check_enabled']:
        terms = load_sensitive_terms(CONFIG["sensitivity_check_terms_file"], CONFIG["script_dir"])
        for record in merged_left:
            final_left.append(sensitivities_checker_single_record(record, 'Left', terms))
        for record in merged_right:
            final_right.append(sensitivities_checker_single_record(record, 'Right', terms))
    else:
        final_left = merged_left
        final_right = merged_right

    write_json(file_out_left, [f.to_dict() for f in final_left])
    write_json(file_out_right, [f.to_dict() for f in final_right])
    log("INFO", f"Written merged files to {file_out_left} and {file_out_right}", prefix="CLI")

    tui.update_data('Merge complete')

    log("INFO", "#########################", prefix="CLI")
    log("INFO", "## Processing complete ##", prefix="CLI")
    log("INFO", "#########################", prefix="CLI")
    log("INFO", "", prefix="CLI")
    get_tui().stop()

if __name__ == "__main__":
    try:
        app()
    except Aborting:
        log("INFO", "Caught abort signal... exiting!", prefix="MAIN")
    finally:
        tui.stop()

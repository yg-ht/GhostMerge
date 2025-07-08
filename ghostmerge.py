import typer
from pathlib import Path
from typing import Optional
from utils import load_config, CONFIG, log, load_json, write_json
from models import Finding
from tui import interactive_merge
from matching import fuzzy_match_findings


app = typer.Typer()

@app.command()
def merge(
    file_a: Path = typer.Option(..., "--file-a", "-a", exists=True, help="First input JSON file"),
    file_b: Path = typer.Option(..., "--file-b", "-b", exists=True, help="Second input JSON file"),
    out_a: Path = typer.Option(..., "--out-a", help="Output JSON for file A ID base"),
    out_b: Path = typer.Option(..., "--out-b", help="Output JSON for file B ID base"),
    config: Optional[Path] = typer.Option(None, "--config", help="Override config file path"),
    debug: bool = typer.Option(False, "--debug", help="Enable verbose logging")
):
    """
    Merge two GhostWriter finding library JSON files and output cleaned, ID-safe results.
    """

    # Load config
    if config:
        load_config(config)
        log("DEBUG", f"Loading user-specified config from: {config}", prefix="CLI")
    else:
        load_config()

    if debug:
        CONFIG["log_verbosity"] = "DEBUG"

    log("DEBUG", f"Args: file_a={file_a}, file_b={file_b}, config={config}, debug={debug}",
        prefix="CLI")

    log("INFO", "Starting merge operation", prefix="CLI")

    findings_a = [Finding.from_dict(f) for f in load_json(file_a)]
    findings_b = [Finding.from_dict(f) for f in load_json(file_b)]

    matches, unmatched_a, unmatched_b = fuzzy_match_findings(findings_a, findings_b)

    merged_a, merged_b = [], []
    for idx, (finding_a, finding_b, score) in enumerate(matches):
        log("INFO", f"Processing matched pair #{idx}: ID A={finding_a.id} ↔ ID B={finding_b.id} (score: {score:.2f})", prefix="CLI")

        # Separate merge decisions for each side
        result_a = interactive_merge(finding_a, finding_b)
        result_b = interactive_merge(finding_b, finding_a)

        merged_a.append(result_a)
        merged_b.append(result_b)

    write_json(out_a, [f.to_dict() for f in merged_a])
    write_json(out_b, [f.to_dict() for f in merged_b])
    log("INFO", f"Written merged files to {out_a} and {out_b}", prefix="CLI")

if __name__ == "__main__":
    app()

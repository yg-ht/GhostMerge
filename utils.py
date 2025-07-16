import json
import csv
import signal
import sys
import traceback
import datetime
from pathlib import Path
from typing import Any
from rich.console import Console
from bs4 import BeautifulSoup

# ── Config & Logging ────────────────────────────────────────────────
CONFIG = {"config_loaded": False, "log_verbosity": "INFO", "log_file_path": "ghostmerge.log"}
LEVEL_ORDER = ["DEBUG", "INFO", "WARN", "ERROR"]
console = Console()

def load_config(config_path: str | Path = "ghostmerge_config.json"):
    global CONFIG
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
            log('DEBUG', f'Loaded config from: {config_path}', prefix="UTILS")
            CONFIG.update(user_config)
            CONFIG["config_loaded"] = True
    except FileNotFoundError:
        log('WARN', f'No config file found at: {config_path}', prefix="UTILS")
        pass  # silently fall back to defaults
    except Exception as e:
        log('ERROR', f"Failed to load config from {config_path}: {e}", prefix="UTILS")


def log(level: str, msg: str, prefix: str = None, exception: Exception = None, log_to_file: bool = True):
    level = level.upper()
    verbosity_overall = LEVEL_ORDER.index(CONFIG["log_verbosity"].upper())
    if CONFIG["config_loaded"]:
        try:
            verbosity_subject = LEVEL_ORDER.index(CONFIG["log_verbosity_" + prefix.lower()].upper())
        except KeyError:
            verbosity_subject = LEVEL_ORDER.index("DEBUG")
            prefix = f"VERBOSITY ERROR: {prefix} not found!"
        verbosity = min(verbosity_overall, verbosity_subject)
    else:
        verbosity = verbosity_overall

    if LEVEL_ORDER.index(level) <= verbosity:
        return

    level_map = {
        "DEBUG": "[dim cyan][DEBUG][/dim cyan]",
        "INFO": "[bold green][INFO][/bold green]",
        "WARN": "[bold yellow][WARN][/bold yellow]",
        "ERROR": "[bold red][ERROR][/bold red]",
    }

    tag = level_map.get(level, "[white][LOG][/white]")
    full_prefix = f"[{prefix}] " if prefix else ""
    full_message = f"{tag} {full_prefix}{msg}"

    console.print(full_message, highlight=False)

    if exception:
        exception_text = f"{type(exception).__name__}: {exception}\n{traceback.format_exc()}"
        console.print(f"[red]{exception_text}[/red]", highlight=False)
    else:
        exception_text = None

    if log_to_file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        plain_prefix = f"[{prefix}] " if prefix else ""
        file_msg = f"{timestamp} | {level:<5} | {plain_prefix}{msg}\n"
        if exception_text:
            file_msg += exception_text + "\n"

        with Path(CONFIG["log_file_path"]).open("a", encoding="utf-8") as f:
            f.write(file_msg)

# ── IO Utilities ────────────────────────────────────────────────────
def load_json(path: str | Path) -> list[dict]:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("JSON must be a list of records.")
        log("DEBUG", f"Loaded {len(data)} records from JSON", prefix="UTILS")
        return data
    except Exception as e:
        log("ERROR", f"Failed to read {path}", prefix="UTILS", exception=e)
        raise

def write_json(path: str | Path, data: list[dict]) -> None:
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        log("INFO", f"Written to {path}", prefix="UTILS")
    except Exception as e:
        log("ERROR", f"Failed to write {path}", prefix="UTILS", exception=e)
        raise

# ── Data Utilities ──────────────────────────────────────────────────
def strip_html(html: str) -> str:
    try:
        text = BeautifulSoup(html, "html.parser").get_text(separator=" ", strip=True)
        log("DEBUG", "HTML stripped successfully", prefix="UTILS")
        return text
    except Exception as e:
        log("ERROR", "HTML stripping failed", prefix="UTILS", exception=e)
        raise

def get_next_available_id(existing_ids: set[int]) -> int:
    current = 1
    while current in existing_ids:
        current += 1
    log("DEBUG", f"Next available ID: {current}", prefix="UTILS")
    return current

def normalise_tags(tag_str: str) -> list[str]:
    tags = list({tag.strip().lower() for tag in tag_str.replace(',', ' ').split() if tag.strip()})
    log("DEBUG", f"Normalised tags: {tags}", prefix="UTILS")
    return tags

# ── Signal Handling ─────────────────────────────────────────────────
def setup_signal_handlers():
    def handle_exit(signum, frame):
        log("WARN", "Received interrupt signal. Exiting gracefully...", prefix="UTILS")
        sys.exit(1)
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

# external module imports
from imports import datetime, json, traceback, Path, Panel, Text, Optional
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()

# ── Config & Logging ────────────────────────────────────────────────
LEVEL_ORDER = ["DEBUG", "INFO", "WARN", "ERROR"]

def load_config(config_path: str | Path = "ghostmerge_config.json"):
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
            log('DEBUG', f'Loaded config from: {config_path}', prefix="UTILS")
            CONFIG.update(user_config)
            CONFIG["config_loaded"] = True
    except FileNotFoundError:
        log('ERROR', f'No config file found at: {config_path}', prefix="UTILS")
    except Exception as e:
        log('ERROR', f"Failed to load config from {config_path}: {e}", prefix="UTILS")


def log(level: str, msg: str, prefix: str = None, exception: Exception = None):
    # set defaults
    TUI = None
    log_to_file = True
    log_file_path = 'ghostmerge.log'
    verbosity_overall = LEVEL_ORDER.index(CONFIG["log_verbosity"].upper())

    level = level.upper()
    if CONFIG["config_loaded"]:
        try:
            verbosity_subject_key = CONFIG["log_verbosity_" + prefix.lower()]
            verbosity_subject = LEVEL_ORDER.index(verbosity_subject_key)
        except KeyError:
            verbosity_subject = LEVEL_ORDER.index("DEBUG")
            prefix = f"VERBOSITY ERROR: {prefix} not found!"
        verbosity = min(verbosity_overall, verbosity_subject)
        try:
            log_to_file = CONFIG["log_file_enabled"]
            log_file_path = CONFIG["log_file_path"]
        except KeyError as e:
            if TUI:
                TUI.update_messages(f'Error getting log file config variables: {e}')
            else:
                print(f'Error getting log file config variables: {e}')

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

    try:
        TUI = get_tui()
        TUI.update_messages(full_message)
    except RuntimeError:
        print(full_message)

    if exception:
        exception_text = f"{type(exception).__name__}: {exception}\n{traceback.format_exc()}"
        if TUI:
            TUI.update_messages(f"[red]{exception_text}[/red]")
        else:
            print(f"[red]{exception_text}[/red]")
    else:
        exception_text = None

    if log_to_file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        plain_prefix = f"[{prefix}] " if prefix else ""
        file_msg = f"{timestamp} | {level:<5} | {plain_prefix}{msg}\n"
        if exception_text:
            file_msg += exception_text + "\n"

        with Path(log_file_path).open("a", encoding="utf-8") as f:
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

def get_user_input(self, choices: Optional[list[str] | str], default_choice: Optional[str]) -> str | bool:
    """
    Gather user input and check it is constrained to a set of single-character choices when specified.
    Returns the selected character as lowercase.
    """

    if isinstance(choices, str):
        choices = list(choices)

    choices = [ch.lower() for ch in choices]

    if default_choice:
        default_choice = default_choice.lower()
        if default_choice not in choices:
            raise log("WARN",f"Default choice '{default_choice}' not in choices: {str(choices)}", prefix="UTILS")

    while True:
        user_input = input(">>> ").strip().lower()
        if user_input == "" and default_choice:
            return default_choice
        if user_input in choices:
            return user_input


'''
def setup_signal_handlers():
    def handle_exit(signum, frame):
        log("WARN", "Received interrupt signal. Exiting gracefully...", prefix="UTILS")
        sys.exit(1)
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
'''

# ── Data Utilities ──────────────────────────────────────────────────
'''
def strip_html(html: str) -> str:
    try:
        text = BeautifulSoup(html, "html.parser").get_text(separator=" ", strip=True)
        log("DEBUG", "HTML stripped successfully", prefix="UTILS")
        return text
    except Exception as e:
        log("ERROR", "HTML stripping failed", prefix="UTILS", exception=e)
        raise

class IDTracker:
    """
    Tracks and assigns unique IDs across a dataset.
    Ensures no collisions when new IDs are needed.
    """
    def __init__(self, prefix: str):
        self.prefix = prefix
        self.existing_ids = set()

    def register_existing(self, existing_id: str):
        self.existing_ids.add(existing_id)
        log("DEBUG", f"Registered existing ID: {existing_id}", prefix="IDTracker")

    def get_next_available_id(self) -> str:
        current = 1
        while True:
            candidate = f"{self.prefix}{current:03d}"
            if candidate not in self.existing_ids:
                self.existing_ids.add(candidate)
                log("DEBUG", f"Generated new ID: {candidate}", prefix="IDTracker")
                return candidate
            current += 1
    
    def get_next_available_id(existing_ids: set[int]) -> int:
        current = 1
        while current in existing_ids:
            current += 1
        log("DEBUG", f"Next available ID: {current}", prefix="UTILS")
        return current
'''

def normalise_tags(tag_str: str) -> list[str]:
    tags = list({tag.strip().lower() for tag in tag_str.replace(',', ' ').split() if tag.strip()})
    log("DEBUG", f"Normalised tags: {tags}", prefix="UTILS")
    return tags
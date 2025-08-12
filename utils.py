# external module imports
from imports import datetime, json, traceback, Path, Panel, Text, Optional, random, b64decode
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


def log(level: str, msg: str, prefix: str = '', exception: Exception = None):
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
            if prefix != '':
                prefix = f"PREFIX not found: {prefix}!"
            else:
                prefix = f"PREFIX not set!"

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



def return_ASCII_art():
    images = []
    images.append('ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIOKWkeKWkuKWk+KWk+KWkuKWkSAgICAgICAgICAgICAgICAgICA'
                  'gICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg4paT4paI4paI4paI4paI4paI4paI4paI4paI4paI4p'
                  'aI4paT4paRICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilpLilojilojil'
                  'ojilojilojilojilojilojilojilojilojilojilojilojilpMgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAg'
                  'ICAgICAgICAgICAgICAgICDilpPilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilpMgICA'
                  'gICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg4paR4paI4paI4paI4paI4paI4paI4paI4p'
                  'aI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paSICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgI'
                  'CAgICAgICAgICAg4paT4paI4paI4paS4paT4paI4paI4paI4paI4paT4paS4paT4paI4paI4paI4paI4paI4paI4paI4paI4paR'
                  'ICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilpPilojilpEgIOKWkuKWiOKWiOKWkyA'
                  'gIOKWkuKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWkSAgICAgICAgICAgICAgICAgIAog4paR4paR4paR4paR4paR4paR4paR4p'
                  'aR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paRICAgICDilpPilojilpIgICDilojilojil'
                  'pMgICAg4paT4paI4paI4paI4paI4paI4paI4paI4paTICAgICAgICAgICAgICAgICAgCiDilpHilpHilpHilpHilpHilpHilpHi'
                  'lpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpEgICAgIOKWkeKWiOKWiOKWkSAg4paI4pa'
                  'I4paI4paSICAg4paS4paI4paI4paI4paI4paI4paI4paI4paT4paT4paSICAgICAgICAgICAgICAgIAog4paR4paR4paR4paR4p'
                  'aR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paRICAgICAg4paT4paI4paI4'
                  'paI4paI4paI4paI4paI4paI4paI4paT4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paT4paT4paSICAgICAgICAg'
                  'ICAgICAKIOKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeK'
                  'WkeKWkSAgICAgIOKWkuKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiO'
                  'KWiOKWk+KWk+KWk+KWk+KWkyAgICAgICAgICAgIAog4paR4paR4paR4paR4paS4paS4paR4paS4paR4paS4paR4paS4paR4paS4'
                  'paS4paR4paS4paS4paR4paR4paR4paR4paR4paRICAgICAg4paS4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI'
                  '4paI4paI4paI4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paSICAgICAgICAgIAog4paR4paR4paR4paR4pa'
                  'S4paR4paR4paR4paR4paR4paS4paS4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paRICAgICDilpHilpLilojilo'
                  'jilojilojilojilojilojilojilojilojilojilojilpPilpPilojilpPilpPilpPilpPilpPilpPilpPilpPilojilpPilpPil'
                  'pPilpPilpMgICAgICAgICAKIOKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKW'
                  'keKWkeKWkeKWkeKWkeKWkSAgICDilpLilpLilpLilpPilojilojilojilojilojilojilojilpPilpPilpPilpPilpPilpPilpP'
                  'ilpPilpPilpPilpPilpPilpPilpPilojilojilojilpPilpPilpPilpPilpMgICAgICAgIAog4paR4paR4paR4paR4paS4paR4p'
                  'aR4paS4paR4paS4paS4paR4paS4paS4paR4paS4paS4paS4paR4paR4paR4paR4paR4paRIOKWkeKWkuKWkuKWkuKWkuKWkuKWk'
                  'uKWk+KWk+KWkuKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkuKWiOKWiOKWiOKW'
                  'iOKWiOKWk+KWk+KWk+KWkSAgICAgICAKIOKWkeKWkeKWkeKWkeKWkuKWkuKWkeKWkuKWkeKWkuKWkeKWkuKWkuKWkuKWkeKWkeK'
                  'WkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWk+KWk+KWkuKWkeKWkeKWkeKWkeKWkeKWke'
                  'KWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWk+KWkiAgICAgICAKIOKWk'
                  'eKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkuKW'
                  'kuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWk+KWkuKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeK'
                  'WkeKWkeKWkeKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWkiAgICAgICAKIOKWkeKWkeKWkeKWkeKWkuKWkeKWkeKWkeKWkeKWke'
                  'KWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkuKWk+KWk+KWk+KWk+KWkuKWkeKWkeKWkeKWkeKWkuKWkuKWk'
                  'uKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWk+KWiOKWiOKWiOKWiOKWiOKWiOKW'
                  'iOKWk+KWkSAgICAgICAKIOKWkeKWkeKWkeKWkeKWk+KWkuKWkeKWkuKWkuKWkuKWkuKWkeKWkuKWkeKWkuKWkeKWkuKWkuKWkuK'
                  'Wk+KWkuKWkeKWkeKWkeKWkuKWkuKWkuKWkuKWk+KWiOKWiOKWkiDilpLilpHilpHilpHilpHilpHilpLilpHilpHilpHilpLilp'
                  'LilpHilpHilpHilpHilpLilpHilpLilojilojilojilojilojilojilojilojilpMgICAgICAgIAog4paR4paR4paR4paR4paR4'
                  'paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paRICAgICAgIOKWkeKWk+KWiOKW'
                  'k+KWk+KWkuKWkeKWkuKWkuKWkeKWkuKWkeKWkuKWkuKWkuKWkuKWkuKWkeKWkeKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOK'
                  'WkyAgICAgICAgIAog4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4p'
                  'aR4paR4paR4paRICAgICAgICAgIOKWkeKWkeKWkeKWkeKWkuKWkuKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWiOKWiOKWiOKWi'
                  'OKWiOKWiOKWiOKWiOKWiOKWiOKWkuKWkSAgICAgICAgIAog4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR'
                  '4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paRICAgICAgICAgIOKWkeKWkeKWkeKWkeKWkuKWkeKWkeKWkeKWkeKWkeK'
                  'WkeKWkeKWkeKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWkuKWkeKWkeKWkeKWkSAgICAgICAgIAog4paR4paR4paR4paR4paR4p'
                  'aR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paRICAgICAgICAgIOKWkeKWkeKWk'
                  'eKWkeKWkuKWkeKWkuKWkeKWkuKWkuKWkuKWkeKWkeKWiOKWiOKWiOKWk+KWkuKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkSAgICAg'
                  'ICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIOKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeK'
                  'WkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkSAgICAgICAgIAogICAgICAgICAgICAgICAgICAgIC'
                  'AgICAgICAgICAgICAgIOKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWk'
                  'eKWkeKWkeKWkeKWkeKWkeKWkSAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIOKWkeKWkeKWkeKW'
                  'keKWkuKWkeKWkuKWkuKWkuKWkuKWkuKWkuKWkeKWkuKWkuKWkuKWkeKWkuKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkSAgICAgICA'
                  'gIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIOKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWke'
                  'KWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkSAgICAgICAKICAgICAgICAgICAgICAgICAgI'
                  'CAgICAgICAgICAgICAgICDilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHi'
                  'lpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpEgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICD'
                  'ilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilp'
                  'HilpHilpHilpHilpEgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilpHilpHilpHilpHil'
                  'pHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpEgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
                  'ICAgICAgICAgICAgICAgICAgICDilpHilpHilpHilpHilpHilpHilpHilpHilpEgICAgICAgICAgICAgIAo=')
    images.append('ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg4paR4paS4paT4paT4paI4paT4paT4paT4paSICAgICAgICA'
                  'gICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilpLilojilojilojilojilojilojilo'
                  'jilojilojilojilojilojilojilpPilpEgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI'
                  'CAgIOKWk+KWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWkSAgICAgICAgICAg'
                  'ICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilpHilojilojilojilojilojilojilojilojilojilojiloj'
                  'ilojilojilojilojilojilojilojilojilojilojilpEgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgIC'
                  'AgICAgIOKWkeKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWi'
                  'OKWiOKWkSAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIOKWkeKWk+KWiOKWiOKWiOKWiOKWiOKW'
                  'iOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWkyAgICAgICAgICAgICAgCiAgICA'
                  'gICAgICAgICAgICAgICAgICAgICAgICAgIOKWkeKWiOKWiOKWiOKWiOKWkuKWkeKWkeKWiOKWiOKWiOKWiOKWkeKWkeKWkeKWku'
                  'KWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWkSAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgI'
                  'CAg4paT4paI4paI4paI4paR4paR4paR4paR4paI4paI4paI4paI4paR4paR4paR4paR4paR4paI4paI4paI4paI4paI4paI4paI'
                  '4paI4paI4paSICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilojilojilojilojilpHilpHilpH'
                  'ilpHilojilojilojilojilpHilpHilpHilpHilpHilojilojilojilojilojilojilojilojilojilpMgICAgICAgICAgICAgCi'
                  'AgICAgICAgICAgICAgICAgICAgICAgICAgICAg4paR4paI4paI4paI4paI4paR4paR4paR4paI4paI4paI4paI4paI4paI4paS4'
                  'paR4paR4paR4paI4paI4paI4paI4paI4paI4paI4paI4paT4paT4paRICAgICAgICAgICAgCiAgICAgIOKWkeKWkeKWkeKWkeKW'
                  'keKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkSAgICAg4paI4paI4paI4paI4paI4paI4paI4paI4pa'
                  'I4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paT4paSICAgICAgICAgICAgCiAgIC'
                  'AgICDilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpEgICAg4paS4paI4paI4'
                  'paI4paI4paI4paI4paI4paR4paR4paR4paR4paS4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paT4paT'
                  '4paRICAgICAgICAgICAKICAgICAgICDilpHilpHilpLilpHilpHilpLilpLilpHilpLilpLilpLilpHilpLilpLilpLilpHilpH'
                  'ilpEgICAg4paR4paI4paI4paI4paI4paI4paI4paR4paR4paR4paR4paR4paR4paR4paI4paI4paI4paI4paI4paI4paI4paI4p'
                  'aI4paI4paI4paI4paT4paT4paT4paRICAgICAgICAgIAogICAgICAgIOKWkeKWkeKWkuKWkeKWkeKWkuKWkuKWkeKWkuKWkeKWk'
                  'eKWkeKWkeKWkuKWkeKWkeKWkeKWkSAgICDilpPilojilojilojilojilojilojilojilojilojilpPilpHilpHilpPilojiloji'
                  'lojilojilojilojilojilojilojilojilpPilpPilpPilpPilpPilpLilpEgICAgICAgIAogICAgICAgIOKWkeKWkeKWkeKWkeK'
                  'WkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkSAgICDilpHilojilojilojilojilojilojilojilo'
                  'jilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilpPilpPilpPilpPilpPilpPilpPilpLilpEgI'
                  'CAgICAKICAgICAgICDilpHilpHilpLilpLilpLilpHilpLilpHilpLilpHilpLilpHilpLilpHilpLilpHilpLilpHilpEgICAg'
                  'IOKWkeKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWk+K'
                  'Wk+KWk+KWk+KWk+KWk+KWk+KWkuKWkuKWkuKWkuKWkSAgICAKICAgICAgICDilpHilpHilpLilpLilpHilpHilpHilpLilpHilp'
                  'HilpLilpLilpLilpHilpHilpLilpHilpHilpHilpEgICAgICDilpHilpPilojilojilojilojilojilojilojilojilojilojil'
                  'ojilojilojilojilojilojilojilpPilpPilpPilpPilpPilpPilpPilpPilpLilpLilpLilpLilpLilpLilpLilpLilpEgICAK'
                  'ICAgICAgICDilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpEgICAgICA'
                  'g4paT4paT4paT4paT4paT4paI4paI4paI4paI4paI4paI4paI4paI4paI4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4p'
                  'aS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paRICAKICAgICAgICDilpHilpHilpHilpLilpHilpHilpLilpHilpHilpLil'
                  'pLilpLilpLilpHilpLilpLilpLilpHilpHilpHilpEgICAgIOKWkeKWkuKWkuKWkuKWkuKWk+KWk+KWk+KWk+KWk+KWk+KWk+KW'
                  'k+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkeKWkeK'
                  'WkSAKICAgICAgICDilpHilpHilpLilpHilpLilpHilpLilpLilpLilpHilpLilpLilpHilpHilpLilpLilpHilpHilpHilpHilp'
                  'HilpEgICDilpHilpHilpHilpLilpLilpLilpLilpLilpLilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpLil'
                  'pLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpHilpEgCiAgICAgICAgICDilpHilpHilpHilpHilpHi'
                  'lpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpEg4paR4paR4paR4paR4paS4paS4paS4paS4pa'
                  'T4paT4paT4paT4paT4paT4paT4paT4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paR4paR4paS4paS4paS4paR4p'
                  'aR4paR4paR4paR4paRCiAgICAgIOKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWk'
                  'eKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkuKWkuKWk+KWk+KWkuKWkuKWk+KWkuKWkuKWkuKW'
                  'kuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkSAg4paR4paR4paR4paR4paR4paR4paR4paR4paRCiAgICAgICAg4paR4pa'
                  'R4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4p'
                  'aR4paR4paR4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paR4paRICAgI'
                  'OKWkeKWkeKWkeKWkeKWkeKWkeKWkSAKICDilpPilojilojilojilojilojilojilpPilpPilpLilpLilpHilpHilpHilpHilpHi'
                  'lpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpHilpLilpLilpLilpLilpLilpLilpLilpL'
                  'ilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpHilpHilpEgICAgICDilpHilpHilpHilpHilpHilpEgCuKWkeKWke'
                  'KWkeKWkeKWkeKWkuKWiOKWiOKWiOKWiOKWk+KWk+KWk+KWkuKWkuKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWkeKWk'
                  'eKWkeKWkeKWkeKWkeKWkeKWkeKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkeKWkeKWkuKW'
                  'keKWkeKWkeKWkSAgICAgICAg4paR4paR4paR4paR4paRICAK4paR4paS4paR4paR4paR4paR4paT4paI4paI4paI4paI4paT4pa'
                  'T4paT4paS4paS4paS4paS4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paS4paS4paS4paS4paS4p'
                  'aS4paS4paS4paS4paS4paS4paS4paR4paS4paR4paR4paR4paR4paR4paRICAgICAgICAgIOKWkeKWkeKWkeKWkeKWkSAgIAogI'
                  'CAgICDilpHilojilojilojilpPilpPilpPilpLilpLilpLilpLilpLilpLilpLilpHilpHilpHilpHilpHilpHilpHilpHilpHi'
                  'lpHilpHilpLilpLilpLilpLilpLilpLilpLilpHilpHilpHilpHilpHilpHilpHilpEgICAgICAgICAgICAgICDilpHilpHilpH'
                  'ilpEgICAgIAogICAgICDilpHilojilojilojilojilojilojilpPilpPilpPilpPilpLilpLilpLilpLilpLilpHilpHilpHilp'
                  'HilpHilpHilpHilpHilpLilpLilpLilpLilpLilpEgICAgICAgICAgICAgICAgICAgICAgICDilpHilpHilpEgICAgICAgCiAgI'
                  'CAgIOKWkeKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWk+KWk+KWk+KWk+KWk+KWkuKWkuKWkuKWkuKWkuKWkuKWkeKWkeKWkeKWkeKW'
                  'kuKWkuKWkuKWkuKWkSAgICAgICAgICAgICAgICAgICAgICAgICAg4paRICAgICAgICAgCiAgICAgIOKWkeKWiOKWiOKWiOKWiOK'
                  'Wk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkSAgICAgICAgIC'
                  'AgICAgICAgICAgICAgICAgIOKWkSAgICAgICAgIAogICAgICDilpHilojilojilojilojilojilojilojilojilojilojilojil'
                  'ojilpPilpPilpPilpPilpPilpPilpLilpLilpLilpLilpLilpLilpIgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAg'
                  'ICAg4paR4paI4paI4paI4paI4paT4paT4paI4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paS4paS4paS4paS4paS4pa'
                  'S4paT4paSICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAg4paR4paI4paI4paI4paI4paI4paI4p'
                  'aI4paI4paI4paI4paI4paI4paI4paT4paI4paT4paT4paT4paT4paT4paT4paT4paT4paT4paSICAgICAgICAgICAgICAgICAgI'
                  'CAgICAgICAgICAgICAgICAgICAKICAgICAg4paR4paT4paI4paI4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paS'
                  '4paS4paS4paS4paS4paS4paT4paT4paT4paT4paSICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICA'
                  'g4paR4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4p'
                  'aT4paT4paRICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAg4paT4paT4paT4paT4paT4paT4paT4'
                  'paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paT4paS4paR4paR4paR4paR4paRICAg'
                  'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgIOKWkeKWk+KWk+KWk+KWkuKWkuKWkuKWkuKWk+KWiOKWiOKWiOK'
                  'WiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWkyAgICAgICAgICAgIC'
                  'AgICAgICAgICAgICAgICAgIAogICAgICAgIOKWkeKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWi'
                  'OKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWkyAgICAgICAgICAgICAgICAgICAgICAgICAg'
                  'ICAgIAogICAgICAgICDilpHilpLilpLilpLilpLilpLilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpP'
                  'ilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpIgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgIC'
                  'Ag4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4paR4'
                  'paR4paRICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAK')
    images.append('ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilpLilpPilpPilpPilojilojilojilpPilpPilpPilpIgICAgICA'
                  'gICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg4paS4paI4paI4paI4paI4p'
                  'aI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paT4paSICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgI'
                  'CAgICAgICAgICAgICAgICAgICDilpLilpPilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojiloji'
                  'lojilpPilpIgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgIOKWkuKWiOKWiOK'
                  'WiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWkyAgICAgICAgICAgICAgIC'
                  'AgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIOKWkuKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWi'
                  'OKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWkyAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAg'
                  'ICAgICAgICAgICAgICAgICDilpHilpPilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojiloj'
                  'ilojilojilojilojilojilpPilpPilpIgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgIC'
                  'DilpLilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojil'
                  'pPilpPilpIgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICDilpPilojilojilpHilpHi'
                  'lpPilojilojilojilojilojilpHilpHilpHilpHilojilojilojilojilojilojilojilojilojilpPilpPilpPilpEgICAgICA'
                  'gICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgIOKWk+KWiOKWiOKWkeKWkeKWkeKWkuKWiOKWiOKWiO'
                  'KWkuKWkeKWkeKWkeKWkeKWkeKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWk+KWk+KWk+KWkSAgICAgICAgICAgICAgICAgI'
                  'CAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICDilpLilpPilojilpHilpHilpHilpHilojilojilojilojilpHilpHilpHi'
                  'lpHilpHilpLilojilojilojilojilojilojilojilpPilpPilpPilpPilpLilpEgICAgICAgICAgICAgICAgICAgIAogICAgICA'
                  'gICAgICAgICAgICAgICAgICAgICAg4paI4paI4paI4paR4paR4paR4paT4paI4paI4paI4paI4paR4paR4paR4paR4paR4paI4p'
                  'aI4paI4paI4paI4paI4paI4paI4paT4paT4paT4paT4paS4paRICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgI'
                  'CAgICAgICAgICAg4paR4paI4paI4paI4paS4paS4paI4paI4paI4paI4paI4paI4paT4paS4paS4paI4paI4paI4paI4paI4paI'
                  '4paI4paI4paI4paI4paT4paT4paT4paT4paT4paR4paRICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICA'
                  'gICAgICDilpPilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilo'
                  'jilojilojilpPilpPilpPilpPilpPilpPilpLilpHilpEgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgI'
                  'CAgIOKWkeKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKW'
                  'iOKWiOKWiOKWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWkuKWkSAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICA'
                  'g4paI4paI4paIICDilpLilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilo'
                  'jilojilojilojilojilojilojilojilpPilpPilpPilpPilpPilpPilpPilpLilpHilpEgICAgICAgICAKICAgICAgICAgICAgI'
                  'CAgICAgICAgICAg4paI4paI4paIICAgIOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKW'
                  'iOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWk+KWk+KWk+KWk+KWkuKWkuKWkSAgICAgICAgCiA'
                  'gICAgICAgICAgICAgICAgICAgICDilojilojilojilojiloggICDilpLilpPilojilojilojilojilojilojilojilojilojilo'
                  'jilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilpPilpPilpPilpPilpPil'
                  'pPilpLilpIgICAgICAgIAogICAgICAgICAgICAgICAgICAgICDilojilojilojilojiloggICDilpHilpPilpPilojilojiloji'
                  'lojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojiloj'
                  'ilojilojilpPilpPilpPilpPilpPilpLilpLilpEgICAgICAgCiAgICAgICAgICAgICAgICAgICAg4paI4paI4paI4paI4paIIC'
                  'Ag4paT4paT4paT4paT4paT4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4'
                  'paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paT4paT4paT4paT4paT4paS4paT4paSICAgICAgIAogICAgICAgICAgICAg'
                  'ICAgICAg4paI4paI4paI4paI4paIICAg4paS4paT4paT4paT4paT4paT4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4pa'
                  'I4paI4paI4paI4paI4paI4paI4paI4paI4paI4paT4paT4paI4paI4paI4paI4paI4paI4paI4paT4paT4paT4paT4paS4paT4p'
                  'aT4paT4paRICAgICAgCiAgICAgICAgICAgICAgICAgIOKWiOKWiOKWiOKWiOKWiOKWkuKWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk'
                  '+KWkuKWk+KWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWk+KWk+KWk+KWiOKW'
                  'iOKWiOKWiOKWiOKWiOKWiOKWk+KWk+KWk+KWk+KWk+KWk+KWk+KWiOKWkyAgICAgIAogICAgICAgICAgICAgIOKWiOKWiOKWiOK'
                  'WiOKWiOKWiOKWiOKWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWkuKWkuKWkuKWk+KWiOKWiOKWiOKWk+KWk+KWk+KWiO'
                  'KWiOKWiOKWiOKWiOKWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWk+KWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWk+KWk+KWk+KWk'
                  '+KWk+KWk+KWiOKWkyAgICAgIAogICAgICAgICAgICDilojilojilojilojilojilojilojilojilojilojilpPilpPilpPilpPi'
                  'lpPilpPilpPilpLilpLilpLilpLilpLilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpP'
                  'ilpPilpPilpPilojilojilojilojilojilojilojilojilpPilpPilpPilpPilpLilpPilojilojilojilpMgICAgIAogICAgIC'
                  'AgICAgICDilojilojilojilojilojilojilojilojilojilojilojilpPilpPilpPilpPilpPilpLilpLilpLilpLilpLilpLil'
                  'pLilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilpPilojilojilojilojilojiloji'
                  'lojilojilojilpPilpPilpPilpPilpPilpPilojilojilojilpMgICAgIAogICAgICAgICAgICDilojilojilojilojilojiloj'
                  'ilojilojilojilojilojilpPilpPilpPilpPilpLilpLilpLilpLilpIgICDilpLilpLilpPilpPilpPilpPilpPilpLilpPilp'
                  'PilpPilpPilpPilpPilpPilpPilojilojilojilojilojilojilojilojilojilojilpPilpPilpPilpPilpPilpPilojilojil'
                  'ojilojilpMgICAgIAogICAgICAgICDilpHilpLilpLilpLilpPilojilojilojilojilojilojilojilpPilpLilpLilpLilpLi'
                  'lpLilpIgICAgICAg4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paT4paT4paI4paI4paI4paI4paI4paI4paI4paI4pa'
                  'I4paI4paI4paI4paT4paT4paT4paT4paT4paT4paT4paI4paI4paI4paI4paI4paTICAgICAKICAgICDilpLilpLilpLilpLilp'
                  'LilpLilpLilpLilojilojilpPilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpIgI'
                  'OKWkuKWkuKWkuKWkuKWk+KWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWk+KW'
                  'k+KWk+KWk+KWk+KWk+KWiOKWiOKWiOKWk+KWk+KWk+KWkyAgICAgCiDilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpL'
                  'ilpLilpPilpPilpPilpLilpLilpPilpLilpLilpPilpLilpPilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilp'
                  'LilpPilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilpPilpPilpPilpPil'
                  'pPilpPilpPilpPilpPilpPilpPilpPilojilojilojiloggICAgCuKWkeKWkeKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKW'
                  'kuKWkuKWk+KWk+KWk+KWkuKWkuKWk+KWkuKWkuKWk+KWk+KWk+KWkuKWk+KWiOKWk+KWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuK'
                  'WiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWk+KWk+KWk+KWk+KWk+'
                  'KWk+KWiOKWk+KWk+KWk+KWk+KWk+KWiOKWiOKWiOKWiOKWiOKWiCAgIAogICAg4paR4paR4paS4paS4paS4paS4paS4paS4paS4'
                  'paS4paS4paT4paS4paS4paT4paT4paT4paT4paT4paT4paS4paT4paT4paS4paS4paT4paT4paS4paS4paS4paS4paI4paI4paI'
                  '4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paT4paT4paT4paT4paI4paI4paI4paT4pa'
                  'T4paT4paT4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paIIAogICAgICAg4paR4paR4paR4paS4paS4paS4paS4paS4p'
                  'aS4paS4paT4paT4paT4paS4paS4paT4paT4paT4paT4paS4paS4paS4paS4paS4paS4paS4paS4paS4paI4paI4paI4paI4paI4'
                  'paI4paI4paI4paI4paI4paI4paI4paI4paI4paT4paT4paT4paT4paT4paT4paT4paT4paT4paI4paT4paT4paT4paT4paI4paI'
                  '4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paICiAgICAgICAgICAgIOKWkeKWkeKWkuKWkuKWkuKWkuKWkuKWkuK'
                  'WkuKWk+KWk+KWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkeKWkeKWkuKWkyAgIOKWiOKWiOKWiOKWiOKWiOKWiO'
                  'KWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWi'
                  'OKWiOKWiOKWiOKWiOKWkwogICAgICAgICAgICAgICDilpHilpHilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLi'
                  'lpLilpLilpLilpEgICAgICAgICAg4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4pa'
                  'I4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paTCiAgICAgICAgICAgICAgICAgIOKWkeKWke'
                  'KWkeKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkeKWkSAgICAgICAgICAgICAgICDilojilojilojilojilpPilojilojilojilojil'
                  'ojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilpMKICAgICAgICAg'
                  'ICAgICAgICAgICAgICDilpHilpHilpHilpEgICAgICAgICAgICAgICAgICAgICAgICAgICDilpLilpPilpPilpPilojilojiloj'
                  'ilojilojilojilojilojilojilojilojilojilojilojilojilojilojilojilpMKICAgICAgICAgICAgICAgICAgICAgICAgIC'
                  'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilpLilpPilojilojilojilojilojilojilojilojilojilojilojil'
                  'ojilojilojilojilpMKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
                  'IOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWkyAKICAgICAgICAgICAgICAgICAgICAgICAgICA'
                  'gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilojilojilojilojilojilojilojilojilojilojilojilojilp'
                  'IgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg4paS4paI4paI4'
                  'paI4paI4paI4paI4paI4paI4paI4paI4paSICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
                  'ICAgICAgICAgICAgICAgIOKWkeKWk+KWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWk+KWkuKWkSAgICAgCiAgICAgICAgICAgICA'
                  'gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilpHilpLilojilojilojilojilojilojilpPilp'
                  'LilpEgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg4paS4'
                  'paT4paI4paT4paI4paT4paSICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
                  'ICAgICAgICAgICAgICAg4paT4paT4paT4paT4paRICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICA'
                  'gICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilpPilpLilpIgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgIC'
                  'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg4paR4paRICAgICAgICAgICAgICAK')
    return "\n" + b64decode(random.choice(images)).decode('utf-8')
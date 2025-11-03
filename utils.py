# external module imports
from soupsieve.util import lower

from imports import traceback, os, random, b64decode, sys, signal, get_origin, get_args, textwrap, datetime, json, Any, Path, Text, Union
# get global state objects (CONFIG and TUI)
from globals import get_config, get_tui
CONFIG = get_config()

# ── Config & Logging ────────────────────────────────────────────────
LEVEL_ORDER = ["DEBUG", "INFO", "WARN", "ERROR"]

def load_config(config_path: str | Path = "ghostmerge_config.json"):
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
            log('INFO', f'Loaded config from: {config_path}', prefix="UTILS")
            log('DEBUG', f'Config is now: {json.dumps(user_config, indent=2)}', prefix="UTILS")
            CONFIG.update(user_config)
            CONFIG["config_loaded"] = True
    except FileNotFoundError:
        log('ERROR', f'No config file found at: {config_path}', prefix="UTILS")
    except Exception as e:
        log('ERROR', f"Failed to load config from {config_path}: {e}", prefix="UTILS")

    # do it all again, but with the postfix ".local" so that Git actions don't get grumpy when updating
    try:
        config_path = config_path + '.local'
        with open(config_path, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
            log('INFO', f'Loaded config from: {config_path}', prefix="UTILS")
            log('DEBUG', f'Config is now: {json.dumps(user_config, indent=2)}', prefix="UTILS")
            CONFIG.update(user_config)
            CONFIG["config_loaded"] = True
    except FileNotFoundError:
        log('DEBUG', f'No ".local" config file found at: {config_path}', prefix="UTILS")
    except Exception as e:
        log('ERROR', f"Failed to load config from {config_path}: {e}", prefix="UTILS")


def is_path_writable(path: str) -> bool:
    """Return True if the given file path is writable (or can be created)."""
    if isinstance(path, str):
        path_as_Path = Path(path)
    elif isinstance(path, Path):
        path_as_Path = path
        path = str(Path)
    else:
        # path isn't a path
        return False

    try:
        if path_as_Path.exists() and path_as_Path.is_file():
            # File exists... check write permission
            return os.access(path, os.W_OK)
        else:
            # File doesn't exist... check parent directory permissions
            parent_dir = path_as_Path.parent
            return os.access(parent_dir, os.W_OK)
    except OSError:
        return False

def log(level: str, msg: str, prefix: str = '', exception: Exception = None):
    # set defaults
    TUI = None
    log_to_file = True
    log_file_path = 'ghostmerge.log'
    verbosity_decision_log_enabled = False
    verbosity_default = LEVEL_ORDER.index(CONFIG["log_verbosity"].upper())
    verbosity_subject_key = None
    level = level.upper()
    level_map = {
        "DEBUG": "[dim cyan][DEBUG][/dim cyan]",
        "INFO": "[bold green][INFO ][/bold green]",
        "WARN": "[bold yellow][WARN ][/bold yellow]",
        "ERROR": "[bold red][ERROR][/bold red]",
    }

    try:
        TUI = get_tui()
    except RuntimeError as e:
        if (e != "TUI is not initialised") and (prefix != "TUI"):
            print(f"!!!!!! ERROR !!!!!!    Its all gone wrong:\n"
                  f"LEVEL: {level}\n"
                  f"MESSAGE: {msg}\n"
                  f"PREFIX: {prefix}\n"
                  f"PASSED EXCEPTION: {exception}\n"
                  f"log() FUNCTION EXCEPTION: {e}")
            exit(2)

    if CONFIG["config_loaded"]:
        try:
            verbosity_subject_key = CONFIG["log_verbosity_" + prefix.lower()]
            verbosity = LEVEL_ORDER.index(verbosity_subject_key)
            verbosity_decision_log_enabled = CONFIG["verbosity_decision_log_enabled"]
        except KeyError:
            # If the prefix given isn't in the config, default to the overall verbosity level
            try:
                verbosity_subject_key = CONFIG["log_verbosity"]
                verbosity = LEVEL_ORDER.index(verbosity_subject_key)
            except KeyError:
                # if the overall verbosity level is not in the config, default to DEBUG as something is wrong
                verbosity_subject_key = "DEBUG"
                verbosity = LEVEL_ORDER.index("DEBUG")
            if prefix != '':
                prefix = f"PREFIX not found: {prefix}!"
            else:
                prefix = f"NO PREFIX!"

        try:
            log_to_file = CONFIG["log_file_enabled"]
            log_file_path = CONFIG["log_file_path"]
        except KeyError as e:
            if TUI:
                TUI.update_messages(f'Error getting log file config variables: {e}')
            else:
                print(f'Error getting log file config variables: {e}')
    else:
        # no config yet
        verbosity = verbosity_default

    if verbosity_decision_log_enabled:
        verbosity_decision_msg = (f'\n'
                                  f'Verbosity decision based on:\n'
                                  f'verbosity_overall = {CONFIG["log_verbosity"].upper()} = {verbosity_default}\n'
                                  f'verbosity_subject = {verbosity_subject_key} = {verbosity}\n'
                                  f'message level = {level} = {LEVEL_ORDER.index(level)}\n'
                                  f'decision verbosity = {LEVEL_ORDER[verbosity]} = {verbosity}\n')
        with Path(log_file_path).open("a", encoding="utf-8") as f:
            f.write(verbosity_decision_msg)

    if LEVEL_ORDER.index(level) < verbosity:
        # if the message level is lower than the required level, just return
        return

    # format the exception text for presentation
    if exception:
        exception_text = f"{type(exception).__name__}: {exception}\n{traceback.format_exc()}"
    else:
        exception_text = None

    # prep the log presentation for TUI
    tag = level_map.get(level, "[white][LOG][/white]")
    full_prefix = f"[{prefix.center(11)}] " if prefix else ""
    full_message_rich = f"{tag} {full_prefix}{Text.from_markup(str(msg))}"
    full_message_plain = f"{tag} {full_prefix}{Text(str(msg))}"
    # push message to the TUI

    # do log to file
    if log_to_file and is_path_writable(log_file_path):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        plain_prefix = f"{prefix:<11} " if prefix else ""
        plain_msg = f"{Text.from_markup(str(msg)).plain}"
        file_msg = f"{timestamp} | {level:<5} | {plain_prefix}{plain_msg}\n"
        if exception_text:
            file_msg += exception_text + "\n"
        with Path(log_file_path).open("a", encoding="utf-8") as f:
            f.write(file_msg)

    # if the log includes an exception dump it to terminal
    if TUI:
        TUI.update_messages(full_message_rich)
        if exception:
            TUI.update_messages(f"[red]{exception_text}[/red]")
    else:
        print(f"{full_message_plain}")
        if exception:
            print(f"{exception_text}")


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

def setup_signal_handlers():
    def handle_exit(signum, frame):
        log("WARN", "User interrupt received. Exiting gracefully...", prefix="UTILS")
        sys.exit(1)
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

# ── Data Utilities ──────────────────────────────────────────────────
'''def strip_html(html: str) -> str:
    try:
        text = BeautifulSoup(html, "html.parser").get_text(separator=" ", strip=True)
        log("DEBUG", "HTML stripped successfully", prefix="UTILS")
        return text
    except Exception as e:
        log("ERROR", "HTML stripping failed", prefix="UTILS", exception=e)
        raise
'''

def normalise_tags(tag_str: str) -> list[str]:
    tags = list({tag.strip().lower() for tag in tag_str.replace(',', ' ').split() if tag.strip()})
    log("DEBUG", f"Normalised tags: {tags}", prefix="UTILS")
    return tags

def is_blank(v):
    return (
            v is None
            or (isinstance(v, str) and v.strip() == "")
            or (isinstance(v, (list, dict)) and len(v) == 0)
    )

def blank_for_type(type_name: str):
    type_name = lower(type_name)
    if type_name in ['float','int','str','bool']:
        log('DEBUG', f'Type is {type_name}, returning None', prefix="UTILS")
        return None
    if type_name is 'list':
        log('DEBUG', f'Type is {type_name}, returning []', prefix="UTILS")
        return []
    if type_name is 'dict':
        log('DEBUG', f'Type is {type_name}, returning {{}}', prefix="UTILS")
        return {}
    else:
        log('DEBUG', 'Type not detected returning None', prefix="UTILS")
        return None

def get_type_as_str(t: Any) -> str:
    """
    Return a human-readable name for a typing annotation or runtime type.

    Behavior
    - Union/Optional: returns "A or B" (e.g., Optional[int] -> "int or NoneType").
    - List[T]: returns "List[T]" with T formatted recursively.
    - Dict[K, V]: returns "Dict[K, V]" with K and V formatted recursively.
    - Named/built-in types: uses the type's __name__ (e.g., str -> "str").
    - Fallback: returns str(t) if no clearer representation is available.

    Notes
    - Uses typing.get_origin/get_args and recurses one level for nested composite types.
    - Handles both typing annotations and concrete classes/instances gracefully.
    """

    origin = get_origin(t)
    args = get_args(t)
    log("DEBUG", f'Origin: {origin} | Args: {args}', prefix="UTILS")

    if origin is Union:
        log("DEBUG", 'Union detected', prefix="UTILS")
        # Optional[...] is Union[X, NoneType]
        readable = [get_type_as_str(arg) for arg in args]
        return " or ".join(readable)
    elif origin is list:
        log("DEBUG", 'List detected', prefix="UTILS")
        inner = get_type_as_str(args[0]) if args else "Any"
        return f"List[{inner}]"
    elif origin is dict:
        log("DEBUG", 'Dict detected', prefix="UTILS")
        key_str = get_type_as_str(args[0]) if args else "Any"
        val_str = get_type_as_str(args[1]) if args else "Any"
        return f"Dict[{key_str}, {val_str}]"
    elif hasattr(t, "__type__"):
        log("DEBUG", f'Data\'s type attribute: {t.__type__}', prefix="UTILS")
        return t.__type__
    elif hasattr(t, "__name__"):
        log("DEBUG", f'Data\'s name attribute: {t.__name__}', prefix="UTILS")
        return t.__name__
    elif isinstance(t, type):
        log("DEBUG", 'Data is a type definition', prefix="UTILS")
        return t.__name__
    else:
        log("DEBUG", f'Unable to identify useful type. Full object details: {str(t)}', prefix="UTILS")
        return str(t)

def is_optional_field(expected_type):
    if (('Optional' in get_type_as_str(expected_type)) or
            ('NoneType' in get_type_as_str(expected_type)) or
            ('None' in get_type_as_str(expected_type))):
        is_optional = True
        log('DEBUG', 'Optional field detected', prefix="MODEL")
    else:
        is_optional = False
        log('DEBUG', 'Mandated field detected', prefix="MODEL")
    return is_optional

def stringify_field(value: Any) -> str:
    if isinstance(value, dict):
        return dumps(value, indent=2, sort_keys=True)
    elif isinstance(value, list):
        return "\n".join(map(str, value))
    return str(value or "")

def wrap_string(input: str, width: int) -> str:
    return "\n".join(
        textwrap.fill(
            line,
            width=width,
            break_long_words=True,
            break_on_hyphens=True,
        ) if line else ""  # preserve blank lines
        for line in input.splitlines()
    )

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
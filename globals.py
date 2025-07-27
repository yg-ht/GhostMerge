__all__ = ["Globals", "get_config", "get_tui", "set_tui"]

class Globals:
    _CONFIG = {
        "config_loaded": False,
        "log_verbosity": "INFO",
        "log_file_path": "ghostmerge.log",
        "tui_refresh_rate": 0.1,
    }
    _TUI = None

    @classmethod
    def get_config(cls):
        if cls._CONFIG is None:
            raise RuntimeError("CONFIG is not initialised")
        return cls._CONFIG

    @classmethod
    def set_tui(cls, tui):
        if cls._TUI is not None:
            raise RuntimeError("TUI is already set")
        cls._TUI = tui

    @classmethod
    def get_tui(cls):
        if cls._TUI is None:
            raise RuntimeError("TUI is not initialised")
        return cls._TUI


# Optional: Shortcut functions for convenience
def get_config():
    return Globals.get_config()

def set_tui(tui):
    Globals.set_tui(tui)

def get_tui():
    return Globals.get_tui()

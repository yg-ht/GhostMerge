# external module imports
from imports import (difflib, os, subprocess, tempfile, threading, sleep, Console, RenderableType,
                     Layout, Live, Panel, Text, Columns, Any, List, Optional)
# get global state objects (CONFIG and TUI)
from globals import get_config, set_tui
CONFIG = get_config()

# local module imports
from utils import log, get_user_input
from merge import stringify_for_diff

__all__ = ["tui"]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TUI:
    def __init__(self, refresh_rate: float = CONFIG['tui_refresh_rate']):
        log('DEBUG', 'Entered __init__', 'TUI')
        console = Console()
        log('DEBUG', 'Started console', 'TUI')

        # Split the screen into logical sections
        self.layout = Layout(name="root")
        self.layout.split(
            Layout(name="data_viewer", ratio=2),
            Layout(name="messages", size=10),
            Layout(name="user_input", size=10)
        )
        log('DEBUG', 'Split console layout', 'TUI')

        # Optional Live display (None until started)
        self.live: Optional[Live] = None
        self._refresh_rate = refresh_rate
        self._running = False
        self._thread: Optional[threading.Thread] = None
        log('DEBUG', 'Set instance fields', 'TUI')

        # set the global variable
        log('DEBUG', 'Calling set_tui', 'TUI')
        set_tui(self)

    def _render_loop(self):
        with Live(self.layout, refresh_per_second=self._refresh_rate, screen=True) as live:
            self.live = live
            while self._running:
                sleep(0.1)  # loop so that external updates are reflected

    def start(self):
        """Start the live rendering in a background thread."""
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._render_loop, daemon=True)
            self._thread.start()

    def stop(self):
        """Stop the live rendering loop."""
        self._running = False
        if self._thread:
            self._thread.join()

    def update_data(self, text: RenderableType, style: str = "white", title: str = None):
        if title:
            title = f'Data: {title}'
        else:
            title = 'Data'
        self.layout["data_viewer"].update(Panel(text, title=title, style=style))

    def update_messages(self, text: RenderableType, style: str = "white", title: str = None):
        if title:
            title = f'Messages: {title}'
        else:
            title = 'Messages'
        self.layout["messages"].update(Panel(text, title=title, style=style))

    def update_input(self, text: RenderableType, style: str = "white", title: str = None):
        if title:
            title = f'User input: {title}'
        else:
            title = 'User input'
        self.layout["user_input"].update(Panel(text, title=title, style=style))

    def invoke_editor(self, seed_text: str) -> str:
        """Launch ``$EDITOR`` (defaulting to *nano*) seeded with *seed_text*.

        Returns the edited contents with surrounding whitespace stripped.  DEBUG
        logs track the temporary file lifecycle so any residue can be investigated
        if the subprocess crashes.
        """

        chosen_editor: str = os.getenv("EDITOR", "nano")
        log("DEBUG", f"_invoke_editor(): Using editor '{chosen_editor}'", prefix="TUI")

        with tempfile.NamedTemporaryFile(
            "w+", delete=False, suffix=".tmp", encoding="utf-8"
        ) as temporary_file:
            temporary_file.write(seed_text)
            temporary_file.flush()
            temporary_path: str = temporary_file.name

        log("DEBUG", f"invoke_editor(): Temporary file created at {temporary_path}", prefix="TUI")

        edited_text = ""
        try:
            subprocess.call([chosen_editor, temporary_path])  # Blocks until editor exits.
            with open(temporary_path, "r", encoding="utf-8") as opened_file:
                edited_text: str = opened_file.read()
                log("DEBUG", f"invoke_editor(): Edited text length={len(edited_text)}", prefix="TUI")
        except FileNotFoundError as e:
            log("ERROR", f"editor invocation failed: {e}", prefix="TUI")
        finally:
            os.unlink(temporary_path)
            log("DEBUG", f"invoke_editor(): Temporary file {temporary_path} deleted", prefix="TUI")

        return edited_text.strip()

    def render_user_choice(
        self,
        prompt: str,
        options: List[str],
        default: Optional[str] = None,
        title: Optional[str] = "Make a choice"
    ) -> str:
        """
        Display a prompt and capture a user's choice
        Returns the chosen value as lowercase.
        """

        option_characters = [opt[:1] for opt in options]

        # Temporarily pause Live rendering before asking user
        # Show the options in the UI
        option_text = "\n".join(f"[bold]{opt[:1].upper()}{opt[1:]}[/]" for opt in options)
        TUI.update_input(f"{prompt}\n\n{option_text}", title=title)

        if self.live:
            self.live.stop()

        choice = get_user_input(prompt, choices=option_characters, default=default)

        if self.live:
            self.live.start()

        log("INFO", f"User decision required: {prompt}, result: {choice.upper()}")
        return choice


    def render_diff_single_field(self, value_from_side_a: Any, value_from_side_b: Any,
                                 title: Optional[str] = "Field-level diff") -> Columns:
        """Return two side‑by‑side *Panels* that highlight differences.

        Complex structures (``dict``/``list``) are serialised into pretty strings
        before diffing so the user easily sees diff
        """

        log(
            "DEBUG",
            f"Field types: A={type(value_from_side_a)}, B={type(value_from_side_b)}",
            prefix="TUI",
        )

        # Serialise non‑scalar data for human‑readable diff output.
        stringified_a = stringify_for_diff(value_from_side_a)
        stringified_b = stringify_for_diff(value_from_side_b)

        # Build Rich *Text* fragments with colour annotations.
        diff_for_side_a: Text = Text()
        diff_for_side_b: Text = Text()

        for line in difflib.ndiff(
            stringified_a.splitlines(), stringified_b.splitlines()
        ):
            change_code, line_content = line[:2], line[2:]
            if change_code == "- ":  # Present only in A – mark red in A panel.
                diff_for_side_a.append(line_content + "\n", style="bold blue")
            elif change_code == "+ ":  # Present only in B – mark green in B panel.
                diff_for_side_b.append(line_content + "\n", style="bold green")
            else:  # Unchanged or intraline hint – copy to both panels.
                diff_for_side_a.append(line_content + "\n")
                diff_for_side_b.append(line_content + "\n")

        log("DEBUG", "render_diff_single_field construction complete", prefix="TUI")

        field_diff = Columns(
            [
                Panel(diff_for_side_a or Text("<empty>"), title="A", padding=(0, 1)),
                Panel(diff_for_side_b or Text("<empty>"), title="B", padding=(0, 1)),
            ],
            equal=True,
            expand=True,
        )

        self.update_data(field_diff)


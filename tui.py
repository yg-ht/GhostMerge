# external module imports
from imports import (difflib, os, subprocess, tempfile, threading, sleep, Console, RenderableType, readchar,
                     Layout, Live, Panel, Text, Columns, Any, List, Optional)
# get global state objects (CONFIG and TUI)
from globals import get_config, set_tui
CONFIG = get_config()

# local module imports
from utils import log
from merge import stringify_for_diff

__all__ = ["tui"]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TUI:
    def __init__(self, refresh_rate: float = CONFIG['tui_refresh_rate']):
        log('DEBUG', 'Entered __init__', 'TUI')
        self.console = Console()
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
        self._layout_lock = threading.Lock()
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

    def update_data(self, text: RenderableType, style: str = "", title: str = None):
        if title:
            title = f'Data view: {title}'
        else:
            title = 'Data view'
        with self._layout_lock:
            renderable = Text.from_markup(text) if isinstance(text, str) else text
            self.layout["data_viewer"].update(Panel(renderable, title=title, style=style))
            if self.live:
                self.live.refresh()

    def update_messages(self, text: RenderableType, style: str = "", title: str = None):
        if not hasattr(self, "_message_history"):
            self._message_history: list[str] = []
        # Convert renderable to string if necessary for storing in history
        if isinstance(text, Text):
            message_str = text.plain
        else:
            message_str = str(text)
        # Split incoming text into lines, add each separately
        new_lines = message_str.splitlines()
        self._message_history.extend(new_lines)
        # Limit history to the last 8 lines
        self._message_history = self._message_history[-8:]

        # Combine the history for display
        history_text = "\n".join(self._message_history)
        if title:
            title = f'Messages: {title}'
        else:
            title = 'Messages'
        with self._layout_lock:
            renderable = Text.from_markup(history_text)
            self.layout["messages"].update(Panel(renderable, title=title, style=style))
            if self.live:
                self.live.refresh()

    def update_input(self, text: RenderableType, style: str = "", title: str = None):
        if title:
            title = f'User input: {title}'
        else:
            title = 'User input'

        with self._layout_lock:
            renderable = Text.from_markup(text) if isinstance(text, str) else text
            self.console.print(Panel(renderable, title=title, style=style))

            self.layout["user_input"].update(Panel(renderable, title=title, style=style))
            if self.live:
                self.live.refresh()

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
        options: Optional[List[str]] = None,
        default: Optional[str] = None,
        title: Optional[str] = "Make a choice",
        multi_char: bool = False
    ) -> str:
        """
        Display a prompt and capture a user's choice
        Returns the chosen value as lowercase.
        If multi_char is True, allows multi-character input and returns it.
        """

        if default:
            prefix_is_default = '--> '
            prefix_not_default = '    '
        else:
            prefix_is_default = ''
            prefix_not_default = ''

        if options:
            options.insert(0, 'Abort')
        option_text = None
        option_characters = None
        if isinstance(options, List):
            option_characters = [opt[:1] for opt in options]
            # Show the options in the UI
            option_text = "\n\n"
            option_text += "\n".join(
                f"{prefix_is_default if default and opt[:1].lower() == default.lower() else prefix_not_default}"
                f"[bold][{opt[:1].upper()}][/bold]{opt[1:]}"
                for opt in options
            )

        self.update_input(f"{prompt}{option_text}", title=title)

        choice = self.get_user_input(choices=option_characters, default=default, multi_char=multi_char)

        log("DEBUG", f"User decision required: {prompt.strip()}, result: {choice.upper()}", prefix="TUI")

        if choice == 'a':
            log("ERROR", "User aborted.", prefix="TUI")
            exit()

        return choice

    def get_user_input(
        self,
        choices: Optional[list[str] | str],
        default: Optional[str],
        multi_char: bool = False
    ) -> str | bool:
        """
        Gather user input and check it is constrained to a set of single-character choices when specified.
        Returns the selected character as lowercase. If multi_char is True, allows user to input any string.
        """

        if multi_char:
            # Read a string instead of a single char
            buffer = ""
            prompt_text = "Enter value: "
            self.update_input(f"{prompt_text}{buffer}")
            while True:
                ch = readchar()
                if ch in ('\n', '\r'):  # ENTER pressed
                    if buffer == "" and default:
                        return default.lower()
                    return buffer.lower()
                elif ch in ('\x7f', '\b'):  # BACKSPACE on Linux/Unix and Windows
                    buffer = buffer[:-1]
                elif ch == '\x03':  # Ctrl-C to cancel
                    raise KeyboardInterrupt
                else:
                    # Only add printable characters
                    if ch.isprintable():
                        buffer += ch
                self.update_input(f"{prompt_text}{buffer}")
        else:
            if isinstance(choices, str):
                choices = list(choices)
            if isinstance(choices, List):
                choices = [ch.lower() for ch in choices]

            if default:
                default = default.lower()
                if default not in choices:
                    raise log("DEBUG", f"Default choice '{default}' not in choices: {str(choices)}", prefix="TUI")

            while True:
                user_input = readchar().lower()
                if user_input == "" and default:
                    result = default
                    break
                if isinstance(choices, List):
                    if user_input in choices:
                        result = user_input
                        break
                else:
                    result = user_input
                    break

        return result

    def render_diff_single_field(self, value_from_side_left: Any, value_from_side_right: Any,
                                 title: Optional[str] = "Field-level diff") -> Columns:
        """Return two side‑by‑side *Panels* that highlight differences.

        Complex structures (``dict``/``list``) are serialised into pretty strings
        before diffing so the user easily sees diff
        """

        log(
            "DEBUG",
            f"Field types: Left={type(value_from_side_left)}, Right={type(value_from_side_right)}",
            prefix="TUI",
        )

        # Serialise non‑scalar data for human‑readable diff output.
        stringified_left = stringify_for_diff(value_from_side_left)
        stringified_right = stringify_for_diff(value_from_side_right)

        # Build Rich *Text* fragments with colour annotations.
        diff_for_side_left: Text = Text()
        diff_for_side_right: Text = Text()

        for line in difflib.ndiff(
            stringified_left.splitlines(), stringified_right.splitlines()
        ):
            change_code, line_content = line[:2], line[2:]
            if change_code == "- ":  # Present only in A – mark red in A panel.
                diff_for_side_left.append(line_content + "\n", style="bold blue")
            elif change_code == "+ ":  # Present only in B – mark green in B panel.
                diff_for_side_right.append(line_content + "\n", style="bold green")
            else:  # Unchanged or intraline hint – copy to both panels.
                diff_for_side_left.append(line_content + "\n")
                diff_for_side_right.append(line_content + "\n")

        log("DEBUG", "render_diff_single_field construction complete", prefix="TUI")

        field_diff = Columns(
            [
                Panel(diff_for_side_left or Text("<empty>"), title="L", padding=(0, 1)),
                Panel(diff_for_side_right or Text("<empty>"), title="R", padding=(0, 1)),
            ],
            equal=True,
            expand=True,
        )

        self.update_data(field_diff)


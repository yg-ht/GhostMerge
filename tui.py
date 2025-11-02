# external module imports
import dataclasses

import model
from imports import (difflib, os, subprocess, tempfile, threading, sleep, Console, RenderableType, readchar, re,
                     Layout, Live, Panel, Text, Table, Columns, Any, List, Optional, MarkupError, Tuple, Dict)
# get global state objects (CONFIG and TUI)
from globals import get_config, set_tui
from model import get_type_as_str

CONFIG = get_config()

# local module imports
from utils import log, blank_for_type, stringify_field, wrap_string

__all__ = ["tui"]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TUI:
    def __init__(self, refresh_rate: float = CONFIG['tui_refresh_rate']):
        log('DEBUG', 'Entered __init__', 'TUI')
        self.console = Console()
        log('DEBUG', 'Started console', 'TUI')

        self.num_lines_messages = 10
        self.num_lines_input = 10

        # Split the screen into logical sections
        self.layout = Layout(name="root")
        self.layout.split(
            Layout(name="data_viewer", ratio=2),
            Layout(name="messages", size=self.num_lines_messages + 2),
            Layout(name="user_input", size=self.num_lines_input + 2)
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

    def resize_splits(self):
        # Split the screen into logical sections
        log('DEBUG', 'Unspliting console layout', 'TUI')
        self.layout.unsplit()
        self.layout.split(
            Layout(name="data_viewer", ratio=2),
            Layout(name="messages", size=CONFIG['num_lines_messages'] + 2),
            Layout(name="user_input", size=CONFIG['num_lines_input'] + 2)
        )
        log('DEBUG', 'Resplit console layout', 'TUI')


    def _render_loop(self):
        with Live(self.layout, refresh_per_second=self._refresh_rate, screen=False) as live:
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

    def blank_data(self):
        self.update_data('')

    def blank_input(self):
        self.update_input('')

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
        # Limit history to the last X lines
        self._message_history = self._message_history[-self.num_lines_messages:]

        # Combine the history for display
        history_text = "\n".join(self._message_history)
        if title:
            title = f'Messages: {title}'
        else:
            title = 'Messages'
        with self._layout_lock:
            try:
                renderable = Text.from_markup(history_text)
                self.layout["messages"].update(Panel(renderable, title=title, style=style))
                if self.live:
                    self.live.refresh()
            except MarkupError:
                log('WARN', 'MarkupError detected:')
                renderable = Text(history_text)
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
        options: Optional[List[str]] = [],
        default: Optional[str] = None,
        title: Optional[str] = "Make a choice",
        multi_char: bool = False,
        is_optional: bool = False

    ) -> str:
        """
        Display a prompt and capture a user's choice
        Returns the chosen value as lowercase.
        If multi_char is True, allows multi-character input and returns it.
        """

        if options:
            duplicate_options_check = []
            for option in options:
                duplicate_options_check.append(option[0].lower())
            if len(duplicate_options_check) > len(options):
                log('ERROR', 'Duplicate options detected, cannot proceed', "TUI")

        if default:
            log("DEBUG", "Default detected, setting display marker", prefix="TUI")
            prefix_is_default = '--> '
            prefix_not_default = '    '
        else:
            log("DEBUG", "No default detected", prefix="TUI")
            prefix_is_default = ''
            prefix_not_default = ''

        if not options and not is_optional and not multi_char:
            log("DEBUG", "No options provided, not an optional field, not multi_char", prefix="TUI")
            options = []
            options.append('Press "enter" or "space" to continue...')
            default = 'p'
        if options:
            log("DEBUG", "User options detected, adding 'Abort'", prefix="TUI")
            options.insert(0, 'Abort')
        if options and is_optional:
            log("DEBUG", "User options detected and is_optional, adding 'Blank'", prefix="TUI")
            options.insert(1, 'Blank')
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

        if choice == 'a' and not multi_char and options:
            log("ERROR", "User aborted.", prefix="TUI")
            exit()

        self.blank_input()
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

        log("DEBUG", f"User choices are: {str(choices)}", prefix="TUI")
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
                    log("WARN", f"Default choice '{default}' not in choices: {str(choices)}", prefix="TUI")

            while True:
                user_input = readchar().lower()
                log("DEBUG", f"User input detected: {user_input}", prefix="TUI")
                if user_input.strip() == "" and default:
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

    def render_left_and_right_record(self, finding_record: Tuple[model.Finding, model.Finding, float], differences: str = ''):
        left_right_table: Table = Table(
            title="Merged Finding", box=None, show_lines=False
        )
        left_right_table.add_column("Field Name", style="bold white")
        left_right_table.add_column("Left Value", overflow="fold")
        left_right_table.add_column("Right Value", overflow="fold")
        left_record = finding_record['left']
        right_record = finding_record['right']
        score = finding_record['score']
        log('INFO', f'These two records have a {score}% match', prefix='TUI')
        for field in dataclasses.fields(model.Finding):
            left_value = str(getattr(left_record, field.name, blank_for_type(get_type_as_str(field.type))))
            right_value = str(getattr(right_record, field.name, blank_for_type(get_type_as_str(field.type))))
            log('DEBUG', f'Rendering field {field.name}: {left_value} -> {right_value}', prefix="TUI")
            if field.name in differences:
                field_style ="bold red"
            else:
                field_style = ""
            left_right_table.add_row(str(field.name),left_value,right_value, style=field_style)
        self.update_data(left_right_table, title='Preview')

    def render_single_partial_dict_record(self, finding_record: Dict):
        record_table: Table = Table(
            title="Raw finding from Dict", box=None, show_lines=False
        )
        log('DEBUG', f'Rendering record: {str(finding_record)}', prefix="TUI")
        record_table.add_column("Field Name", style="bold white")
        record_table.add_column("Field Value", overflow="fold")
        for id, field_name in enumerate(finding_record):
            log('DEBUG', f'Rendering field: {str(field_name)} with value: {str(finding_record[field_name])}', prefix="TUI")
            record_table.add_row(str(field_name), str(finding_record[field_name]))
        self.update_data(record_table, title='Preview')

    def render_single_whole_finding_record(self, finding_record: model.Finding, highlight_value: str = None):
        record_table: Table = Table(
            title="Merged Finding (post‑manual)", box=None, show_lines=False
        )
        record_table.add_column("Field Name", style="bold white")
        record_table.add_column("Field Value", overflow="fold")
        for field in dataclasses.fields(model.Finding):
            field_value = str(finding_record.get(field.name) or blank_for_type(get_type_as_str(field.type)))
            log('DEBUG', f'Rendering field {field.name}: {field_value}', prefix="TUI")
            # style here ####
            if highlight_value:
                field_value.replace(highlight_value,f'[{CONFIG["field_level_diff_highlight_style"]}]'
                                                    f'{highlight_value}[/{CONFIG["field_level_diff_highlight_style"]}]')
            record_table.add_row(str(field.name), field_value)
        self.update_data(record_table, title='Preview')

    def render_diff_single_field(self, value_from_left: Any, value_from_right: Any, auto_value: Optional[Any] = None,
                                 title: Optional[str] = "Field-level diff"):
        """Return two or three columns for side‑by‑side rendering in a Panel, highlighting differences in two fields.

        Complex structures are serialised into strings before diffing so the user easily sees diff
        """

        log(
            "DEBUG",
            f"Field types: Left={type(value_from_left)}, Right={type(value_from_right)}, Auto={auto_value}, Title={title}",
            prefix="TUI",
        )

        # Serialise non‑scalar data for human‑readable diff output.
        if CONFIG['field_level_diff_max_width'] > 0:
            stringified_left = wrap_string(stringify_field(value_from_left), CONFIG['field_level_diff_max_width'])
            stringified_right = wrap_string(stringify_field(value_from_right), CONFIG['field_level_diff_max_width'])
            stringified_auto = wrap_string(stringify_field(auto_value), CONFIG['field_level_diff_max_width'])
        else:
            stringified_left = stringify_field(value_from_left)
            stringified_right = stringify_field(value_from_right)
            stringified_auto = stringify_field(auto_value)
        log('DEBUG', f'Top and tail of stringified left: {stringified_left[20:]}...{stringified_left[:20]}', prefix="TUI")
        log('DEBUG', f'Top and tail of stringified right: {stringified_right[20:]}...{stringified_right[:20]}', prefix="TUI")
        log('DEBUG', f'Top and tail of stringified auto: {stringified_auto[20:]}...{stringified_auto[:20]}', prefix="TUI")

        # Build Rich *Text* fragments with colour annotations.
        diff_for_side_left: Text = Text()
        diff_for_side_right: Text = Text()

        previous_change_code = None
        for line in difflib.ndiff(stringified_left.splitlines(), stringified_right.splitlines()):
            change_code, line_content = line[:2], line[2:]
            log('DEBUG', f'Current line change_code: {change_code}', prefix="TUI")
            if change_code == "- ":  # Present only in Left – mark blue in Left panel.
                log('DEBUG', f'Line is only in left: {line_content[10:]}', prefix="TUI")
                diff_for_side_left.append(line_content + "\n", style=CONFIG['field_level_diff_highlight_style'])
            elif change_code == "+ ":  # Present only in Right – mark blue in Right panel.
                log('DEBUG', f'Line is only in right: {line_content[10:]}', prefix="TUI")
                diff_for_side_right.append(line_content + "\n", style=CONFIG['field_level_diff_highlight_style'])
            elif change_code == "? ":
                log('DEBUG', 'Line is a user hint (aka intra-line)', prefix="TUI")
                if previous_change_code == "- ":
                    diff_for_side_left.append(line_content)
                elif previous_change_code == "+ ":
                    diff_for_side_right.append(line_content)
                else:
                    log('ERROR', f'Unexpected previous change code in render_diff_single_field: "{previous_change_code}"', prefix="TUI")
            else:  # Unchanged – copy to both panels.
                log('DEBUG', f'Line is in both: {line_content[:10]}', prefix="TUI")
                diff_for_side_left.append(line_content + "\n", style=CONFIG['field_level_diff_nolight_style'])
                diff_for_side_right.append(line_content + "\n", style=CONFIG['field_level_diff_nolight_style'])
            previous_change_code = change_code

        log("DEBUG", f"render_diff_single_field construction complete", prefix="TUI")

        if auto_value is not None:
            field_diff = Columns(
                [
                    Panel(diff_for_side_left, title="Left", padding=(0, 1)),
                    Panel(diff_for_side_right, title="Right", padding=(0, 1)),
                    Panel(stringified_auto, title="Offered resolution", padding=(0, 1)),
                ],
                equal=True,
                expand=True,
            )
        else:
            field_diff = Columns(
                [
                    Panel(diff_for_side_left, title="Left", padding=(0, 1)),
                    Panel(diff_for_side_right, title="Right", padding=(0, 1)),
                ],
                equal=True,
                expand=True,
            )

        self.update_data(field_diff, title=title)


# ── Future compatibility ─────────────────────────────────────────────
from __future__ import annotations

# ── Standard library ────────────────────────────────────────────────
import ast
import datetime
import difflib
import json
import os
import random
import re
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import traceback
from base64 import b64decode
from dataclasses import dataclass, field, fields
from pathlib import Path
from time import sleep

# ── Third-party libraries ───────────────────────────────────────────
from readchar import readchar
from bs4 import BeautifulSoup
from json import dumps
from rapidfuzz import fuzz
from typing import Any, Dict, List, Tuple, Optional, Union, get_origin, get_args, get_type_hints

# ── Interface related ────────────────────────────────────────────────
import typer
from rich.columns import Columns
from rich.console import Console, RenderableType
from rich.errors import MarkupError
from rich.layout import Layout
from rich.markup import escape
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

__all__ = [
    # ── Standard library ──
    "ast",
    "b64decode",
    "dataclass",
    "datetime",
    "difflib",
    "dumps",
    "field",
    "fields",
    "json",
    "os",
    "Path",
    "random",
    "re",
    "signal",
    "sleep",
    "subprocess",
    "sys",
    "tempfile",
    "textwrap",
    "threading",
    "traceback",

    # ── Third-party ──
    "Any",
    "BeautifulSoup",
    "Columns",
    "Console",
    "Dict",
    "escape",
    "fuzz",
    "get_origin",
    "get_args",
    "get_type_hints",
    "Layout",
    "List",
    "Live",
    "MarkupError",
    "Optional",
    "Panel",
    "readchar",
    "RenderableType",
    "Table",
    "Text",
    "Tuple",
    "Union",

    # ── CLI / Interface ──
    "typer",
]

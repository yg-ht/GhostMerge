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
import threading
import traceback
from base64 import b64decode
from dataclasses import dataclass, field
from pathlib import Path
from time import sleep

# ── Third-party libraries ───────────────────────────────────────────
from readchar import readchar
from bs4 import BeautifulSoup
from json import dumps
from rapidfuzz import fuzz
from typing import Any, Dict, List, Tuple, Optional, Union, get_origin, get_args

# ── Interface related ────────────────────────────────────────────────
import typer
from rich.columns import Columns
from rich.console import Console, RenderableType
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

__all__ = [
    # ── Standard library ──
    "ast",
    "b64decode",
    "datetime",
    "difflib",
    "json",
    "os",
    "signal",
    "subprocess",
    "sys",
    "tempfile",
    "threading",
    "traceback",
    "Path",
    "random",
    "sleep",
    "dumps",
    "dataclass",
    "field",

    # ── Third-party ──
    "BeautifulSoup",
    "fuzz",
    "Console",
    "RenderableType",
    "readchar",
    "Layout",
    "Live",
    "Panel",
    "Confirm",
    "Prompt",
    "Table",
    "Text",
    "Columns",
    "Any",
    "Dict",
    "List",
    "Tuple",
    "Optional",
    "Union",
    "get_origin",
    "get_args",

    # ── CLI / Interface ──
    "typer",
]

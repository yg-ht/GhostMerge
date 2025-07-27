# ── Future compatibility ─────────────────────────────────────────────
from __future__ import annotations

# ── Standard library ────────────────────────────────────────────────
import ast
import datetime
import difflib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from time import sleep

# ── Third-party libraries ───────────────────────────────────────────
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
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

'''# ── Local project ───────────────────────────────────────────────────
from matching import fuzzy_match_findings
from merge import stringify_for_diff, interactive_merge
from model import Finding
from sensitivity import check_finding_for_sensitivities, load_sensitive_terms
from tui import tui
from utils import load_config, log, load_json, write_json, normalise_tags

    # ── Local project symbols ──
    "load_config",
    "log",
    "load_json",
    "write_json",
    "normalise_tags",
    "Finding",
    "fuzzy_match_findings",
    "interactive_merge",
    "check_finding_for_sensitivities",
    "load_sensitive_terms",
    "stringify_for_diff",

'''

__all__ = [
    # ── Standard library ──
    "ast",
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
    "sleep",
    "dumps",
    "dataclass",
    "field",

    # ── Third-party ──
    "BeautifulSoup",
    "fuzz",
    "Console",
    "RenderableType",
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

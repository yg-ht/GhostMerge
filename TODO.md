# ✅ GhostMerge TODO

## ✔️ Completed Tasks

### 🛠 Project Setup & Infrastructure
- [x] Created CLI entry point using Typer
- [x] Set up centralised config file (`ghostmerge_config.json`)
- [x] Designed and implemented Finding data model
- [x] Built robust validation logic for `Finding.from_dict()`
- [x] Integrated `log()` function with verbosity, exception handling, and file output
- [x] Merged utility modules (`log_utils`, `io_utils`, etc.) into single `utils.py`
- [x] Implemented graceful shutdown with signal handlers
- [x] Built I/O handlers for JSON and CSV
- [x] Added support for tag normalisation and HTML stripping
  - [ ] Consider options for more normalisation - for example, depluralisation 

### 🔍 Matching Engine
- [x] Implemented `score_finding_similarity()` with:
  - [x] Token-based title match
  - [x] Optional description fallback
  - [x] Exact `finding_type` boost
  - [x] Weighted score using config values
- [x] Built `fuzzy_match_findings()` matcher:
  - [x] One-to-one greedy matching
  - [x] Returns match tuples, unmatched A, unmatched B
  - [x] Logs all scoring, skips, and decisions
- [x] Added matching weights to config:
  - [x] `match_weight_title`
  - [x] `match_weight_description`
  - [x] `match_weight_finding_type`

### 🔧 Tooling & Environment
- [x] Generated `requirements.txt` with only external libraries
- [x] Generated reproducible zip bundle of project
- [x] Refactored file imports to centralised `utils`
- [x] Used type guards and defensive parsing on incoming data

## ⏳ In Progress / Next Up

### 🧠 Merge Engine
- [ ] Build merge orchestration logic:
  - [ ] Handle unique-to-A/B detection
  - [ ] Detect and route conflicting records
  - [ ] Maintain original IDs in output
  - [ ] Allow auto-merging of low-risk fields (e.g. tags, references)

### 🖥️ Interactive Merge Flow (TUI)
- [ ] Render side-by-side diffs using `rich`
- [ ] Prompt user per-field to select preferred value
- [ ] Allow manual entry or fallback to `$EDITOR`
- [ ] Support merged record preview before final write

### 🛡️ Sensitive Content Checker
- [x] Load sensitivity list from file
- [x] Scan selected fields (e.g. impact, description)
- [x] Suggest redaction or replacement
- [ ] Allow override per field/output file
- [ ] Redact from A, but retain in B (or vice versa)

### 🧪 Tests & Validation
- [ ] Write unit tests for `Finding.from_dict()`
- [x] Add test fixture files for dummy A/B merges
- [ ] Validate that all fields pass roundtrip merge → output → load

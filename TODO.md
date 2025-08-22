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

### 🧠 Automatic Merge Engine and supporting functions
- [ ] Refactor such that we use "left" and "right" instead of A and B (in progress)
- [ ] Build merge orchestration logic:
  - [ ] Handle unique-to-left/right detection
  - [ ] Detect and route conflicting records
  - [ ] Maintain original IDs in output
  - [ ] Allow auto-merging of low-risk fields (e.g. tags, references)
  - [ ] Start with very high fuzzy matches and iterate down
  
### 🖥️ Interactive Merge Flow (TUI)
- [ ] Render side-by-side diffs
- [ ] Render side-by-side preview before user agrees that fuzzy match is close enough
- [ ] Prompt user per-field to select preferred value
  - [ ] Keep left and right as they are
  - [ ] Use left
  - [ ] Use right
  - [ ] Auto suggested option
  - [ ] Remove value (where appropriate)
  - [ ] Skip whole record
  - [ ] Manual edit
  - [ ] Full editor, not just in-line
- [ ] Expose `match_score` to user before they decide to accept a match
- [ ] Allow user to **reject a match entirely** (not just resolve fields)
- [ ] Prompt user at match-level: "Accept this pairing?" before proceeding to field selection
- [ ] When a match is rejected, **return both findings to unmatched pool**
- [ ] Track and log **rejected matches** for debug use
- [ ] Add logic to optionally **re-process orphans** after all initial matches are reviewed
- [ ] Provide user-facing access to **unmatched A and B findings** after merge
- [ ] Allow user to **manually pair unmatched findings** from side A to B (manual match)
- [ ] Implement config file `threshold` override to adjust sensitivity of fuzzy matching
- [ ] Deal with orphans - those that aren't matched somehow?
- [ ] Support merged record preview before final write 

### 🛡️ Sensitive Content Checker
- [x] Load sensitivity list from file
- [x] Scan selected fields (e.g. impact, description)
- [x] Suggest redaction or replacement
- [ ] Allow override per field/output file
- [ ] Redact from left, but retain in right (or vice versa)
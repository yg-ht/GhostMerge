# GhostMerge TODO

## Project Setup & Infrastructure
- [x] Created CLI entry point using Typer
- [x] Set up centralised config file (`ghostmerge_config.json`)
- [x] Designed and implemented Finding data model
- [x] Built robust validation logic for `Finding.from_dict()`
- [x] Integrated `log()` function with verbosity, exception handling, and file output
- [x] Merged utility modules (`log_utils`, `io_utils`, etc.) into single `utils.py`
- [x] Implemented graceful shutdown with signal handlers
- [x] Built I/O handlers for JSON and CSV
- [x] Added support for tag normalisation and HTML stripping

## Tooling & Environment
- [x] Generated `requirements.txt`
- [x] File imports completed with centralised `utils`
- [x] Type guards and defensive parsing on incoming data

## Matching Engine
- [x] Built `fuzzy_match_findings()` matcher
- [x] Added matching weights to config

## Style normalisation
- [ ] Depluralisation
- [ ] Removal of double spaces
- [ ] Title case normalising
- [ ] Control or advise on use of parenthesis
- [ ] Enforce the presence of reference URLs (configurable)
- [ ] Enforce the presence of compliance references (configurable)
- [ ] Integration with LLM for grammar etc support (configurable)
- [ ] Identify regional use of spellings ("s" vs "z" for example)
- [ ] Alert on long sentences

## Automatic Merge Engine and supporting functions
- [x] Refactor such that we use "left" and "right" instead of A and B (in progress)
- [x] Handle unique-to-left/right detection
- [x] Detect and route conflicting records
- [x] Maintain original IDs in output
- [x] Allow auto-merging of low-risk fields (e.g. tags, references)
- [x] Start with very high fuzzy matches and iterate down
  
## Interactive Merge Flow
- [x] Render side-by-side field-level diffs
- [x] Render side-by-side record-level preview
- [x] Prompt user per-field to select preferred value
- [x] Auto-suggest option development
- [x] Remove value / return blank on optional fields
- [x] Skip whole record
- [x] Manual field-level edit
- [x] Expose `match_score` to user where it is useful information
- [ ] Allow user to reject a match entirely, not just resolve fields
- [ ] When a match is rejected, return both findings to unmatched pool
- [ ] Add logic to optionally re-process orphans after all initial matches are reviewed
- [x] Process unmatched findings after main merge effort completed
- [ ] Allow manual matching of unmatched findings
- [x] Implement config file `threshold` override to adjust sensitivity of fuzzy matching
- [ ] Preview merged record before final write and prompt for acceptance 
- [ ] Improve UX for interactive handling of extra_fields
- [ ] Improve UX for interactive handling of tags

##  Sensitive Content Checker
- [x] Load sensitivity list from file
- [x] Scan selected fields (e.g. impact, description)
- [x] Suggest redaction or replacement
- [x] Allow override per field/output file
- [ ] Redact from left, but retain in right (or vice versa)
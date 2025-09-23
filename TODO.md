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
- [ ] Handle unique-to-left/right detection
- [ ] Detect and route conflicting records
- [ ] Maintain original IDs in output
- [ ] Allow auto-merging of low-risk fields (e.g. tags, references)
- [ ] Start with very high fuzzy matches and iterate down
  
## Interactive Merge Flow
- [ ] Render side-by-side field-level diffs
- [ ] Render side-by-side record-level preview
- [ ] Prompt user per-field to select preferred value
- [ ] Auto-suggest option development
- [ ] Remove value / return blank on optional fields
- [ ] Skip whole record
- [ ] Manual field-level edit
- [ ] Expose `match_score` to user where it is useful information
- [ ] Allow user to reject a match entirely, not just resolve fields
- [ ] When a match is rejected, return both findings to unmatched pool
- [ ] Add logic to optionally re-process orphans after all initial matches are reviewed
- [ ] Process unmatched findings after main merge effort completed
- [ ] Allow manual matching of unmatched findings
- [x] Implement config file `threshold` override to adjust sensitivity of fuzzy matching
- [ ] Preview merged record before final write and prompt for acceptance 

##  Sensitive Content Checker
- [x] Load sensitivity list from file
- [x] Scan selected fields (e.g. impact, description)
- [x] Suggest redaction or replacement
- [ ] Allow override per field/output file
- [ ] Redact from left, but retain in right (or vice versa)
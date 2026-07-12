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
- [X] Removal of double spaces
- [ ] Title case normalising
- [ ] Control or advise on use of parenthesis
- [ ] Enforce the presence of reference URLs (configurable)
- [x] Normalise reference field whitespace and duplicate lines
- [ ] Enforce the presence of compliance references (configurable)
- [ ] Integration with LLM for grammar etc support (configurable)
- [ ] Identify regional use of spellings ("s" vs "z" for example)
- [ ] Alert on long sentences
- [x] Normalise line endings
- [x] Remove pointless HTML tags
- [x] Normalise CVSS vector whitespace and metric casing
- [x] Apply matching-only text normalisation for punctuation, case, whitespace, dashes, and quotes
- [x] Sort normalised tags deterministically
- [x] Canonicalise configured HTML cleanup output for stable attributes, classes, and styles

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
- [x] Allow user to reject a match entirely, not just resolve fields
- [x] When a match is rejected, return both findings to unmatched pool
- [x] Add logic to optionally re-process orphans after all initial matches are reviewed
- [x] Process unmatched findings after main merge effort completed
- [ ] Allow manual matching of unmatched findings
- [x] Implement config file `threshold` override to adjust sensitivity of fuzzy matching
- [x] Preview matched records before field-level web review
- [ ] Preview final merged output before final write and prompt for acceptance
- [x] Improve UX for interactive handling of extra_fields with auto-suggestion and placeholder handling
- [x] Improve UX for interactive handling of tags with deterministic combined suggestions
- [x] Pause / resume web merge jobs by persisting and reopening previous jobs
- [ ] Pause / resume CLI merge sessions for large merges
- [ ] Integrate a CVSS checker to check the severity levels match the score / vector
- [x] Normalise CVSS vector formatting before review and sync

## Web Frontend
- [x] Fix web sensitivity review so multiple sensitive terms in the same field are all reviewed.
      `get_next_sensitivity_item()` currently returns only the first hit in a field after advancing
      `sensitivity_field_index`; after the user handles that hit, review resumes at the next field,
      so remaining hits in the same value can be skipped and left in downloaded output.
- [x] Block web finalisation until conflict review is fully complete.
      Direct access to `/jobs/<id>/complete`, or download redirects to completion, can call
      `finalise_job()` before all conflicts are resolved. `finalise_job()` should not serialise
      partial `merged_left`/`merged_right`; it should reject incomplete jobs or drive completion only
      when there are no unresolved conflict review items.

## Ghostwriter API Sync
- [x] Define a standard `extra_fields` timestamp for the last update to each Finding Template.
      Decide the exact key name, timestamp format, and whether GhostMerge or Ghostwriter should be
      authoritative. Once agreed, populate that field during API sync and preserve it through file
      import/export workflows.

##  Sensitive Content Checker
- [x] Load sensitivity list from file
- [x] Scan selected fields (e.g. impact, description)
- [x] Suggest redaction or replacement
- [x] Allow override per field/output file
- [X] Redact from left, but retain in right (or vice versa)

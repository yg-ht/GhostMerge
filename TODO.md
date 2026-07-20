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
- [ ] Close Flask test-client download and static-file responses explicitly.
      The documented `unittest` discovery run passes but emits `ResourceWarning` messages for
      unclosed response file handles in existing web download and static asset tests.

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
- [ ] Normalise evidence placeholders from curly-bracket syntax to the canonical angle-bracket syntax.
      Define the accepted input forms, canonical output, escaping rules, and tests for placeholders
      embedded in plain text and HTML before enabling the transformation.
- [ ] Normalise spans that apply manual black text formatting.
      Identify the editor-generated colour attributes and values, remove only redundant black-text
      styling, and preserve spans whose styling or attributes carry other meaning.
- [ ] Normalise `<span style="background-color: yellow">` markup to the canonical highlight markup,
      including the variant without the currently recognised `highlight` class.
- [ ] Normalise list items containing a single paragraph from `<li><p>…</p></li>` to `<li>…</li>`.
      Preserve paragraph wrappers when a list item contains multiple paragraphs or other meaningful
      sibling content.
- [ ] Normalise line breaks at the ends of HTML tags as well as line breaks between tags.
      Document which whitespace is structural or user-visible so normalisation does not join words
      or alter preformatted/code content.
- [ ] Canonicalise equivalent HTML tag ordering, including sequences such as
      `&gt;<br/></mark></p>`. Define valid target nesting and malformed-input handling before applying
      rewrites so the resulting markup remains semantically equivalent and well formed.
- [ ] Canonicalise an absent or empty compliance reference in `extra_fields` as
      `"compliance_reference": null`. Cover missing keys, empty strings, JSON strings, and nested
      dictionaries without overwriting a populated compliance reference.

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
- [ ] Allow configured fields to auto-accept a substantially longer populated value instead of
      requiring manual review. Start with `extra_fields.ghostpiper_mapping`, make the field names
      configurable, define a conservative length/difference threshold, and retain manual review for
      ambiguous, blank, malformed, or similarly sized values.
- [ ] Define per-field difference metrics using percentage difference and/or changed-character count.
      Determine whether the metrics are display-only or may drive configurable auto-accept rules,
      with safe defaults for short strings, structured fields, and HTML.

## Web Frontend
- [ ] Verify that every required merge stage is complete before presenting a job as completed.
      Define the required stages and ensure the status shown on the home page, job pages, and final
      output cannot report completion while review, sensitivity checks, sync, or another required
      stage remains unfinished.
- [ ] Remove or disable the “Abandon merge” button when a merge job is complete.
      Define the terminal job states consistently and ensure completed output cannot be deleted or
      invalidated through an abandonment action that is no longer applicable.
- [ ] Remove user-facing references to “AzSure”.
      Audit page copy, templates, help text, configuration descriptions, and error messages; replace
      each reference with the intended product or source name without changing compatibility-facing
      identifiers unless separately approved.
- [ ] Review and rename page and section titles so they describe the current workflow consistently.
      Identify every affected title before changing shared terminology, and retain stable routes,
      API fields, and other compatibility-facing identifiers.
- [ ] Rename “Previous merge jobs” to “Merge jobs”.
      Apply the wording consistently to the relevant heading, navigation, and accessible labels
      without changing job filtering or historical-job behaviour.
- [ ] Limit the number of rows shown in home-page tables and add pagination.
      Define a sensible default page size, stable ordering, empty and out-of-range behaviour, and
      accessible previous/next controls while preserving filters and other table state.
- [x] Fix web sensitivity review so multiple sensitive terms in the same field are all reviewed.
      `get_next_sensitivity_item()` currently returns only the first hit in a field after advancing
      `sensitivity_field_index`; after the user handles that hit, review resumes at the next field,
      so remaining hits in the same value can be skipped and left in downloaded output.
- [x] Block web finalisation until conflict review is fully complete.
      Direct access to `/jobs/<id>/complete`, or download redirects to completion, can call
      `finalise_job()` before all conflicts are resolved. `finalise_job()` should not serialise
      partial `merged_left`/`merged_right`; it should reject incomplete jobs or drive completion only
      when there are no unresolved conflict review items.
- [ ] Correct the left/right column titles when API sources are used.
      Display the configured source names and source types consistently so users can tell which API
      or uploaded file each value came from throughout preview, conflict review, and completion.
- [ ] Add an unselect-field control to the record preview so an accidental field choice can be
      cleared before submitting the selected decisions.
- [ ] In “Conflict review - Finding”, allow the user to click the chosen option itself.
      Keep keyboard controls and accessible form semantics, visibly indicate the active choice, and
      ensure clicking an already selected option has predictable behaviour.
- [ ] Provide a safely sanitised rendered HTML view alongside the existing line-by-line diff.
      Make the raw/source view readily available and prevent active content or unsafe links from
      executing in the rendered preview.
- [ ] Add intra-line character highlighting so individual character changes are visible rather than
      marking only complete lines as changed.
- [ ] Improve diff alignment when one side splits or joins lines.
      Avoid treating every following line as changed by using content-aware line alignment before
      applying intra-line character highlighting.
- [ ] Review the left/right colour scheme because the current colours imply misleading semantics.
      Define colours for source identity separately from added/removed/selected state and maintain
      sufficient contrast in dark and light modes.
- [ ] Audit table usage across the web interface and define a consistent approach.
      Decide which data should use semantic tables versus cards or definition lists, then standardise
      headings, responsive behaviour, accessibility, spacing, and actions without a broad rewrite.
- [ ] Rename “Review remaining fields” to “Individual field review” or similarly clear wording that
      accurately describes the next stage, and use the chosen term consistently in help text.

## Ghostwriter API Sync
- [x] Verify that outbound synchronisation behaves consistently for both configured sides.
      Regression coverage proves each side uses only its configured destination and reviewed output,
      preserves existing extra fields while adding `ghostmerge_last_synced_at`, retains verified
      recovery backup details after destructive-stage failures, and rejects duplicate operations.
- [ ] Add observation synchronisation support.
      Define observation matching, field mapping, direction, conflict handling, create/update rules,
      permissions, validation, rate limiting, failure recovery, and backwards compatibility before
      implementing API requests or changing persisted job data.
- [x] Define a standard `extra_fields` timestamp for the last update to each Finding Template.
      Decide the exact key name, timestamp format, and whether GhostMerge or Ghostwriter should be
      authoritative. Once agreed, populate that field during API sync and preserve it through file
      import/export workflows.
- [ ] Confirm whether findings and observations expose a reliable created/updated timestamp in the
      Ghostwriter API and internal data structures. Document its source, timezone, precision, and
      suitability for conflict detection before using it in matching or sync decisions.
- [ ] Design a scheduled job for unattended API operations.
      Define which fetch, merge, backup, or sync action should run; the scheduling mechanism;
      locking and duplicate-run behaviour; credentials handling; retries; logging; and failure alerts
      before implementation.
- [ ] Apply the same configured rate limiting to sync-back requests as the main API fetch/sync path.
      Verify all request routes share throttling, retry, and backoff behaviour without reducing
      protection against duplicate or concurrent sync operations.

##  Sensitive Content Checker
- [x] Load sensitivity list from file
- [x] Scan selected fields (e.g. impact, description)
- [x] Suggest redaction or replacement
- [x] Allow override per field/output file
- [X] Redact from left, but retain in right (or vice versa)

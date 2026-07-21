# GhostMerge TODO

## Completed development: Web and CLI workflow parity

This completed development effort made every shared processing stage explicit, equivalent, and
verifiable in the Web UI. Web-only API and Observation Template features remain supported extensions
rather than being constrained to the CLI feature set.

- [x] Define the shared workflow contract and add a baseline CLI/Web output-equivalence regression.
- [x] Snapshot sensitivity configuration per Web job and apply the CLI-equivalent pre-match pass.
- [x] Add a visible, resumable post-merge sensitivity stage with persisted audit statistics.
- [x] Validate sensitivity decisions against server-derived pending state rather than browser fields.
- [x] Resolve remaining shared-workflow differences in invalid-input handling and interactive mode.
      Include canonical handling of equal blank optional fields: the CLI currently resolves empty
      strings through its offered-value path while the Web service preserves them unchanged.
- [x] Add final output preview and explicit approval before durable output or outbound API sync.
- [x] Complete end-to-end parity, failure-mode, security, and backwards-compatibility regression tests.
- [x] Update operator documentation after the implemented workflow passes final review.
      The README now provides separate CLI and Web operator runbooks, enumerates every visible Web
      review and approval gate, explains resume and failure behaviour, and includes a destructive
      outbound-sync checklist.

## Recently completed priorities

1. **Protect completed merge output from abandonment. (Completed.)** Remove or disable the destructive
   “Abandon merge” action once output is ready, and reject direct abandonment requests for
   completed jobs. This closes the clearest remaining local data-loss path.
2. **Preview and approve final merged output before writing or outbound sync. (Completed.)** Give operators a
   last verification point after all review and sensitivity decisions, before durable output can
   become the source of a destructive API replacement.
3. **Show unambiguous source identity throughout left/right review. (Completed.)** Use configured API names and
   uploaded filenames consistently so an operator cannot mistake which source or destination a
   decision affects.

These selected safety and review-clarity items are complete. Their regression coverage protects
completed output, digest-bound final approval, and source identity throughout the workflow.

## Project Setup & Infrastructure
- [x] Created CLI entry point using Typer
- [x] Set up centralised config file (`ghostmerge_config.json`)
- [x] Designed and implemented Finding data model
- [x] Built robust validation logic for `Finding.from_dict()`
- [x] Integrated `log()` function with verbosity, exception handling, and file output
- [x] Merged utility modules (`log_utils`, `io_utils`, etc.) into single `utils.py`
- [x] Implemented graceful shutdown with signal handlers
- [x] Built JSON I/O handlers
- [ ] Decide whether CSV import or export is required before adding CSV I/O.
      Define the supported record shape, quoting and encoding rules, nested-field representation,
      validation behaviour, and round-trip expectations before implementation.
- [x] Added support for tag normalisation and configured HTML cleanup

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
- [x] Removal of double spaces
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
- [x] Normalise list items containing a single paragraph from `<li><p>…</p></li>` to `<li>…</li>`.
      Single direct paragraph wrappers are removed, while multiple paragraphs and meaningful text
      siblings retain their structure; regression coverage includes both behaviours.
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
- [x] Refactor such that we use "left" and "right" instead of A and B
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
- [x] Allow manual matching of unmatched records.
  - [x] Define the shared validation and match-construction contract for Findings and Observations.
  - [x] Add a persisted, token-bound Web selection stage before unmatched records are copied.
  - [x] Route manually selected pairs through the normal preview and field-review workflow.
  - [x] Add interactive CLI selection for unmatched Findings without changing non-interactive behaviour.
  - [x] Add service, route, CLI, persistence, rejection, and edge-case regression coverage.
  - [x] Document the operator workflow and mark the feature complete after validation.
- [x] Implement config file `threshold` override to adjust sensitivity of fuzzy matching
- [x] Preview matched records before field-level web review
- [x] Preview final merged output before final write and prompt for acceptance
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
- [x] Verify that every required merge stage is complete before presenting a job as completed.
      Inbound API import, merge/output, and outbound API sync now have distinct persisted state.
      Output is ready only after conflict and sensitivity review and durable creation of both JSON
      files. Optional left and right outbound sync states do not block local output completion.
- [x] Remove or disable the “Abandon merge” button when a merge job is complete.
      Define the terminal job states consistently and ensure completed output cannot be deleted or
      invalidated through an abandonment action that is no longer applicable.
- [x] Remove user-facing references to “AzSure”.
      A repository-wide audit found no remaining references outside this historical TODO entry.
- [x] Review and rename page and section titles so they describe the current workflow consistently.
      Identify every affected title before changing shared terminology, and retain stable routes,
      API fields, and other compatibility-facing identifiers.
- [x] Rename “Previous merge jobs” to “Merge jobs”.
      Apply the wording consistently to the relevant heading, navigation, and accessible labels
      without changing job filtering or historical-job behaviour.
- [x] Limit the number of rows shown in home-page history tables.
      Configurable recent-row limits and links to dedicated full-history pages are implemented for
      API source checks and merge jobs.
- [x] Prioritise frequently used home-page sections.
      Merge-job status now appears first, followed by job creation, inbound imports, API source
      checks, and API backups; existing history limits, sorting, and routes are unchanged.
- [ ] Add pagination to the dedicated history pages.
      Define a sensible page size, stable ordering, empty and out-of-range behaviour, and accessible
      previous/next controls while preserving filters and other table state.
- [ ] Clarify the estimated total on the inbound API import status page.
      The fetched count includes Finding and Observation Templates, but the previous-backup estimate
      currently uses only the Finding count. This can produce confusing text such as “Fetched 509
      records of approx 488”. Either display separate Finding and Observation counts, include both in
      the estimate, or label the denominator precisely; retain sensible behaviour for legacy backups
      and unknown estimates.
- [ ] Investigate reducing per-record API requests during inbound API imports.
      Finding and Observation list queries already fetch pages of up to 100 records, but tags are
      retrieved with a follow-up query for each record. Determine whether Ghostwriter GraphQL can
      return tags through relationships or a safe batched query, then assess pagination, memory use,
      rate limiting, progress reporting, cancellation, and backwards compatibility before changing
      the import strategy.
- [x] Fix web sensitivity review so multiple sensitive terms in the same field are all reviewed.
      Review now remains on the current field until every sensitive hit has been handled, preventing
      later terms in the same value from reaching downloaded output without a decision.
- [x] Block web finalisation until conflict review is fully complete.
      Completion routes and output persistence now reject incomplete conflict or sensitivity review,
      and durable output readiness additionally requires both output files.
- [x] Correct the left/right column titles when API sources are used.
      Display the configured source names and source types consistently so users can tell which API
      or uploaded file each value came from throughout preview, conflict review, and completion.
- [ ] Add an unselect-field control to the record preview so an accidental field choice can be
      cleared before submitting the selected decisions.
- [x] Make record-preview value cells clickable when choosing left, right, or offered values.
      The underlying radio controls and keyboard workflow remain intact, and the selected cell is
      visibly highlighted before the choices are submitted.
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
- [x] Rename “Review remaining fields” to “Individual field review” or similarly clear wording that
      accurately describes the next stage, and use the chosen term consistently in help text.

## Ghostwriter API Sync
- [x] Verify that outbound synchronisation behaves consistently for both configured sides.
      Regression coverage proves each side uses only its configured destination and reviewed output,
      preserves existing extra fields while adding `ghostmerge_last_synced_at`, retains verified
      recovery backup details after destructive-stage failures, and rejects duplicate operations.
- [x] Add observation synchronisation support.
      Observation-aware jobs review and write Observation Templates alongside findings. Focused
      bilateral HTTP regression coverage confirms destination isolation, replacement, tags,
      preserved extra fields, and `ghostmerge_last_synced_at`; legacy finding-only jobs retain
      destination observations for backwards compatibility.
- [x] Define a standard `extra_fields` timestamp for the last update to each Finding Template.
      GhostMerge writes the authoritative UTC `ghostmerge_last_synced_at` value during outbound sync
      and preserves it through file import/export workflows.
- [ ] Confirm whether findings and observations expose a reliable created/updated timestamp in the
      Ghostwriter API and internal data structures. Document its source, timezone, precision, and
      suitability for conflict detection before using it in matching or sync decisions.
- [ ] Design a scheduled job for unattended API operations.
      Define which fetch, merge, backup, or sync action should run; the scheduling mechanism;
      locking and duplicate-run behaviour; credentials handling; retries; logging; and failure alerts
      before implementation.
- [x] Apply configured rate limiting to all Ghostwriter GraphQL requests, including outbound sync.
      Fetch, backup, validation, deletion, creation, tagging, and restore use the same rate-limited
      GraphQL client transport.
- [ ] Add bounded retry and backoff behaviour for retryable Ghostwriter API failures.
      Define retryable errors, attempt limits, backoff and jitter, progress reporting, and safe
      behaviour around destructive operations without weakening duplicate-operation locks.

##  Sensitive Content Checker
- [x] Load sensitivity list from file
- [x] Scan selected fields (e.g. impact, description)
- [x] Suggest redaction or replacement
- [x] Allow override per field/output file
- [x] Redact from left, but retain in right (or vice versa)

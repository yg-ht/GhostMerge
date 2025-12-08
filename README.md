# 🧰 GhostMerge

GhostMerge is an interactive bidirectional merge engine for security finding templates from the GhostWriter report writing tool.

It accepts two JSON files, validates and normalises their contents, performs fuzzy matching to identify equivalent findings, guides the user through field-level conflict resolution, applies optional sensitivity scanning, performs deterministic ID renumbering, and finally outputs two aligned, schema-compatible JSON files suitable for ingestion by legacy systems.

GhostMerge is designed for situations where multiple environments produce overlapping, inconsistent, or partially conflicting Finding templates.

---

## Features

The intended process works along these lines:
- Two input json files
- Two output json files
- Data is coerced into proper types and checked against the (inferred) requirements of the data model
- Data is output back into the loose data types that actually get used
- The system fuzzy matches Findings and then presents the user with Finding records that differ
- The records that differ are then interactively processed field-by-field with highlighting to show differences
- Where possible the system makes a guess at which option (Left or Right) would be most likely chosen
- Finding records that are missing from either side are added
- The fields of all records are then checked for sensitive (and other unwanted) terms
- Finally, the `id` for each record is then renumbered such that there are no conflicts

Other features:
- The system logs to file as well as onscreen
- Log verbosity is configured per module within the configuration file
- Strongly typed across all actions to ensure that errors are identified early
- The user can escape the TUI to the default text editor for a single field before returning to the workflow

Detailed configuration options:
- Logging & verbosity
- Sensitivity & content checking
- Matching & scoring
- Output & filenames
- Interaction & mode control
- Severity & filtering
- TUI rendering & layout

---

## 🚀 Usage

Basic invocation:
```bash
python ghostmerge.py -left test_data_left.json -right test_data_right.json
```

---

## 🔍 Configuration

Config is loaded automatically from `ghostmerge_config.json` unless overriden.
Similarly `sensitive_terms.txt` is loaded unless overriden. If there is a `ghostmerge_config.json.local` or 
`sensitive_terms.txt.local` present, these will overwrite their non-`.local` counterparts.

---

## 🧼 Still to Implement

See `TODO.md` for (potentially) upcoming features
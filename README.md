# GhostMerge

GhostMerge is an interactive merge tool for GhostWriter finding and observation template JSON exports.

It compares two template sets, identifies likely matching records, helps the
analyst resolve field-level differences, checks for sensitive terms, renumbers
IDs deterministically, then writes two aligned JSON output files that can be
re-imported into downstream systems.

Use it when two environments, teams, or branches contain overlapping GhostWriter
findings and you need a controlled way to reconcile them without losing useful
content.

## Contents

- [What GhostMerge does](#what-ghostmerge-does)
- [Installation](#installation)
- [Command-line usage](#command-line-usage)
- [Web frontend](#web-frontend)
- [Ghostwriter API sync](#ghostwriter-api-sync)
- [Configuration](#configuration)
- [Input and output formats](#input-and-output-formats)
- [Sensitive terms](#sensitive-terms)
- [Testing](#testing)
- [Deployment](#deployment)
- [Repository layout](#repository-layout)
- [Current limitations](#current-limitations)

## What GhostMerge does

GhostMerge currently supports this workflow:

1. Load two JSON files, two Ghostwriter API sources, or one of each.
2. Validate and normalise GhostWriter-style finding and observation records.
3. Clean common formatting issues, including whitespace, line endings, and empty HTML wrappers.
4. Fuzzy-match likely equivalent findings and observations using weighted fields such as title, type, description, impact, and mitigation where available.
5. Present matched records interactively so the analyst can choose the preferred field values.
6. Append templates that only exist on one side into both outputs.
7. Check fields for configured sensitive terms and allow replacement, editing, or keeping the original value.
8. Renumber template IDs so the final output is deterministic and conflict-safe.
9. Write separate left and right output JSON files.
10. Optionally live-sync reviewed output back to API-backed Ghostwriter sources.

### Shared CLI and Web workflow contract

The CLI and Web UI use different presentation and persistence mechanisms, but their common Finding
workflow is expected to preserve the same processing order and produce equivalent JSON records for
the same inputs, configuration, and analyst decisions:

1. Load configuration and two input record sets.
2. Validate and normalise every accepted record.
3. Load the configured sensitive-term rules once for the operation.
4. When enabled, apply explicit pre-match sensitive-term replacements while deferring flag-only
   terms for analyst review.
5. Run the configured fuzzy-match thresholds in order.
6. Let the analyst accept or reject each proposed record match and resolve its differing fields.
7. Optionally reprocess remaining unmatched records without recreating a rejected pair.
8. Copy records still unmatched on either side into both output sets.
9. Review configured sensitive terms across both merged output sets.
10. Resequence aligned record IDs and serialise both outputs.

A stage that has no findings is still a completed stage. In particular, the Web UI must eventually
show whether sensitivity checking was disabled, failed, found no terms, or required decisions; it
must not silently treat those states as equivalent. Web-only Observation Template processing, API
imports, durable job persistence, output approval, backups, and outbound synchronisation extend this
shared contract.

The parity contract applies to valid Finding inputs and shared configuration. Equal normalised field
values are preserved without passing through conflict suggestions, including equal blank optional
strings. Invalid input and interaction have explicit surface-specific behaviour: the interactive CLI
may correct type mismatches or intentionally skip a record, while the non-interactive CLI and Web UI
fail closed. The Web UI reports the numbered invalid record and never opens a terminal prompt.

## Installation

### Requirements

GhostMerge is a Python tool with an optional Flask web frontend. It has been
written around these dependencies:

- Python 3.10 or later
- Typer
- Rich
- RapidFuzz
- Beautiful Soup
- Soup Sieve
- readchar
- pytest, for the regression suite
- Flask, for the optional web frontend

The project includes `requirements.txt`. Keep dependencies isolated in a virtual
environment rather than installing them into the system Python.

### Virtual environment setup

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Use the project virtual environment for local commands:

```bash
.venv/bin/python ghostmerge.py --help
```

### Pipenv setup

If you prefer Pipenv for local development:

```bash
pipenv install -r requirements.txt
pipenv run python ghostmerge.py --help
```

Do not run `sudo pipenv install`; the systemd installer deliberately ignores
root-owned Pipenv environments under `/root`.

## Command-line usage

### Merge the sample files

Run GhostMerge against the included sample files:

```bash
.venv/bin/python ghostmerge.py \
  --file-left test_data_left.json \
  --file-right test_data_right.json
```

Short options are also available:

```bash
.venv/bin/python ghostmerge.py -l test_data_left.json -r test_data_right.json
```

With Pipenv:

```bash
pipenv run python ghostmerge.py \
  --file-left test_data_left.json \
  --file-right test_data_right.json
```

### Choose output paths

By default, output filenames are generated by appending the value of
`default_output_filename_append` from `ghostmerge_config.json`. The default is
`-out.json`, so `test_data_left.json` becomes `test_data_left-out.json`.

To specify output files explicitly:

```bash
.venv/bin/python ghostmerge.py \
  -l test_data_left.json \
  -r test_data_right.json \
  --out-left merged_left.json \
  --out-right merged_right.json
```

### Use a specific config file

```bash
.venv/bin/python ghostmerge.py \
  -l left.json \
  -r right.json \
  --config ghostmerge_config.json
```

### Interactive controls

GhostMerge uses a terminal user interface. During conflict resolution it presents
candidate values and asks the analyst to choose how to handle them.

The interface supports choosing the left value, choosing the right value,
accepting an offered value where available, merging compatible text fields,
removing optional values, skipping records, and editing a field in the configured
terminal editor before returning to the workflow.

For best results, run GhostMerge in a normal terminal rather than inside a
minimal console pane that does not handle interactive key input well.

When `interactive_mode` is disabled, the CLI does not start the terminal UI or
wait for key input. It automatically accepts deterministic offered conflict and
sensitivity replacements. If a malformed record, a conflict without an offered
value, or a flag-only sensitive term requires analyst judgement, the command
stops without writing outputs and returns a non-zero exit status. Use interactive
mode when those decisions need to be corrected or reviewed in the terminal.

## Web frontend

### Start the web app

GhostMerge includes a small Flask frontend for local browser-based merge review.
It uses the same finding model, matching, sensitivity, and output serialisation
code as the CLI.

From the repository root:

```bash
.venv/bin/python web_app.py
```

Then open the local URL printed by Flask. Uploaded files and in-progress job
state are stored under `ghostmerge_web_jobs/` by default. Treat that directory as
local working data and remove it when old merge jobs are no longer needed.

### Review workflow

The web review flow starts with a whole-record preview for each matched pair,
then moves through field-level conflicts. Differing fields and field-level diffs
are highlighted.

Web uploads always use strict parsing, regardless of the CLI's
`interactive_mode` setting. A malformed Finding or Observation is rejected with
its one-based record number; Web workers never wait on an invisible terminal
correction prompt.

On the whole-record preview page, select any changed fields whose offered values
you want to accept, then apply them in one action. Remaining changed fields stay
in the normal field-by-field review queue.

Decision buttons can be clicked directly, and common CLI-style keyboard
shortcuts are available during review:

```text
Left arrow   use left value
Right arrow  use right value
Up arrow     keep left and right intact
Down arrow   blank optional field or keep sensitivity value
Space        use offered/default value
M            merge left and right text where available
E            focus the custom edit field
```

The home page can start a new merge, reopen previous local jobs, download
completed outputs, and open the API backup browser.

The API source checks and previous merge jobs panes on the home page show a
limited number of recent rows. Use the dedicated `API source checks` and
`Previous merge jobs` links shown under those panes when more rows exist.
Configure the home-page limits with `web_ui.home_api_source_checks_limit` and
`web_ui.home_previous_jobs_limit`; both default to `10`.

### Web access controls

The web frontend is protected by the `web_access` block in
`ghostmerge_config.json`. Source IP restriction and GET API-key authentication
default to enabled; if the block, allowed IP list, or API key is missing, the
application fails closed.

Set `allowed_source_ips` to the direct client IPs or CIDR ranges that may reach
Flask, and set `api_key` to a deployment-specific secret. The key is supplied on
the first GET request with the configured query parameter, for example
`/?api_key=...`; after a valid GET, the Flask session stays authenticated for
later navigation and CSRF-protected form posts.

The source IP check defaults to Flask's direct `request.remote_addr` value. Set
`source_ip_mode` to control which client address source is checked:

| Mode | Behaviour |
| --- | --- |
| `direct` | Check only the directly observed peer address. This is the default. |
| `trusted_header` | Check only `trusted_source_ip_header`, but only when the direct peer is in `trusted_proxy_ips`. |
| `both` | Check the direct peer address and, when the peer is trusted, also check `trusted_source_ip_header`. |

For Caddy or another reverse proxy, add the proxy's direct address or CIDR to
`trusted_proxy_ips` before using a trusted header such as `X-Forwarded-For`.
Header values from untrusted peers are ignored or rejected, depending on the
selected mode, so a client cannot authorise itself by sending a spoofed forwarded
header directly to Flask.

When the web frontend is embedded in another application, keep `allow_framing`
enabled and set `frame_ancestors` to the embedding origin where possible. The
default cross-site iframe cookie settings are `SESSION_COOKIE_SAMESITE=None` and
`SESSION_COOKIE_SECURE=True`, so iframe sessions require HTTPS in normal
browsers.

## Ghostwriter API sync

### API source selection

The web frontend can load the left side, the right side, or both sides directly
from configured Ghostwriter API servers. Configure the relevant side under
`ghostwriter_api.servers`, then choose the API option on the upload page.

Use the home page's API source check buttons to fetch and back up a configured
side before creating a merge job. This confirms GhostMerge can retrieve the
current findings and observations, stores the full backup JSON in the backup browser, and reports
progress on a status page without saving a job. The Create merge job button
still performs the API retrieval automatically for any side set to API.

When a merge job is API-backed, the completion page offers outbound API
synchronisation for that side after conflict review and sensitivity review are
complete and both merged output files have been written successfully.
Left and right write-back use the same workflow but remain independent: each
side uses its own configured endpoint, bearer token, reviewed output, backup
directory, lock, and status. Synchronising one side does not contact or modify
the other side.

### Merge and API operation states

GhostMerge tracks three distinct parts of the workflow:

1. **Inbound API import** retrieves source records used to create a merge job.
2. **Merge/output** covers conflict review, sensitivity review, and durable
   creation of both reviewed JSON outputs. A job is output-ready only when both
   files exist; interrupted or failed writes do not present the job as complete.
3. **Outbound API sync** optionally writes one reviewed output back to its
   corresponding API-backed destination. Left and right outbound states are
   tracked separately, and neither is required for local merged output to be
   complete.

Existing completed jobs created before the output-ready marker was introduced
remain compatible when their saved final records and both output files are
present. Persisted API operation status values are retained for compatibility;
the operation and direction fields distinguish inbound import from outbound
sync.

### Outbound sync behaviour

Outbound sync is destructive. For the selected API-backed side, GhostMerge:

1. Runs a non-destructive GraphQL preflight.
2. Validates the reviewed records can be converted to Ghostwriter API inputs.
3. Writes a local backup of existing target Finding Templates, Observation Templates, and tags.
4. Deletes existing target Finding and Observation Templates.
5. Recreates the reviewed output for both template types.
6. Reapplies tags.

Observation replacement is enabled for observation-aware jobs created from an
API import or the combined `{ "findings": [...], "observations": [...] }` file
format. An explicit empty observation list clears observations at the selected
destination. A legacy finding-list job deliberately leaves destination
observations unchanged; those untouched observations therefore do not receive
a new GhostMerge sync timestamp.

If preflight or record preparation fails, GhostMerge stops before backup,
deletion, or reload. If deletion or reload fails after the backup has been
written, the outbound sync status retains that verified backup path. Use the
backup browser to download the full original dataset, inspect the backup, or
restore individual records.

### Sync metadata

When GhostMerge writes Finding or Observation Templates through outbound API sync, it records the
write timestamp in `extra_fields.ghostmerge_last_synced_at`. GhostMerge is
authoritative for this field. The value is a UTC ISO-8601 timestamp in
`YYYY-MM-DDTHH:MM:SSZ` format. Existing `extra_fields` values are preserved, and
file import/export keeps the field as ordinary `extra_fields` data. The
timestamp is added independently to every template written to either the left
or right Ghostwriter destination.

### API backups and restore

API backups are written under `ghostwriter_api.backup_dir`, which defaults to
`ghostmerge_api_backups`. Backups are stored per side and include raw API records,
normalised records, server name, GraphQL URL, creation timestamp, finding count,
and observation count.

The web frontend includes an API backup browser. It lists available backups,
downloads the full backup JSON, shows normalised findings and observations, and
can restore a selected record to the currently configured matching Ghostwriter
server. The downloaded JSON includes raw and normalised sections for findings and
observations, so the full original dataset remains available even if the
per-record restore workflow is not sufficient. Before restoring a single record,
GhostMerge checks the current server for a matching Finding Template by original
Ghostwriter ID or by exact title and finding type. Observation Templates are
matched by original Ghostwriter ID or exact title. If a match is found, the web
UI asks whether to replace the existing template, add the backup record as a
duplicate, or skip the restore.
Restore refuses to run if the backup's recorded GraphQL URL does not match the
current server configuration.

### Preflight requirements

The configured token must be able to see these GraphQL query fields:

- `finding`
- `findingSeverity`
- `findingType`
- `observation`
- `tags`

It must also be able to see these GraphQL mutation fields:

- `delete_finding_by_pk`
- `insert_finding_one`
- `delete_observation_by_pk`
- `insert_observation_one`
- `setTags`

If any required field is missing, sync stops before backup, deletion, or reload.

## Configuration

### Config files

GhostMerge loads committed defaults from `ghostmerge_config.example.json`, then
loads `ghostmerge_config.json` from the project directory when it exists. The
local config can be sparse: include only the values that need to differ from the
committed defaults. The local config is gitignored so server URLs, web access
keys, and Ghostwriter bearer tokens are not committed.

You can override the config path with `--config`.

If a `.local` version exists, it is loaded last and can override local settings
without changing either the committed defaults or the base local file:

```text
ghostmerge_config.json.local
sensitive_terms.txt.local
```

### Ghostwriter API servers

For Ghostwriter API sync, set each server's `base_url` to the Ghostwriter site
root, for example `https://ghostwriter.example`, and leave `graphql_endpoint` as
`/v1/graphql` unless your deployment exposes GraphQL somewhere else.
`graphql_endpoint` may also be a full URL if needed.

Enable only the sides you intend to use:

```json
{
  "ghostwriter_api": {
    "servers": {
      "left": {
        "enabled": true,
        "name": "Left Ghostwriter",
        "base_url": "https://left-ghostwriter.example",
        "graphql_endpoint": "/v1/graphql",
        "bearer_token": "gwat_replace-with-local-token",
        "rate_limit_per_second": 0.2,
        "verify_tls": true,
        "strict_x509_verification": true
      }
    }
  }
}
```

Set `rate_limit_per_second` per server, or set
`ghostwriter_api.default_rate_limit_per_second`, to control how quickly
GhostMerge sends GraphQL requests. The default is `0.2`, which sends one request
approximately every five seconds. Keep this conservative for production
Ghostwriter instances because full backups also retrieve tags for each finding.

Leave `verify_tls` enabled for normal deployments. If an internal CA chain is
trusted by the operating system but fails with an OpenSSL strict-mode error such
as `Basic Constraints of CA cert not marked critical`, set
`strict_x509_verification` to `false` for that Ghostwriter side. That keeps
normal CA trust and hostname verification enabled while relaxing OpenSSL's
strict X.509 extension checks. Set `verify_tls` to `false` only as a temporary
last resort, because it disables certificate verification entirely.

### GhostWriter API tokens

Ghostwriter authenticates GraphQL requests with `Authorization: Bearer TOKEN`.
Current Ghostwriter releases support short-lived login JWTs, user API tokens with
the `gwat_` prefix, and service tokens with the `gwst_` prefix.

Do not use the GraphQL `login` action for GhostMerge outbound API sync. That action
returns a short-lived user JWT. It is also disabled for accounts that use MFA.

For regular GhostMerge outbound API sync, use a `gwat_` user API token created from the
Ghostwriter profile page's API Tokens card. A user API token inherits the
creating user's current permissions, can have an explicit expiry, can be
revoked, and works for accounts that use MFA. Because GhostMerge can make
global, destructive changes to the template libraries, create the token from a
dedicated Ghostwriter user whose permissions are limited to the environments and
Finding and Observation Template operations GhostMerge genuinely needs.

Ghostwriter also supports `gwst_` service tokens for non-human automation, but
Ghostwriter cannot currently grant a service token all permissions required for
GhostMerge outbound API sync. Do not use a service token for this workflow unless that
limitation changes and the token can be proven to read, delete, create, and tag
Finding and Observation Templates.

Store the generated token in the server's `bearer_token` setting in local
`ghostmerge_config.json` or `ghostmerge_config.json.local`; do not put real
tokens in committed files.

#### Creating a user API token in Ghostwriter

In the Ghostwriter web interface, create a user API token from the API Tokens
card on the user's profile page. This is separate from the GraphQL `login`
mutation, which only creates short-lived JWTs.

1. Sign in as the dedicated Ghostwriter user that should own GhostMerge sync operations.
2. Open that user's profile page.
3. Use the API Tokens card, not the Service Tokens card and not the GraphQL `login` action.
4. Create a new API token for GhostMerge with a descriptive name such as `ghostmerge-live-sync`.
5. Set an expiry that matches your operational policy.
6. Copy the generated `gwat_` token immediately and store it in the relevant server's `bearer_token` setting.
7. Confirm the user account can perform these GraphQL operations for the template libraries:
   `finding`, `findingSeverity`, `findingType`, `observation`, `tags`,
   `delete_finding_by_pk`, `insert_finding_one`, `delete_observation_by_pk`,
   `insert_observation_one`, and `setTags`.
8. Run a GhostMerge API import and then a live-sync preflight against a test
   Ghostwriter environment before using the token against production data.

GhostMerge's preflight catches missing schema visibility before changes begin,
but the final proof is a test sync against non-production template libraries
with the exact user API token and account permissions.

### Web access configuration

For local or proxied web deployments, configure `web_access` with source IP
restrictions, a deployment-specific API key, and proxy settings appropriate to
the deployment. Do not bind Flask to a public interface unless source IP
restriction, API-key authentication, framing policy, and TLS termination have
been reviewed for that deployment.

### Useful configuration areas

Useful configuration areas include:

| Setting area | Purpose |
| --- | --- |
| Logging | Control console and file verbosity per module. |
| Matching | Tune fuzzy match thresholds, field weights, and optional orphan reprocessing. |
| Output | Control default output filename suffixes. |
| Interaction | Enable terminal review; disabled mode accepts deterministic offers and fails closed when analyst judgement is required. |
| Normalisation | Strip whitespace, remove empty HTML tags, normalise line endings, deduplicate references, canonicalise CVSS vectors, and reduce matching-only text noise. |
| Sensitivity checks | Enable term scanning and configure the terms file. |
| Web UI | Limit how many API source checks and previous merge jobs are shown on the home page. |
| Web access | Restrict browser access by source IP, API key, frame policy, and proxy prefix. |
| Ghostwriter API | Configure inbound API sources, outbound sync destinations, tokens, rate limits, TLS, and backups. |
| TUI layout | Tune render width, refresh rate, and display limits. |

`orphan_reprocessing_enabled` defaults to `true`. When enabled, GhostMerge offers
another orphan matching pass after each reviewed match cycle while both sides
still have unmatched records; the user can stop at the prompt.

## Input and output formats

### Input format

Each file-backed input can be either a legacy JSON list of finding records or a
combined template object:

```json
{
  "findings": [],
  "observations": []
}
```

Use the list form for finding-only merges. Use the combined object when the
same job should review and synchronise Observation Templates as well.

Each finding is expected to use the GhostWriter-style fields represented by the
`Finding` model:

```text
id
severity
cvss_score
cvss_vector
finding_type
title
description
impact
mitigation
replication_steps
host_detection_techniques
network_detection_techniques
references
finding_guidance
tags
extra_fields
```

The included `test_data_left.json` and `test_data_right.json` files are useful
minimal examples.

Observation records use the smaller Ghostwriter Observation Template schema:

```text
id
title
description
tags
extra_fields
```

### Extra fields key migration

Finding Template `extra_fields` keys can be migrated during import and API
normalisation. This is intended for Ghostwriter naming changes where only the
custom-field key changes, not the value or the rest of the template record.

The default configuration removes the legacy `extra_` prefix from Finding
Template `extra_fields` keys:

```json
{
  "extra_fields_key_migration_enabled": true,
  "extra_fields_key_migrations": [
    {
      "template_type": "finding",
      "prefix": "extra_",
      "collision": "preserve_existing"
    }
  ]
}
```

For example, `extra_compliance_reference` becomes
`compliance_reference`. The migration is scoped to the top-level
`extra_fields` keys on Finding Templates; ordinary fields and Observation
Template `extra_fields` are not changed by the default rule.

When both old and new keys exist, `preserve_existing` keeps the unprefixed key
and drops the prefixed duplicate.

### Output files

GhostMerge writes two JSON files:

- one aligned output for the left input
- one aligned output for the right input

Matched and resolved findings and observations are written to both outputs.
Records that only existed in one input are appended to both outputs. IDs are
then resequenced independently for each template type so the final files remain
compatible with systems that expect unique sequential template IDs.

## Sensitive terms

Sensitive term checks are configured through `sensitive_terms.txt` by default.

Each non-comment line can either flag a term:

```text
confidential
```

Or provide a suggested replacement:

```text
acme-corp => [REDACTED COMPANY]
```

During processing, GhostMerge scans finding fields for these terms and offers
the analyst a chance to edit, keep, or apply a replacement.

When `sensitivity_check_before_matching` is enabled, both interfaces apply only
rules with explicit replacements before fuzzy matching. Flag-only terms remain
unchanged for the later analyst review. This keeps sensitive names from
artificially reducing a match score while avoiding an automatic deletion where
no replacement was configured.

Each new Web merge job stores the enabled state, normalised rules, configured
source name, and a SHA-256 rules digest with its protected local job data. File
and API-backed jobs therefore continue with the rules they started with even if
the deployment configuration changes while review is in progress. The raw rule
snapshot and merged record content are not rendered in job summaries or logged;
treat the Web job directory as sensitive working data.

After conflict review, the Web UI always displays the post-merge sensitivity
stage. It reports whether checking was disabled, no configured terms were found,
or every detected term received an analyst decision. The audit summary records
start and completion times, the snapshotted rules source and digest, scan totals,
and decision totals without displaying the rule contents. Refreshing or resuming
the page does not repeat the initial scan or inflate those totals.

Merged output remains unavailable until the analyst acknowledges this summary.
If checking is enabled but the configured rules could not be loaded, the stage
fails closed: acknowledgement and output creation remain blocked, and the Web UI
shows a configuration diagnostic. Correct the configuration and start a new job
so it receives a valid immutable rules snapshot.

Each post-merge decision form contains a one-time token tied to the job's current
server-side review cursor. Record identity, side, field, sensitive term, and
offered replacement are derived again from protected job state when the form is
submitted rather than trusted from browser fields. A stale tab, altered token, or
replayed submission is rejected without changing merged content or audit totals;
reload the review page to obtain the current decision.

## Formatting cleanup

Formatting cleanup is configured in `ghostmerge_config.example.json` and local
config overrides. It runs as part of string normalisation before matching,
conflict review, and sensitivity review, so deprecated presentation markup does
not become a review decision.

The default rule rewrites legacy yellow highlight spans:

```html
<span class="highlight" style="background-color: yellow">text</span>
```

to:

```html
<mark>text</mark>
```

Additional cleanup rules can be added with a source tag, required attributes,
and replacement tag:

```json
{
  "formatting_cleanup_enabled": true,
  "formatting_cleanup_rules": [
    {
      "name": "legacy-yellow-highlight-span",
      "tag": "span",
      "attrs": {
        "class": "highlight",
        "style": "background-color: yellow"
      },
      "replacement_tag": "mark"
    },
    {
      "name": "legacy-font-weight-span",
      "action": "unwrap",
      "tag": "span",
      "attrs": {
        "style": "font-weight: 400"
      }
    },
    {
      "name": "legacy-red-span-inside-mark",
      "action": "unwrap",
      "tag": "span",
      "parent_tag": "mark",
      "attrs": {
        "data-color": "#f00",
        "style": "color: #f00"
      }
    },
    {
      "name": "normalise-pre-to-code",
      "tag": "pre",
      "attrs": {},
      "replacement_tag": "code",
      "replacement_attrs": {
        "spellcheck": "false"
      }
    },
    {
      "name": "normalise-code-spellcheck",
      "action": "set_attrs",
      "tag": "code",
      "attrs": {},
      "drop_attrs": ["data-end", "start"],
      "replacement_attrs": {
        "spellcheck": "false"
      }
    }
  ]
}
```

This is separate from sensitive terms. Sensitive terms should be used for
content that needs analyst review, not deterministic HTML formatting rewrites.
Older local sensitive term files that still contain opening HTML tag
replacements are handled safely for backwards compatibility, but new formatting
cleanup should be added here instead.

## Testing

GhostMerge includes a pytest-discoverable regression suite under `tests/`. From
the repository root, run it with the project virtual environment:

```bash
.venv/bin/python -m pytest
```

The tests are written with the standard-library `unittest` API, so they can also
be run without pytest when needed:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

The suite covers CLI-critical behaviours, model coercion, normalisation,
matching, merge helpers, sensitivity helpers, config loading, systemd installer
behaviour, web access controls, API backup handling, and Ghostwriter API sync
safety checks.

## Deployment

### Systemd web service

The repository includes a systemd unit template and installer for running the
Flask web frontend as a system service. Prepare a local config file first:

```bash
printf '{}\n' > ghostmerge_config.json
```

Edit `ghostmerge_config.json` or `ghostmerge_config.json.local` before
installing. These files can contain only deployment-specific overrides. The web
frontend fails closed when required web access values are empty or incomplete,
and deployment secrets such as API keys and Ghostwriter bearer tokens must stay
in local config files.

The installer uses `PROJECT_DIR/.venv` when it already exists. If it does not
exist, the installer tries to discover a Pipenv virtualenv for the project. If
neither contains Flask, a normal installation creates `PROJECT_DIR/.venv` and
installs `requirements.txt` automatically.

Inspect the generated service without writing to systemd:

```bash
./install-systemd-service.sh --dry-run
```

Install the service:

```bash
sudo ./install-systemd-service.sh
```

By default the service binds Flask to `127.0.0.1:5000`, enables the unit at boot,
does not start it immediately, and runs as a dedicated locked `ghostmerge`
system user/group. If the account does not already exist, the installer creates
it without an interactive shell and without creating a home directory.

During installation it checks that this account can read the app/config and
write the project-local job, backup, and log paths used by the current app. The
installer creates those writable paths for the service user without changing
ownership of the whole checkout. Use explicit options when needed:

```bash
sudo ./install-systemd-service.sh \
  --user ghostmerge \
  --group ghostmerge \
  --host 127.0.0.1 \
  --port 5000 \
  --start
```

The installer refuses to configure the service to run as `root`. If your
deployment uses a pre-created account, pass `--no-create-user` to require the
dedicated user and group to exist before installation. If you have checked
filesystem permissions another way, pass `--no-check-access` to skip the
service-user access probe.

To use an existing non-root Pipenv environment instead of the project-local
`.venv`, install dependencies without `sudo` and pass the discovered path:

```bash
pipenv install -r requirements.txt
sudo ./install-systemd-service.sh --venv-dir "$(pipenv --venv)"
```

Operational commands:

```bash
sudo systemctl status ghostmerge-web.service
sudo systemctl restart ghostmerge-web.service
sudo journalctl -u ghostmerge-web.service -f
```

### Caddy reverse proxy

An example Caddy configuration is provided at
`packaging/caddy/Caddyfile.example`. Its purpose is to provide a reviewed
starting point for deployments where one Caddy site serves multiple internal
applications by top-level path, such as `/merge/` for GhostMerge.

Caddy is useful in this layout because it can terminate TLS, keep the GhostMerge
Flask service bound to loopback, provide one public hostname for multiple tools,
and strip the public `/merge` prefix before requests reach Flask. That keeps the
application simple: GhostMerge continues to receive normal internal paths such
as `/`, `/jobs/...`, and `/static/...`, while browsers use the public
`/merge/...` URLs.

For a same-host Caddy deployment, keep the GhostMerge service bound to
`127.0.0.1:5000` and configure `ghostmerge_config.json` along these lines:

```json
{
  "web_access": {
    "source_ip_restriction_enabled": true,
    "allowed_source_ips": ["203.0.113.0/24"],
    "source_ip_mode": "trusted_header",
    "trusted_proxy_ips": ["127.0.0.1"],
    "trusted_source_ip_header": "X-Forwarded-For",
    "reverse_proxy_prefix": "/merge",
    "api_key_auth_enabled": true,
    "api_key_query_param": "api_key",
    "api_key": "replace-with-a-deployment-secret"
  }
}
```

With this proxy layout, users authenticate at
`https://example.com/merge/?api_key=...`. The `reverse_proxy_prefix` setting
makes GhostMerge generate static image, script, form, link, and redirect URLs
under `/merge/...`, while Caddy strips `/merge` before forwarding requests to
Flask.

## Repository layout

```text
ghostmerge.py             CLI entry point
web_app.py                Flask web frontend
web_service.py            Web workflow and job persistence service layer
ghostwriter_api.py        Ghostwriter GraphQL client, API sync, backups, restore helpers
model.py                  Finding and Observation dataclasses, validation, coercion, serialisation
matching.py               Fuzzy matching and scoring logic
merge.py                  Conflict resolution and ID renumbering
tui.py                    Rich-based terminal user interface
sensitivity.py            Sensitive-term scanning and replacement flow
utils.py                  Config, logging, JSON I/O, and normalisation helpers
ghostmerge_config.example.json
                           Example configuration template
sensitive_terms.txt       Example sensitive-term rules
templates/                Flask templates
static/                   Web frontend static assets
packaging/                Deployment packaging examples
tests/                    Regression suite
test_data_left.json       Sample left input
test_data_right.json      Sample right input
TODO.md                   Development backlog
```

## Current limitations

The project is still evolving. Planned or partially implemented areas are
tracked in `TODO.md`, including manual matching of unmatched findings, improved
handling of complex fields, pause and resume for large merges, and CVSS
consistency checks.

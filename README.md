# GhostMerge

GhostMerge is an interactive merge tool for GhostWriter finding-library JSON exports.

It compares two finding sets, identifies likely matching findings, helps the analyst resolve field-level differences, checks for sensitive terms, renumbers IDs deterministically, then writes two aligned JSON output files that can be re-imported into downstream systems.

Use it when two environments, teams, or branches contain overlapping GhostWriter findings and you need a controlled way to reconcile them without losing useful content.

## What GhostMerge does

GhostMerge currently supports this workflow:

1. Load two JSON files containing GhostWriter finding records.
2. Validate and normalise field types.
3. Clean common formatting issues, including whitespace, line endings, and empty HTML wrappers.
4. Fuzzy-match likely equivalent findings using weighted fields such as title, type, description, impact, and mitigation.
5. Present matched records interactively so the analyst can choose the preferred field values.
6. Append findings that only exist on one side into both outputs.
7. Check fields for configured sensitive terms and allow replacement, editing, or keeping the original value.
8. Renumber finding IDs so the final output is deterministic and conflict-safe.
9. Write separate left and right output JSON files.

## Requirements

GhostMerge is a Python command-line tool. It has been written around these dependencies:

- Python 3.10 or later, recommended
- Pipenv, recommended for local development and repeatable installs
- Typer
- Rich
- RapidFuzz
- Beautiful Soup
- readchar
- pytest, for the regression suite
- Flask, for the optional web frontend

The project currently includes `requirements.txt`. If you are setting up the project for regular use, prefer Pipenv so dependencies are isolated from your system Python.

## Quick start with Pipenv

From the repository root:

```bash
pipenv install -r requirements.txt
pipenv run python ghostmerge.py --help
```

## Running tests

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

The suite covers the current CLI-critical behaviours, including model coercion,
normalisation, matching, merge helpers, sensitivity helpers, config loading, and
a non-interactive CLI merge smoke test.

## Web frontend

GhostMerge also includes a small Flask frontend for local browser-based merge
review. It uses the same finding model, matching, sensitivity, and output
serialisation code as the CLI.

From the repository root:

```bash
.venv/bin/python web_app.py
```

Then open the local URL printed by Flask. Uploaded files and in-progress job
state are stored under `ghostmerge_web_jobs/` by default. Treat that directory as
local working data and remove it when old merge jobs are no longer needed.

The web frontend is protected by the `web_access` block in
`ghostmerge_config.json`. Source IP restriction and GET API-key authentication
default to enabled; if the block, allowed IP list, or API key is missing, the
application fails closed. Set `allowed_source_ips` to the direct client IPs or
CIDR ranges that may reach Flask, and set `api_key` to a deployment-specific
secret. The key is supplied on the first GET request with the configured query
parameter, for example `/?api_key=...`; after a valid GET, the Flask session
stays authenticated for later navigation and CSRF-protected form posts.

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
selected mode, so a client cannot authorise itself by sending a spoofed
forwarded header directly to Flask.

When the web frontend is embedded in another application, keep `allow_framing`
enabled and set `frame_ancestors` to the embedding origin where possible. The
default cross-site iframe cookie settings are `SESSION_COOKIE_SAMESITE=None` and
`SESSION_COOKIE_SECURE=True`, so iframe sessions require HTTPS in normal
browsers.

The web review flow starts with a whole-record preview for each matched pair,
then moves through field-level conflicts. Differing fields and field-level diffs
are highlighted. Decision buttons can be clicked directly, and common CLI-style
keyboard shortcuts are available during review:

```text
Left arrow   use left value
Right arrow  use right value
Up arrow     keep left and right intact
Down arrow   blank optional field or keep sensitivity value
Space        use offered/default value
M            merge left and right text where available
E            focus the custom edit field
```

On the whole-record preview page, select any changed fields whose offered values
you want to accept, then apply them in one action. Remaining changed fields stay
in the normal field-by-field review queue. The home page can also start a new
merge or reopen previous local jobs and completed outputs from
`ghostmerge_web_jobs/`.

Run GhostMerge against the included sample files:

```bash
pipenv run python ghostmerge.py \
  --file-left test_data_left.json \
  --file-right test_data_right.json
```

Short options are also available:

```bash
pipenv run python ghostmerge.py -l test_data_left.json -r test_data_right.json
```

By default, output filenames are generated by appending the value of `default_output_filename_append` from `ghostmerge_config.json`. The default is `-out.json`, so `test_data_left.json` becomes `test_data_left-out.json`.

To specify output files explicitly:

```bash
pipenv run python ghostmerge.py \
  -l test_data_left.json \
  -r test_data_right.json \
  --out-left merged_left.json \
  --out-right merged_right.json
```

To use a specific configuration file:

```bash
pipenv run python ghostmerge.py \
  -l left.json \
  -r right.json \
  --config ghostmerge_config.json
```

## Systemd web service

The repository includes a systemd unit template and installer for running the
Flask web frontend as a system service. Prepare the project first:

```bash
cp ghostmerge_config.example.json ghostmerge_config.json
```

Edit `ghostmerge_config.json` before installing. The web frontend fails closed
when `web_access` is missing or incomplete, and deployment secrets such as API
keys and Ghostwriter bearer tokens must stay in local config files.

The installer uses `PROJECT_DIR/.venv` when it already exists. If it does not
exist, the installer tries to discover a Pipenv virtualenv for the project. If
neither contains Flask, a normal installation creates `PROJECT_DIR/.venv` and
installs `requirements.txt` automatically. Do not run `sudo pipenv install`;
that creates a root-owned virtualenv under `/root`, which the dedicated service
user should not depend on and the installer deliberately ignores.

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
it without an interactive shell and without creating a home directory. During
installation it checks that this account can read the app/config and write the
project-local job, backup, and log paths used by the current app. The installer
creates those writable paths for the service user without changing ownership of
the whole checkout. Use explicit options when needed:

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

If exposing the service through a reverse proxy, keep the default loopback bind
where possible and configure `web_access.trusted_proxy_ips`,
`web_access.source_ip_mode`, and `web_access.trusted_source_ip_header` to match
the proxy. Do not bind to a public interface unless the source IP restriction,
API key, framing policy, and TLS termination have been reviewed for that
deployment.

### Caddy reverse proxy

An example Caddy configuration is provided at
`packaging/caddy/Caddyfile.example`. Its purpose is to provide a reviewed
starting point for deployments where one Caddy site serves multiple internal
applications by top-level path, such as `/merge/` for GhostMerge.

Caddy is useful in this layout because it can terminate TLS, keep the
GhostMerge Flask service bound to loopback, provide one public hostname for
multiple tools, and strip the public `/merge` prefix before requests reach
Flask. That keeps the application simple: GhostMerge continues to receive normal
internal paths such as `/`, `/jobs/...`, and `/static/...`, while browsers use
the public `/merge/...` URLs.

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

## Input format

Each input file must be a JSON list of finding records.

Each finding is expected to use the GhostWriter-style fields represented by the `Finding` model:

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

The included `test_data_left.json` and `test_data_right.json` files are useful minimal examples.

## Interactive controls

GhostMerge uses a terminal user interface. During conflict resolution it presents candidate values and asks the analyst to choose how to handle them.

The interface supports choosing the left value, choosing the right value, accepting an offered value where available, merging compatible text fields, removing optional values, skipping records, and editing a field in the configured terminal editor before returning to the workflow.

For best results, run GhostMerge in a normal terminal rather than inside a minimal console pane that does not handle interactive key input well.

## Configuration

GhostMerge loads `ghostmerge_config.json` automatically from the project directory. The repository includes `ghostmerge_config.example.json` as the committed template; copy it to `ghostmerge_config.json` for local use. The local config is gitignored so server URLs and bearer tokens are not committed. You can override the config path with `--config`.

If a `.local` version exists, it is loaded after the base file and can override local settings without changing the committed defaults:

```text
ghostmerge_config.json.local
sensitive_terms.txt.local
```

For Ghostwriter API sync, set each server's `base_url` to the Ghostwriter site root, for example `https://ghostwriter.example`, and leave `graphql_endpoint` as `/v1/graphql` unless your deployment exposes GraphQL somewhere else. `graphql_endpoint` may also be a full URL if needed.

Ghostwriter authenticates GraphQL requests with `Authorization: Bearer TOKEN`.
Current Ghostwriter releases support short-lived login JWTs, user API tokens with
the `gwat_` prefix, and service tokens with the `gwst_` prefix. For GhostMerge
live sync, prefer a `gwat_` user API token created from the Ghostwriter profile
page's API Tokens card. A user API token inherits the creating user's
permissions, can have an explicit expiry, can be revoked, and works for accounts
that use MFA. Store the generated value in the server's `bearer_token` setting
in local `ghostmerge_config.json` or `ghostmerge_config.json.local`; do not put
real tokens in committed files.

Use a `gwst_` service token only when its scoped permissions explicitly allow
all GhostMerge live sync operations. Live sync is destructive: GhostMerge backs
up the target server, deletes existing Finding Templates, then recreates the
reviewed output and tags. Before doing that, GhostMerge runs a non-destructive
GraphQL preflight. The configured token must be able to see the `finding`,
`findingSeverity`, `findingType`, and `tags` query fields and the
`delete_finding_by_pk`, `insert_finding_one`, and `setTags` mutation fields. If
any required field is missing, sync stops before backup, deletion, or reload.

Useful configuration areas include:

| Setting area | Purpose |
| --- | --- |
| Logging | Control console and file verbosity per module. |
| Matching | Tune fuzzy match thresholds and field weights. |
| Output | Control default output filename suffixes. |
| Interaction | Enable or disable interactive handling. |
| Normalisation | Strip whitespace, remove empty HTML tags, and normalise line endings. |
| Sensitivity checks | Enable term scanning and configure the terms file. |
| TUI layout | Tune render width, refresh rate, and display limits. |

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

During processing, GhostMerge scans finding fields for these terms and offers the analyst a chance to edit, keep, or apply a replacement.

## Output

GhostMerge writes two JSON files:

- one aligned output for the left input
- one aligned output for the right input

Matched and resolved findings are written to both outputs. Findings that only existed in one input are appended to both outputs. IDs are then resequenced so the final files remain compatible with systems that expect unique sequential finding IDs.

## Repository layout

```text
ghostmerge.py             CLI entry point
model.py                  Finding dataclass, validation, coercion, serialisation
matching.py               Fuzzy matching and scoring logic
merge.py                  Conflict resolution and ID renumbering
tui.py                    Rich-based terminal user interface
sensitivity.py            Sensitive-term scanning and replacement flow
utils.py                  Config, logging, JSON I/O, and normalisation helpers
ghostmerge_config.example.json
                           Example configuration template
sensitive_terms.txt       Example sensitive-term rules
test_data_left.json       Sample left input
test_data_right.json      Sample right input
TODO.md                   Development backlog
```

## Current limitations

The project is still evolving. Planned or partially implemented areas are tracked in `TODO.md`, including manual matching of unmatched findings, improved handling of complex fields, pause and resume for large merges, and CVSS consistency checks.

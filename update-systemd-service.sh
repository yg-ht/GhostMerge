#!/usr/bin/env bash
set -Eeuo pipefail

# Safely update an existing GhostMerge systemd deployment. The application is
# stopped only after Git, configuration, candidate source and operation-state
# preflights have succeeded.
umask 027

ORIGINAL_PROJECT_DIR="${GHOSTMERGE_UPDATE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SERVICE_NAME="ghostmerge-web"
REPAIR_CURRENT=0
RUN_TESTS=1
DRY_RUN=0
HEALTH_TIMEOUT_SECONDS=30
METADATA_DIR="${GHOSTMERGE_METADATA_DIR:-/etc/ghostmerge}"
SNAPSHOT_PATH="${GHOSTMERGE_UPDATE_SNAPSHOT_PATH:-}"

MAINTENANCE_PATH=""
MAINTENANCE_CREATED=0
STAGING_DIR=""
CANDIDATE_VENV_DIR=""
CANDIDATE_VENV_KEEP=0
UNIT_BACKUP=""
METADATA_BACKUP=""
UNIT_PATH=""
METADATA_PATH=""
PREVIOUS_REVISION=""
TARGET_REVISION=""
SERVICE_WAS_STOPPED=0
UPDATE_STARTED=0
UPDATE_COMPLETED=0
HAD_METADATA=0
CHECKOUT_CHANGED=0

usage() {
    cat <<'USAGE'
Safely update an existing GhostMerge systemd deployment.

Usage:
  sudo ./update-systemd-service.sh [options]

Options:
  --project-dir PATH      Installed Git checkout. Defaults to this script's directory.
  --service-name NAME     Systemd service name without ".service". Defaults to ghostmerge-web.
  --repair-current        Reconcile and verify the current clean revision without fetching Git.
  --skip-tests            Skip the full pytest suite; compile, import and dependency checks still run.
  --health-timeout SEC    Seconds to wait for the local service socket. Defaults to 30.
  --dry-run               Validate the current installation without fetching, stopping or changing it.
  -h, --help              Show this help text.

Normal mode requires a clean branch with an upstream and accepts only a
fast-forward update. Local ghostmerge_config files are validated and preserved;
they are never generated, merged or overwritten by this updater.
USAGE
}

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

validate_plain_token() {
    local label="$1"
    local value="$2"
    [[ -n "${value}" ]] || fail "${label} cannot be empty."
    [[ "${value}" != *[[:space:]]* ]] || fail "${label} must not contain whitespace."
}

validate_service_name() {
    [[ "${SERVICE_NAME}" =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]*$ ]] || \
        fail "--service-name may contain only letters, numbers, dots, underscores, @ and hyphens, and must start with a letter or number."
    [[ "${SERVICE_NAME}" != *.service ]] || fail "--service-name must not include the .service suffix."
}

absolute_path() {
    local path="$1"
    if [[ "${path}" = /* ]]; then
        printf '%s\n' "${path}"
    else
        printf '%s/%s\n' "$(pwd)" "${path}"
    fi
}

parse_args() {
    while (($#)); do
        case "$1" in
            --project-dir)
                [[ $# -ge 2 ]] || fail "--project-dir requires a value."
                ORIGINAL_PROJECT_DIR="$(absolute_path "$2")"
                shift 2
                ;;
            --service-name)
                [[ $# -ge 2 ]] || fail "--service-name requires a value."
                SERVICE_NAME="$2"
                shift 2
                ;;
            --repair-current)
                REPAIR_CURRENT=1
                shift
                ;;
            --skip-tests)
                RUN_TESTS=0
                shift
                ;;
            --health-timeout)
                [[ $# -ge 2 ]] || fail "--health-timeout requires a value."
                HEALTH_TIMEOUT_SECONDS="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fail "Unknown updater option: $1"
                ;;
        esac
    done
}

create_private_snapshot() {
    local snapshot
    if [[ "${GHOSTMERGE_UPDATE_SNAPSHOT:-0}" == "1" || "${DRY_RUN}" -eq 1 ]]; then
        return
    fi
    snapshot="$(mktemp /tmp/ghostmerge-systemd-update.XXXXXX)"
    install -m 0700 -- "$0" "${snapshot}"
    exec env \
        GHOSTMERGE_UPDATE_SNAPSHOT=1 \
        GHOSTMERGE_UPDATE_SNAPSHOT_PATH="${snapshot}" \
        GHOSTMERGE_UPDATE_PROJECT_DIR="${ORIGINAL_PROJECT_DIR}" \
        "${snapshot}" "$@"
}

remove_temporary_files() {
    if [[ -n "${MAINTENANCE_PATH}" && -f "${MAINTENANCE_PATH}" ]]; then
        if [[ "${MAINTENANCE_CREATED}" -eq 1 ]]; then
            rm -f -- "${MAINTENANCE_PATH}"
        fi
    fi
    if [[ -n "${STAGING_DIR}" && -d "${STAGING_DIR}" ]]; then
        rm -rf -- "${STAGING_DIR}"
    fi
    if [[ "${CANDIDATE_VENV_KEEP}" -eq 0 && -n "${CANDIDATE_VENV_DIR}" && \
        -d "${CANDIDATE_VENV_DIR}" && "${CANDIDATE_VENV_DIR}" == */.${SERVICE_NAME}-venv.* ]]; then
        rm -rf -- "${CANDIDATE_VENV_DIR}"
    fi
    if [[ -n "${UNIT_BACKUP}" && -f "${UNIT_BACKUP}" ]]; then
        rm -f -- "${UNIT_BACKUP}"
    fi
    if [[ -n "${METADATA_BACKUP}" && -f "${METADATA_BACKUP}" ]]; then
        rm -f -- "${METADATA_BACKUP}"
    fi
    if [[ -n "${SNAPSHOT_PATH}" && "${SNAPSHOT_PATH}" == /tmp/ghostmerge-systemd-update.* ]]; then
        rm -f -- "${SNAPSHOT_PATH}"
    fi
}

run_as_identity() {
    local identity="$1"
    local identity_home="$2"
    shift 2
    if [[ "${identity}" == "$(id -un)" ]]; then
        env HOME="${identity_home}" USER="${identity}" LOGNAME="${identity}" \
            GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=never "$@"
    else
        runuser --user "${identity}" -- env \
            HOME="${identity_home}" USER="${identity}" LOGNAME="${identity}" \
            GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=never "$@"
    fi
}

run_as_identity_in_dir() {
    local identity="$1"
    local identity_home="$2"
    local working_dir="$3"
    shift 3
    run_as_identity "${identity}" "${identity_home}" sh -c \
        'cd "$1" && shift && exec "$@"' sh "${working_dir}" "$@"
}

run_as_owner() {
    run_as_identity "${APP_OWNER}" "${APP_OWNER_HOME}" "$@"
}

run_as_service() {
    run_as_identity "${SERVICE_USER}" "${SERVICE_USER_HOME}" "$@"
}

run_as_venv_owner() {
    run_as_identity "${VENV_OWNER}" "${VENV_OWNER_HOME}" "$@"
}

run_as_venv_owner_in_dir() {
    local working_dir="$1"
    shift
    run_as_identity_in_dir "${VENV_OWNER}" "${VENV_OWNER_HOME}" "${working_dir}" "$@"
}

validate_installed_unit() {
    [[ -n "${UNIT_PATH}" && -f "${UNIT_PATH}" && ! -L "${UNIT_PATH}" ]] || \
        fail "The installed ${SERVICE_NAME}.service unit is unavailable or unsafe."
    [[ "$(stat -c '%U:%G' "${UNIT_PATH}")" == "root:root" ]] || \
        fail "The installed systemd unit must be owned by root:root."
    [[ -z "$(find "${UNIT_PATH}" -maxdepth 0 -perm /022 -print)" ]] || \
        fail "The installed systemd unit must not be group/other writable."
}

restore_previous_installation() {
    local rollback_failed=0
    local current_revision=""
    set +e
    printf '\nUpdate validation failed; restoring the previous GhostMerge installation.\n' >&2
    if [[ "${SERVICE_WAS_STOPPED}" -eq 1 ]]; then
        systemctl stop "${SERVICE_NAME}.service" || rollback_failed=1
    fi
    if [[ "${CHECKOUT_CHANGED}" -eq 1 && -n "${PREVIOUS_REVISION}" ]]; then
        current_revision="$(run_as_owner git -C "${PROJECT_DIR}" rev-parse HEAD)" || rollback_failed=1
        if [[ "${current_revision}" != "${TARGET_REVISION}" && \
            "${current_revision}" != "${PREVIOUS_REVISION}" ]]; then
            printf 'The checkout revision changed unexpectedly after the update began; refusing to rewrite it.\n' >&2
            rollback_failed=1
        elif [[ -z "$(run_as_owner git -C "${PROJECT_DIR}" status --porcelain --untracked-files=all)" ]]; then
            run_as_owner git -C "${PROJECT_DIR}" reset --hard "${PREVIOUS_REVISION}" || rollback_failed=1
        else
            printf 'The checkout changed unexpectedly after the update began; refusing to discard those changes.\n' >&2
            rollback_failed=1
        fi
    fi
    if [[ -n "${UNIT_BACKUP}" && -f "${UNIT_BACKUP}" && -n "${UNIT_PATH}" ]]; then
        install -m 0644 -o root -g root "${UNIT_BACKUP}" "${UNIT_PATH}" || rollback_failed=1
    fi
    if [[ "${HAD_METADATA}" -eq 1 && -f "${METADATA_BACKUP}" ]]; then
        install -d -m 0755 -o root -g root "${METADATA_DIR}" || rollback_failed=1
        install -m 0644 -o root -g root "${METADATA_BACKUP}" "${METADATA_PATH}" || rollback_failed=1
    elif [[ "${HAD_METADATA}" -eq 0 && -n "${METADATA_PATH}" ]]; then
        rm -f -- "${METADATA_PATH}"
    fi
    systemctl daemon-reload || rollback_failed=1
    if [[ "${MAINTENANCE_CREATED}" -eq 1 && -n "${MAINTENANCE_PATH}" ]]; then
        rm -f -- "${MAINTENANCE_PATH}"
        MAINTENANCE_CREATED=0
    fi
    if [[ "${SERVICE_WAS_STOPPED}" -eq 1 && "${rollback_failed}" -eq 0 ]]; then
        systemctl start "${SERVICE_NAME}.service" || rollback_failed=1
    fi
    if [[ "${rollback_failed}" -eq 0 ]]; then
        printf 'The previous revision and systemd unit were restored and the service was restarted.\n' >&2
    else
        printf 'Automatic rollback was incomplete. Inspect systemctl status %s.service and the checkout immediately.\n' \
            "${SERVICE_NAME}" >&2
    fi
    set -e
}

handle_exit() {
    local status=$?
    trap - EXIT ERR INT TERM
    if [[ "${status}" -ne 0 && "${UPDATE_STARTED}" -eq 1 && "${UPDATE_COMPLETED}" -eq 0 ]]; then
        restore_previous_installation
    fi
    remove_temporary_files
    exit "${status}"
}

validate_required_commands() {
    local command
    for command in bash find flock git install stat systemctl tar timeout; do
        command -v "${command}" >/dev/null 2>&1 || fail "${command} is required to update GhostMerge."
    done
    command -v python3 >/dev/null 2>&1 || fail "python3 is required to update GhostMerge."
}

read_metadata() {
    local metadata_values
    [[ -f "${METADATA_PATH}" && ! -L "${METADATA_PATH}" ]] || return 1
    [[ "$(stat -c '%U:%G:%a' "${METADATA_PATH}")" == "root:root:644" ]] || \
        fail "Deployment metadata must be root:root mode 0644: ${METADATA_PATH}"
    metadata_values="$(python3 -c '
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
keys = ("service_name", "project_dir", "venv_dir", "service_user", "service_group", "host", "port")
values = [data.get(key) for key in keys]
if not all(isinstance(value, str) and value and "\n" not in value for value in values):
    raise SystemExit("invalid deployment metadata")
print("\n".join(values))
' "${METADATA_PATH}")" || fail "Deployment metadata is invalid: ${METADATA_PATH}"
    mapfile -t DEPLOYMENT_VALUES <<<"${metadata_values}"
    [[ "${#DEPLOYMENT_VALUES[@]}" -eq 7 ]] || fail "Deployment metadata is incomplete."
    [[ "${DEPLOYMENT_VALUES[0]}" == "${SERVICE_NAME}" ]] || \
        fail "Deployment metadata belongs to a different service."
    PROJECT_DIR="${DEPLOYMENT_VALUES[1]}"
    VENV_DIR="${DEPLOYMENT_VALUES[2]}"
    SERVICE_USER="${DEPLOYMENT_VALUES[3]}"
    SERVICE_GROUP="${DEPLOYMENT_VALUES[4]}"
    HOST="${DEPLOYMENT_VALUES[5]}"
    PORT="${DEPLOYMENT_VALUES[6]}"
    HAD_METADATA=1
}

read_installed_unit() {
    local parsed_values
    UNIT_PATH="$(systemctl show "${SERVICE_NAME}.service" --property=FragmentPath --value)"
    validate_installed_unit

    PROJECT_DIR="$(systemctl show "${SERVICE_NAME}.service" --property=WorkingDirectory --value)"
    SERVICE_USER="$(systemctl show "${SERVICE_NAME}.service" --property=User --value)"
    SERVICE_GROUP="$(systemctl show "${SERVICE_NAME}.service" --property=Group --value)"
    parsed_values="$(python3 -c '
import pathlib
import shlex
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
entries = [line.removeprefix("ExecStart=") for line in lines if line.startswith("ExecStart=")]
if len(entries) != 1:
    raise SystemExit("expected one ExecStart")
args = shlex.split(entries[0])
venv = str(pathlib.Path(args[0]).resolve().parent.parent)
if "--bind" in args:
    bind = args[args.index("--bind") + 1]
    if bind.startswith("["):
        host, separator, port = bind.rpartition("]:")
        host = host + "]"
    else:
        host, separator, port = bind.rpartition(":")
    if not separator:
        raise SystemExit("invalid Gunicorn bind")
elif "--host" in args and "--port" in args:
    host = args[args.index("--host") + 1]
    port = args[args.index("--port") + 1]
else:
    raise SystemExit("unsupported ExecStart")
print(venv)
print(host)
print(port)
' "${UNIT_PATH}")" || fail "Could not recover deployment settings from ${UNIT_PATH}."
    mapfile -t UNIT_VALUES <<<"${parsed_values}"
    [[ "${#UNIT_VALUES[@]}" -eq 3 ]] || fail "Installed unit settings are incomplete."
    VENV_DIR="${UNIT_VALUES[0]}"
    HOST="${UNIT_VALUES[1]}"
    PORT="${UNIT_VALUES[2]}"
}

resolve_deployment() {
    local metadata_project=""
    local metadata_venv=""
    local metadata_user=""
    local metadata_group=""
    local metadata_host=""
    local metadata_port=""

    METADATA_PATH="${METADATA_DIR}/${SERVICE_NAME}.json"
    if read_metadata; then
        metadata_project="${PROJECT_DIR}"
        metadata_venv="${VENV_DIR}"
        metadata_user="${SERVICE_USER}"
        metadata_group="${SERVICE_GROUP}"
        metadata_host="${HOST}"
        metadata_port="${PORT}"
    fi
    read_installed_unit
    if [[ "${HAD_METADATA}" -eq 1 ]]; then
        [[ "${PROJECT_DIR}" == "${metadata_project}" && "${VENV_DIR}" == "${metadata_venv}" && \
            "${SERVICE_USER}" == "${metadata_user}" && "${SERVICE_GROUP}" == "${metadata_group}" && \
            "${HOST}" == "${metadata_host}" && "${PORT}" == "${metadata_port}" ]] || \
            fail "Deployment metadata does not match the installed systemd unit. Re-run the installer deliberately before updating."
    fi

    PROJECT_DIR="$(absolute_path "${PROJECT_DIR}")"
    VENV_DIR="$(absolute_path "${VENV_DIR}")"
    [[ "${PROJECT_DIR}" == "$(absolute_path "${ORIGINAL_PROJECT_DIR}")" ]] || \
        fail "Updater checkout ${ORIGINAL_PROJECT_DIR} does not match installed project ${PROJECT_DIR}."
    validate_plain_token "service name" "${SERVICE_NAME}"
    validate_plain_token "service user" "${SERVICE_USER}"
    validate_plain_token "service group" "${SERVICE_GROUP}"
    validate_plain_token "bind address" "${HOST}"
    [[ "${PROJECT_DIR}" != *[[:space:]]* ]] || fail "Installed project path must not contain whitespace."
    [[ "${VENV_DIR}" != *[[:space:]]* ]] || fail "Installed virtualenv path must not contain whitespace."
    [[ "${PORT}" =~ ^[0-9]+$ ]] && ((PORT >= 1 && PORT <= 65535)) || \
        fail "Installed service port is invalid."
    [[ -d "${PROJECT_DIR}/.git" ]] || fail "Installed project is not a Git checkout: ${PROJECT_DIR}"
    [[ -x "${VENV_DIR}/bin/python" ]] || fail "Installed virtual environment is unavailable: ${VENV_DIR}"
    [[ -x "${PROJECT_DIR}/install-systemd-service.sh" ]] || fail "Systemd installer is unavailable."
    [[ -f "${PROJECT_DIR}/requirements.txt" ]] || fail "requirements.txt is unavailable."
    [[ -f "${PROJECT_DIR}/ghostmerge_config.json" ]] || fail "ghostmerge_config.json is required."
    id -u "${SERVICE_USER}" >/dev/null 2>&1 || fail "Service user does not exist: ${SERVICE_USER}"
    getent group "${SERVICE_GROUP}" >/dev/null || fail "Service group does not exist: ${SERVICE_GROUP}"

    APP_OWNER="$(stat -c '%U' "${PROJECT_DIR}")"
    id -u "${APP_OWNER}" >/dev/null 2>&1 || fail "Checkout owner does not resolve to a local user."
    VENV_OWNER="$(stat -c '%U' "${VENV_DIR}")"
    id -u "${VENV_OWNER}" >/dev/null 2>&1 || fail "Virtualenv owner does not resolve to a local user."
    for identity in "${APP_OWNER}" "${SERVICE_USER}" "${VENV_OWNER}"; do
        if [[ "${identity}" != "$(id -un)" ]]; then
            command -v runuser >/dev/null 2>&1 || fail "runuser is required to use deployment identity ${identity}."
        fi
    done
    if [[ -n "$(find "${VENV_DIR}" -maxdepth 0 -perm /002 -print)" ]]; then
        fail "Installed virtualenv must not be writable by other users: ${VENV_DIR}"
    fi
    IFS=: read -r _ _ _ _ _ APP_OWNER_HOME _ < <(getent passwd "${APP_OWNER}")
    IFS=: read -r _ _ _ _ _ SERVICE_USER_HOME _ < <(getent passwd "${SERVICE_USER}")
    IFS=: read -r _ _ _ _ _ VENV_OWNER_HOME _ < <(getent passwd "${VENV_OWNER}")
    [[ -n "${APP_OWNER_HOME}" ]] || fail "Checkout owner has no configured home directory."
    [[ -n "${SERVICE_USER_HOME}" ]] || fail "Service user has no configured home directory."
    [[ -n "${VENV_OWNER_HOME}" ]] || fail "Virtualenv owner has no configured home directory."
}

validate_clean_checkout() {
    [[ -z "$(run_as_owner git -C "${PROJECT_DIR}" status --porcelain --untracked-files=all)" ]] || \
        fail "The GhostMerge checkout has uncommitted or untracked changes. No update was attempted."
    run_as_owner git -C "${PROJECT_DIR}" symbolic-ref --quiet HEAD >/dev/null || \
        fail "The GhostMerge checkout has a detached HEAD."
}

validate_json_configs() {
    run_as_service "${VENV_DIR}/bin/python" -c '
import json
import pathlib
import sys

for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise SystemExit(f"Configuration root must be an object: {path}")
' "${PROJECT_DIR}/ghostmerge_config.example.json" \
        "${PROJECT_DIR}/ghostmerge_config.json" \
        "${PROJECT_DIR}/ghostmerge_config.json.local"
}

candidate_preflight() {
    local target_revision="$1"
    STAGING_DIR="$(mktemp -d /tmp/ghostmerge-update-candidate.XXXXXX)"
    run_as_owner git -C "${PROJECT_DIR}" archive "${target_revision}" | tar -x -C "${STAGING_DIR}"
    [[ -f "${STAGING_DIR}/requirements.txt" ]] || fail "Candidate revision has no requirements.txt."
    [[ -f "${STAGING_DIR}/packaging/systemd/ghostmerge-web.service" ]] || \
        fail "Candidate revision has no systemd unit template."
    [[ -x "${STAGING_DIR}/install-systemd-service.sh" ]] || \
        fail "Candidate revision has no executable systemd installer."
    [[ -x "${STAGING_DIR}/update-systemd-service.sh" ]] || \
        fail "Candidate revision has no executable systemd updater."
    bash -n "${STAGING_DIR}/install-systemd-service.sh"
    bash -n "${STAGING_DIR}/update-systemd-service.sh"
    python3 -c '
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
with (root / "ghostmerge_config.example.json").open("r", encoding="utf-8") as handle:
    value = json.load(handle)
if not isinstance(value, dict):
    raise SystemExit("Default configuration root must be an object")
for path in root.rglob("*.py"):
    compile(path.read_text(encoding="utf-8"), str(path), "exec")
' "${STAGING_DIR}"
    chmod -R a+rX "${STAGING_DIR}"
}

prepare_candidate_runtime() {
    local venv_parent
    venv_parent="$(dirname "${VENV_DIR}")"
    CANDIDATE_VENV_DIR="$(run_as_venv_owner mktemp -d \
        "${venv_parent}/.${SERVICE_NAME}-venv.XXXXXX")"
    if ! run_as_venv_owner "${VENV_DIR}/bin/python" -m venv "${CANDIDATE_VENV_DIR}"; then
        fail "Could not create the candidate virtualenv. Install Python venv support for the deployment interpreter and retry."
    fi
    chmod 0755 "${CANDIDATE_VENV_DIR}"
    printf 'Installing candidate dependencies into %s...\n' "${CANDIDATE_VENV_DIR}"
    run_as_venv_owner_in_dir "${STAGING_DIR}" \
        "${CANDIDATE_VENV_DIR}/bin/python" -m pip install \
        --disable-pip-version-check --no-cache-dir -r requirements.txt
    run_as_venv_owner "${CANDIDATE_VENV_DIR}/bin/python" -m pip check
    # The archived candidate is intentionally not writable by the virtualenv
    # owner. Keep bytecode in the candidate runtime instead of attempting to
    # create __pycache__ directories within the immutable source tree.
    run_as_venv_owner env \
        PYTHONPYCACHEPREFIX="${CANDIDATE_VENV_DIR}/.ghostmerge-pycache" \
        "${CANDIDATE_VENV_DIR}/bin/python" -m compileall -q "${STAGING_DIR}"
    if [[ "${RUN_TESTS}" -eq 1 ]]; then
        printf 'Running the complete GhostMerge regression suite against the candidate...\n'
        run_as_venv_owner_in_dir "${STAGING_DIR}" env PYTHONPATH="${STAGING_DIR}" \
            "${CANDIDATE_VENV_DIR}/bin/python" -m pytest -q "${STAGING_DIR}/tests"
    fi
}

active_operation_preflight() {
    run_as_service "${VENV_DIR}/bin/python" -c '
import json
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
active = []
if not root.is_dir() or not os.access(root, os.R_OK | os.X_OK):
    raise SystemExit(f"GhostMerge operation state is not readable: {root}")

def directory_entries(path):
    try:
        return list(path.iterdir())
    except OSError as exc:
        raise SystemExit(f"GhostMerge operation state is not readable: {path}: {exc}") from exc

for folder in ("api_imports", "api_source_checks"):
    folder_path = root / folder
    if not folder_path.exists():
        continue
    if not folder_path.is_dir() or not os.access(folder_path, os.R_OK | os.X_OK):
        raise SystemExit(f"GhostMerge operation state is not readable: {folder_path}")
    for path in (item for item in directory_entries(folder_path) if item.suffix == ".json"):
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            active.append(f"unreadable operation state {path}")
            continue
        operation_status = state.get("status")
        if operation_status in {"running", "cancelling"}:
            active.append(f"{folder}/{path.stem} ({operation_status})")
for job_dir in (item for item in directory_entries(root) if item.is_dir()):
    if job_dir.name in {"api_imports", "api_source_checks"}:
        continue
    if not os.access(job_dir, os.R_OK | os.X_OK):
        raise SystemExit(f"GhostMerge operation state is not readable: {job_dir}")
    job_entries = directory_entries(job_dir)
    job_path = job_dir / "job.json"
    if not job_path.exists():
        if any(item.name.startswith("sync-") and item.suffix == ".lock" for item in job_entries):
            active.append(f"sync lock in job directory without readable job state {job_dir}")
        continue
    try:
        job = json.loads(job_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        active.append(f"unreadable job state {job_path}")
        continue
    if (job.get("unattended") or {}).get("status") in {"queued", "running"}:
        active.append(f"job {job_path.parent.name} unattended worker")
    for side, state in (job.get("sync_results") or {}).items():
        if isinstance(state, dict) and state.get("status") in {"queued", "running", "cancelling"}:
            active.append(f"job {job_path.parent.name} {side} sync")
    for lock_path in (
        item for item in job_entries if item.name.startswith("sync-") and item.suffix == ".lock"
    ):
        active.append(f"sync lock {lock_path}")
if active:
    print("Active GhostMerge operations prevent a safe update:", file=sys.stderr)
    for item in active:
        print(f"  - {item}", file=sys.stderr)
    raise SystemExit(3)
' "${PROJECT_DIR}/ghostmerge_web_jobs"
}

resolve_target_revision() {
    PREVIOUS_REVISION="$(run_as_owner git -C "${PROJECT_DIR}" rev-parse HEAD)"
    TARGET_REVISION="${PREVIOUS_REVISION}"
    if [[ "${REPAIR_CURRENT}" -eq 1 ]]; then
        return
    fi
    run_as_owner git -C "${PROJECT_DIR}" rev-parse --verify '@{upstream}' >/dev/null 2>&1 || \
        fail "The current branch has no configured upstream."
    CURRENT_BRANCH="$(run_as_owner git -C "${PROJECT_DIR}" symbolic-ref --short HEAD)"
    UPSTREAM_REMOTE="$(run_as_owner git -C "${PROJECT_DIR}" config --get "branch.${CURRENT_BRANCH}.remote")"
    [[ -n "${UPSTREAM_REMOTE}" ]] || fail "The current branch upstream remote is unavailable."
    printf 'Fetching the configured GhostMerge upstream as %s...\n' "${APP_OWNER}"
    run_as_owner timeout --signal=TERM 60s git -C "${PROJECT_DIR}" fetch --prune -- "${UPSTREAM_REMOTE}"
    TARGET_REVISION="$(run_as_owner git -C "${PROJECT_DIR}" rev-parse '@{upstream}')"
    run_as_owner git -C "${PROJECT_DIR}" merge-base --is-ancestor \
        "${PREVIOUS_REVISION}" "${TARGET_REVISION}" || \
        fail "The upstream update is not a fast-forward from the installed revision."
}

wait_for_ghostmerge_http() {
    run_as_service "${CANDIDATE_VENV_DIR}/bin/python" -c '
import sys
import time
import urllib.error
import urllib.request

host = sys.argv[1]
port = int(sys.argv[2])
deadline = time.monotonic() + int(sys.argv[3])
if host in {"0.0.0.0", "*"}:
    host = "127.0.0.1"
elif host in {"::", "[::]"}:
    host = "::1"
host = host.strip("[]")
last_error = None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
while time.monotonic() < deadline:
    try:
        url_host = f"[{host}]" if ":" in host else host
        request = urllib.request.Request(f"http://{url_host}:{port}/", method="GET")
        try:
            response = opener.open(request, timeout=1)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            body = response.read(262144)
        if b"<title>GhostMerge</title>" in body:
            raise SystemExit(0)
        last_error = RuntimeError("the listener did not identify itself as GhostMerge")
    except (OSError, RuntimeError) as exc:
        last_error = exc
        time.sleep(0.5)
raise SystemExit(f"GhostMerge HTTP readiness check failed: {last_error}")
' "${HOST}" "${PORT}" "${HEALTH_TIMEOUT_SECONDS}"
}

perform_update() {
    local lock_path="/run/lock/${SERVICE_NAME}-update.lock"

    exec 9>"${lock_path}"
    flock -n 9 || fail "Another ${SERVICE_NAME} update is already running."
    systemctl is-active --quiet "${SERVICE_NAME}.service" || \
        fail "${SERVICE_NAME}.service must be active before it can be updated safely."

    validate_clean_checkout
    validate_json_configs
    resolve_target_revision
    candidate_preflight "${TARGET_REVISION}"
    prepare_candidate_runtime

    MAINTENANCE_PATH="${PROJECT_DIR}/ghostmerge_web_jobs/.deployment-maintenance"
    [[ ! -e "${MAINTENANCE_PATH}" ]] || \
        fail "GhostMerge is already in deployment maintenance mode; inspect the existing gate before updating."
    install -m 0640 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" /dev/null "${MAINTENANCE_PATH}"
    MAINTENANCE_CREATED=1
    active_operation_preflight

    UNIT_BACKUP="$(mktemp /tmp/${SERVICE_NAME}-unit.XXXXXX)"
    cp --preserve=mode,ownership,timestamps -- "${UNIT_PATH}" "${UNIT_BACKUP}"
    if [[ -f "${METADATA_PATH}" ]]; then
        HAD_METADATA=1
        METADATA_BACKUP="$(mktemp /tmp/${SERVICE_NAME}-metadata.XXXXXX)"
        cp --preserve=mode,ownership,timestamps -- "${METADATA_PATH}" "${METADATA_BACKUP}"
    fi

    UPDATE_STARTED=1
    SERVICE_WAS_STOPPED=1
    printf 'Stopping %s.service...\n' "${SERVICE_NAME}"
    systemctl stop "${SERVICE_NAME}.service"
    # Close the race with requests which passed the maintenance check before
    # its marker was placed, and with first upgrades from versions which do not
    # yet understand the marker. No checkout or dependency change has occurred.
    active_operation_preflight

    if [[ "${TARGET_REVISION}" != "${PREVIOUS_REVISION}" ]]; then
        printf 'Fast-forwarding GhostMerge from %s to %s...\n' \
            "${PREVIOUS_REVISION}" "${TARGET_REVISION}"
        CHECKOUT_CHANGED=1
        run_as_owner git -C "${PROJECT_DIR}" merge --ff-only "${TARGET_REVISION}"
    else
        printf 'Repairing the current GhostMerge revision %s.\n' "${PREVIOUS_REVISION}"
    fi

    validate_clean_checkout
    validate_json_configs
    run_as_service env PYTHONPATH="${PROJECT_DIR}" "${CANDIDATE_VENV_DIR}/bin/python" -c '
import sys
from pathlib import Path
from web_app import create_app

create_app({
    "GHOSTMERGE_START_SCHEDULER": False,
    "GHOSTMERGE_JOBS_DIR": Path(sys.argv[1]),
})
' "${PROJECT_DIR}/ghostmerge_web_jobs"

    "${PROJECT_DIR}/install-systemd-service.sh" \
        --project-dir "${PROJECT_DIR}" \
        --venv-dir "${CANDIDATE_VENV_DIR}" \
        --service-name "${SERVICE_NAME}" \
        --user "${SERVICE_USER}" \
        --group "${SERVICE_GROUP}" \
        --host "${HOST}" \
        --port "${PORT}" \
        --no-create-user \
        --check-access \
        --no-install-deps \
        --no-enable \
        --no-start

    rm -f -- "${MAINTENANCE_PATH}"
    MAINTENANCE_CREATED=0
    printf 'Starting %s.service...\n' "${SERVICE_NAME}"
    systemctl start "${SERVICE_NAME}.service"
    systemctl is-active --quiet "${SERVICE_NAME}.service"
    wait_for_ghostmerge_http
    systemctl is-active --quiet "${SERVICE_NAME}.service"
    SERVICE_WAS_STOPPED=0
    CANDIDATE_VENV_KEEP=1
    UPDATE_COMPLETED=1
    printf 'GhostMerge update completed successfully at revision %s.\n' \
        "$(run_as_owner git -C "${PROJECT_DIR}" rev-parse --short HEAD)"
}

main() {
    parse_args "$@"
    create_private_snapshot "$@"
    trap handle_exit EXIT ERR INT TERM
    validate_required_commands
    validate_plain_token "--service-name" "${SERVICE_NAME}"
    validate_service_name
    [[ "${HEALTH_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] && \
        ((HEALTH_TIMEOUT_SECONDS >= 1 && HEALTH_TIMEOUT_SECONDS <= 300)) || \
        fail "--health-timeout must be between 1 and 300 seconds."
    if [[ "${DRY_RUN}" -eq 0 && "${EUID}" -ne 0 ]]; then
        fail "The updater must run as root. Re-run it with sudo, or use --dry-run."
    fi
    resolve_deployment
    validate_clean_checkout
    validate_json_configs

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        systemctl is-active --quiet "${SERVICE_NAME}.service" || \
            fail "${SERVICE_NAME}.service is not active."
        active_operation_preflight
        run_as_venv_owner "${VENV_DIR}/bin/python" -m pip check
        PREVIOUS_REVISION="$(run_as_owner git -C "${PROJECT_DIR}" rev-parse HEAD)"
        candidate_preflight "${PREVIOUS_REVISION}"
        printf 'GhostMerge installation preflight passed. Network fetch and mutating update steps were not run.\n'
        printf 'Project: %s\nVirtualenv: %s\nService: %s.service\nBind: %s:%s\n' \
            "${PROJECT_DIR}" "${VENV_DIR}" "${SERVICE_NAME}" "${HOST}" "${PORT}"
        return
    fi
    perform_update
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

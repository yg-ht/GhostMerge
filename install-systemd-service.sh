#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROJECT_DIR="${SCRIPT_DIR}"
VENV_DIR="${PROJECT_DIR}/.venv"
VENV_DIR_EXPLICIT=0
SERVICE_NAME="ghostmerge-web"
SERVICE_USER="ghostmerge"
SERVICE_GROUP="ghostmerge"
HOST="127.0.0.1"
PORT="5000"
ENABLE_SERVICE=1
START_SERVICE=0
DRY_RUN=0
CREATE_SERVICE_USER=1
CHECK_SERVICE_ACCESS=1
INSTALL_DEPS=1
UNIT_DIR="/etc/systemd/system"
TEMPLATE_PATH="${PROJECT_DIR}/packaging/systemd/ghostmerge-web.service"

usage() {
    cat <<'USAGE'
Install GhostMerge's Flask web frontend as a systemd system service.

Usage:
  ./install-systemd-service.sh [options]

Options:
  --project-dir PATH      Project checkout path. Defaults to this script's directory.
  --venv-dir PATH         Python virtualenv path. Defaults to PROJECT_DIR/.venv, then Pipenv discovery.
  --service-name NAME     Systemd service name without ".service". Defaults to ghostmerge-web.
  --user USER             Dedicated service user. Defaults to ghostmerge.
  --group GROUP           Dedicated service group. Defaults to ghostmerge.
  --create-user           Create the service user/group if missing. This is the default.
  --no-create-user        Require the service user/group to already exist.
  --check-access          Verify the service user can read and write required paths. This is the default.
  --no-check-access       Skip service-user filesystem access checks.
  --install-deps          Create PROJECT_DIR/.venv and install requirements if no venv is usable. This is the default.
  --no-install-deps       Refuse to install Python dependencies automatically.
  --host ADDRESS          Flask bind address. Defaults to 127.0.0.1.
  --port PORT             Flask bind port. Defaults to 5000.
  --enable                Enable the service at boot. This is the default.
  --no-enable             Do not enable the service at boot.
  --start                 Start or restart the service after installation.
  --no-start              Do not start the service after installation. This is the default.
  --dry-run               Render and print the unit without writing to /etc/systemd/system.
  -h, --help              Show this help text.
USAGE
}

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

absolute_path() {
    local path="$1"

    # Systemd units should not depend on the caller's current directory.
    if [[ "${path}" = /* ]]; then
        printf '%s\n' "${path}"
    else
        printf '%s/%s\n' "$(pwd)" "${path}"
    fi
}

systemd_escape_value() {
    local value="$1"

    # Backslashes and double quotes must be escaped when values are embedded in unit fields.
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s\n' "${value}"
}

validate_plain_token() {
    local label="$1"
    local value="$2"

    # Keep fields passed to systemd as simple argv tokens so they cannot smuggle extra arguments.
    [[ -n "${value}" ]] || fail "${label} cannot be empty."
    [[ "${value}" != *[[:space:]]* ]] || fail "${label} must not contain whitespace."
}

validate_port() {
    [[ "${PORT}" =~ ^[0-9]+$ ]] || fail "--port must be a number."
    (( PORT >= 1 && PORT <= 65535 )) || fail "--port must be between 1 and 65535."
}

parse_args() {
    while (($#)); do
        case "$1" in
            --project-dir)
                [[ $# -ge 2 ]] || fail "--project-dir requires a value."
                PROJECT_DIR="$(absolute_path "$2")"
                if (( VENV_DIR_EXPLICIT == 0 )); then
                    VENV_DIR="${PROJECT_DIR}/.venv"
                fi
                TEMPLATE_PATH="${PROJECT_DIR}/packaging/systemd/ghostmerge-web.service"
                shift 2
                ;;
            --venv-dir)
                [[ $# -ge 2 ]] || fail "--venv-dir requires a value."
                VENV_DIR="$(absolute_path "$2")"
                VENV_DIR_EXPLICIT=1
                shift 2
                ;;
            --service-name)
                [[ $# -ge 2 ]] || fail "--service-name requires a value."
                SERVICE_NAME="$2"
                shift 2
                ;;
            --user)
                [[ $# -ge 2 ]] || fail "--user requires a value."
                SERVICE_USER="$2"
                shift 2
                ;;
            --group)
                [[ $# -ge 2 ]] || fail "--group requires a value."
                SERVICE_GROUP="$2"
                shift 2
                ;;
            --create-user)
                CREATE_SERVICE_USER=1
                shift
                ;;
            --no-create-user)
                CREATE_SERVICE_USER=0
                shift
                ;;
            --check-access)
                CHECK_SERVICE_ACCESS=1
                shift
                ;;
            --no-check-access)
                CHECK_SERVICE_ACCESS=0
                shift
                ;;
            --install-deps)
                INSTALL_DEPS=1
                shift
                ;;
            --no-install-deps)
                INSTALL_DEPS=0
                shift
                ;;
            --host)
                [[ $# -ge 2 ]] || fail "--host requires a value."
                HOST="$2"
                shift 2
                ;;
            --port)
                [[ $# -ge 2 ]] || fail "--port requires a value."
                PORT="$2"
                shift 2
                ;;
            --enable)
                ENABLE_SERVICE=1
                shift
                ;;
            --no-enable)
                ENABLE_SERVICE=0
                shift
                ;;
            --start)
                START_SERVICE=1
                shift
                ;;
            --no-start)
                START_SERVICE=0
                shift
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
                fail "Unknown option: $1"
                ;;
        esac
    done
}

venv_has_flask() {
    local venv_dir="$1"

    [[ -n "${venv_dir}" && -x "${venv_dir}/bin/flask" ]]
}

discover_pipenv_venv() {
    local discovered

    command -v pipenv >/dev/null 2>&1 || return 1
    [[ -f "${PROJECT_DIR}/Pipfile" ]] || [[ -f "${PROJECT_DIR}/requirements.txt" ]] || return 1

    # Run from the project directory so Pipenv resolves the same project that systemd will run.
    discovered="$(cd "${PROJECT_DIR}" && pipenv --venv 2>/dev/null || true)"
    [[ -n "${discovered}" ]] || return 1
    if [[ "${discovered}" == /root/* ]]; then
        printf 'Ignoring Pipenv virtualenv under /root because the dedicated service user should not depend on root-owned private environments: %s\n' "${discovered}" >&2
        return 1
    fi
    venv_has_flask "${discovered}" || return 1

    printf '%s\n' "${discovered}"
}

install_project_venv() {
    local python_bin

    (( INSTALL_DEPS == 1 )) || return 1
    (( DRY_RUN == 0 )) || return 1
    [[ -f "${PROJECT_DIR}/requirements.txt" ]] || fail "No usable Flask executable found and requirements.txt is missing."

    if command -v python3 >/dev/null 2>&1; then
        python_bin="python3"
    elif command -v python >/dev/null 2>&1; then
        python_bin="python"
    else
        fail "No usable Flask executable found and neither python3 nor python is available to create ${PROJECT_DIR}/.venv."
    fi

    printf 'No usable Flask executable found. Creating project virtualenv at %s/.venv\n' "${PROJECT_DIR}" >&2
    "${python_bin}" -m venv "${PROJECT_DIR}/.venv" || fail "Could not create ${PROJECT_DIR}/.venv. Install the Python venv package for ${python_bin}, or provide --venv-dir."
    "${PROJECT_DIR}/.venv/bin/python" -m pip install --upgrade pip || fail "Could not upgrade pip in ${PROJECT_DIR}/.venv."
    "${PROJECT_DIR}/.venv/bin/python" -m pip install -r "${PROJECT_DIR}/requirements.txt" || fail "Could not install requirements.txt into ${PROJECT_DIR}/.venv."
    VENV_DIR="${PROJECT_DIR}/.venv"
}

resolve_venv_dir() {
    local discovered

    if (( VENV_DIR_EXPLICIT == 1 )); then
        venv_has_flask "${VENV_DIR}" || fail "Flask executable not found or not executable: ${VENV_DIR}/bin/flask"
        return
    fi

    if venv_has_flask "${PROJECT_DIR}/.venv"; then
        VENV_DIR="${PROJECT_DIR}/.venv"
        return
    fi

    if discovered="$(discover_pipenv_venv)"; then
        VENV_DIR="${discovered}"
        return
    fi

    install_project_venv || fail "Flask executable not found or not executable. Create ${PROJECT_DIR}/.venv, run pipenv install without sudo and pass --venv-dir \"\$(pipenv --venv)\", or re-run with --install-deps."
    venv_has_flask "${VENV_DIR}" || fail "Dependency installation completed but Flask executable is still missing: ${VENV_DIR}/bin/flask"
}

validate_inputs() {
    PROJECT_DIR="$(absolute_path "${PROJECT_DIR}")"
    VENV_DIR="$(absolute_path "${VENV_DIR}")"

    [[ -d "${PROJECT_DIR}" ]] || fail "Project directory not found: ${PROJECT_DIR}"
    [[ "${PROJECT_DIR}" != *[[:space:]]* ]] || fail "Project directory must not contain whitespace because systemd ExecStart paths are not shell-expanded."
    [[ -f "${PROJECT_DIR}/web_app.py" ]] || fail "web_app.py not found in ${PROJECT_DIR}"
    [[ -f "${PROJECT_DIR}/ghostmerge_config.json" ]] || fail "ghostmerge_config.json is required before installing the web service."
    [[ -f "${TEMPLATE_PATH}" ]] || fail "Systemd template not found: ${TEMPLATE_PATH}"

    if (( DRY_RUN == 0 && EUID != 0 )); then
        fail "System service installation requires root. Re-run with sudo, or use --dry-run to inspect the unit."
    fi

    resolve_venv_dir
    VENV_DIR="$(absolute_path "${VENV_DIR}")"
    [[ "${VENV_DIR}" != *[[:space:]]* ]] || fail "Virtualenv directory must not contain whitespace because systemd ExecStart paths are not shell-expanded."

    validate_plain_token "--service-name" "${SERVICE_NAME}"
    [[ "${SERVICE_NAME}" != *.service ]] || fail "--service-name should not include the .service suffix."
    validate_plain_token "--user" "${SERVICE_USER}"
    validate_plain_token "--group" "${SERVICE_GROUP}"
    [[ "${SERVICE_USER}" != "root" ]] || fail "The service must not run as root. Choose a dedicated unprivileged user."
    [[ "${SERVICE_GROUP}" != "root" ]] || fail "The service group must not be root. Choose a dedicated unprivileged group."
    validate_plain_token "--host" "${HOST}"
    validate_port

}

ensure_service_account() {
    if getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
        :
    elif (( CREATE_SERVICE_USER == 1 )); then
        groupadd --system "${SERVICE_GROUP}"
    else
        fail "Service group does not exist: ${SERVICE_GROUP}"
    fi

    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        :
    elif (( CREATE_SERVICE_USER == 1 )); then
        # A locked system account limits service privileges and prevents interactive login.
        useradd \
            --system \
            --gid "${SERVICE_GROUP}" \
            --home-dir "${PROJECT_DIR}" \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "${SERVICE_USER}"
    else
        fail "Service user does not exist: ${SERVICE_USER}"
    fi

    if ! id -nG "${SERVICE_USER}" | tr ' ' '\n' | grep -Fxq "${SERVICE_GROUP}"; then
        fail "Service user ${SERVICE_USER} is not a member of service group ${SERVICE_GROUP}."
    fi
}

prepare_service_state_paths() {
    # Keep the application code and virtualenv root-owned where desired, while granting
    # the service account only the project-local paths the current app writes to.
    install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${PROJECT_DIR}/ghostmerge_web_jobs"
    install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${PROJECT_DIR}/ghostmerge_api_backups"
    touch "${PROJECT_DIR}/ghostmerge.log"
    chown "${SERVICE_USER}:${SERVICE_GROUP}" "${PROJECT_DIR}/ghostmerge.log"
    chmod 0640 "${PROJECT_DIR}/ghostmerge.log"
}

check_service_account_access() {
    local probe

    if (( CHECK_SERVICE_ACCESS == 0 )); then
        return
    fi

    command -v runuser >/dev/null 2>&1 || fail "runuser is required for service-user access checks. Install util-linux or pass --no-check-access."

    # The Flask app currently stores jobs, optional API backups, and the default log file under the project directory.
    # Probe those paths as the service account so systemd does not install a unit that cannot start or save state.
    probe='
        set -e
        test -x "$1"
        test -r "$1/web_app.py"
        test -r "$1/ghostmerge_config.json"
        test -x "$2/bin/flask"
        test -w "$1/ghostmerge_web_jobs"
        test -w "$1/ghostmerge_api_backups"
        test -w "$1/ghostmerge.log"
        touch "$1/ghostmerge_web_jobs/.ghostmerge-systemd-access-check"
        rm -f "$1/ghostmerge_web_jobs/.ghostmerge-systemd-access-check"
    '

    if ! runuser -u "${SERVICE_USER}" -- sh -c "${probe}" sh "${PROJECT_DIR}" "${VENV_DIR}"; then
        fail "Service user ${SERVICE_USER} cannot read the app/config or write required project state. Fix ownership/permissions, move the deployment outside a private home directory, or re-run with --no-check-access if you have checked this manually."
    fi
}

render_unit() {
    local project_dir
    local venv_dir
    local service_user
    local service_group
    local host
    local port

    project_dir="$(systemd_escape_value "${PROJECT_DIR}")"
    venv_dir="$(systemd_escape_value "${VENV_DIR}")"
    service_user="$(systemd_escape_value "${SERVICE_USER}")"
    service_group="$(systemd_escape_value "${SERVICE_GROUP}")"
    host="$(systemd_escape_value "${HOST}")"
    port="$(systemd_escape_value "${PORT}")"

    sed \
        -e "s|{{PROJECT_DIR}}|${project_dir}|g" \
        -e "s|{{VENV_DIR}}|${venv_dir}|g" \
        -e "s|{{SERVICE_USER}}|${service_user}|g" \
        -e "s|{{SERVICE_GROUP}}|${service_group}|g" \
        -e "s|{{HOST}}|${host}|g" \
        -e "s|{{PORT}}|${port}|g" \
        "${TEMPLATE_PATH}"
}

install_unit() {
    local service_file="${UNIT_DIR}/${SERVICE_NAME}.service"
    local temp_file

    ensure_service_account
    prepare_service_state_paths
    check_service_account_access

    temp_file="$(mktemp)"
    render_unit > "${temp_file}"
    install -m 0644 "${temp_file}" "${service_file}"
    rm -f "${temp_file}"

    systemctl daemon-reload
    if (( ENABLE_SERVICE == 1 )); then
        systemctl enable "${SERVICE_NAME}.service"
    fi
    if (( START_SERVICE == 1 )); then
        systemctl restart "${SERVICE_NAME}.service"
    fi

    printf 'Installed %s\n' "${service_file}"
    printf 'Check status with: systemctl status %s.service\n' "${SERVICE_NAME}"
    printf 'View logs with: journalctl -u %s.service -f\n' "${SERVICE_NAME}"
}

main() {
    parse_args "$@"
    validate_inputs

    if (( DRY_RUN == 1 )); then
        render_unit
        exit 0
    fi

    install_unit
}

main "$@"

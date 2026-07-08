from __future__ import annotations

import json
import ipaddress
import secrets
import threading
import uuid
from pathlib import Path
from typing import Any

from flask import Flask, Response, redirect, render_template, request, send_file, session, url_for

from ghostwriter_api import (
    GhostwriterApi,
    GhostwriterApiError,
    backup_root_from_config,
    configured_server_summary,
    list_backups,
    load_backup_record,
    load_server_configs,
    verify_backup,
)
from globals import get_config
from sensitivity import load_sensitive_terms
from utils import load_config
from web_service import (
    WebMergeError,
    accept_offered_fields_for_current_match,
    accept_offered_for_current_match,
    acknowledge_current_preview,
    apply_conflict_decision,
    apply_sensitivity_decision,
    create_merge_job,
    finalise_job,
    get_current_match_preview,
    get_next_conflict,
    get_next_sensitivity_item,
    get_review_progress,
    job_summary,
    list_previous_jobs,
    load_job,
    load_records_from_json_text,
    save_job,
    save_outputs,
)

CONFIG = get_config()
SOURCE_IP_MODES = {"direct", "trusted_header", "both"}


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        GHOSTMERGE_JOBS_DIR=Path("ghostmerge_web_jobs"),
    )
    if test_config:
        app.config.update(test_config)

    if not CONFIG.get("config_loaded"):
        load_config()

    app.wsgi_app = ConfiguredReverseProxyPrefixMiddleware(app.wsgi_app, _web_access_config)
    _configure_session_cookie_policy(app)

    jobs_dir = Path(app.config["GHOSTMERGE_JOBS_DIR"])
    jobs_dir.mkdir(parents=True, exist_ok=True)

    @app.before_request
    def require_configured_web_access():
        blocked_response = _require_allowed_source_ip()
        if blocked_response is not None:
            return blocked_response
        return _require_get_api_key_authentication()

    @app.before_request
    def require_csrf_token():
        if request.method != "POST":
            return None
        expected_token = session.get("_csrf_token")
        submitted_token = request.form.get("_csrf_token")
        if not expected_token or not submitted_token or not secrets.compare_digest(expected_token, submitted_token):
            return render_template("error.html", error="Invalid or missing form token."), 400
        return None

    @app.context_processor
    def inject_csrf_token():
        def csrf_token() -> str:
            # A session-scoped token protects local mutating routes without adding a new dependency.
            token = session.get("_csrf_token")
            if not token:
                token = secrets.token_urlsafe(32)
                session["_csrf_token"] = token
            return token

        return {"csrf_token": csrf_token}

    @app.after_request
    def apply_framing_policy(response: Response) -> Response:
        return _apply_framing_policy(response)

    @app.get("/")
    def index():
        return render_template(
            "upload.html",
            previous_jobs=list_previous_jobs(jobs_dir),
            api_source_checks=_list_api_source_checks(jobs_dir),
            api_imports=_list_api_imports(jobs_dir),
            api_servers=configured_server_summary(CONFIG),
            backups=list_backups(backup_root_from_config(CONFIG)),
            root_page=True,
        )

    @app.post("/jobs")
    def create_job_route():
        try:
            input_sources = {
                "left": request.form.get("left_source", "file"),
                "right": request.form.get("right_source", "file"),
            }
            _validate_input_sources(input_sources)
            if "api" in input_sources.values():
                import_id = _start_import_thread(app, jobs_dir, input_sources, request.files)
                return redirect(url_for("import_status", import_id=import_id))
            left_records = _load_records_for_side("left", request.files.get("left_file"), input_sources["left"])
            right_records = _load_records_for_side("right", request.files.get("right_file"), input_sources["right"])
            job = create_merge_job(left_records, right_records, input_sources=input_sources)
            save_job(job, jobs_dir)
            return redirect(url_for("summary", job_id=job.job_id))
        except (UnicodeDecodeError, WebMergeError, GhostwriterApiError) as exc:
            return render_template(
                "upload.html",
                error=str(exc),
                previous_jobs=list_previous_jobs(jobs_dir),
                api_source_checks=_list_api_source_checks(jobs_dir),
                api_imports=_list_api_imports(jobs_dir),
                api_servers=configured_server_summary(CONFIG),
                backups=list_backups(backup_root_from_config(CONFIG)),
                root_page=True,
            ), 400

    @app.post("/api-sources/<side>/check")
    def check_api_source(side: str):
        try:
            if side not in {"left", "right"}:
                return render_template("error.html", error="Unknown API source side."), 404
            check_id = _start_api_source_check_thread(app, jobs_dir, side)
            return redirect(url_for("api_source_check_status", check_id=check_id))
        except GhostwriterApiError as exc:
            return render_template(
                "upload.html",
                error=str(exc),
                previous_jobs=list_previous_jobs(jobs_dir),
                api_source_checks=_list_api_source_checks(jobs_dir),
                api_imports=_list_api_imports(jobs_dir),
                api_servers=configured_server_summary(CONFIG),
                backups=list_backups(backup_root_from_config(CONFIG)),
                root_page=True,
            ), 400

    @app.get("/api-sources/checks/<check_id>/status")
    def api_source_check_status(check_id: str):
        try:
            state = _load_api_source_check_state(jobs_dir, check_id)
            return render_template("api_source_check_status.html", state=state)
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404

    @app.get("/imports/<import_id>/status")
    def import_status(import_id: str):
        try:
            state = _load_import_state(jobs_dir, import_id)
            return render_template("import_status.html", state=state)
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404

    @app.get("/jobs/<job_id>/summary")
    def summary(job_id: str):
        try:
            job = load_job(jobs_dir, job_id)
            return render_template("summary.html", summary=job_summary(job), progress=get_review_progress(job))
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404

    @app.get("/jobs/<job_id>/conflicts")
    def conflicts(job_id: str):
        try:
            job = load_job(jobs_dir, job_id)
            if not job.preview_acknowledged:
                preview = get_current_match_preview(job)
                save_job(job, jobs_dir)
                if preview is not None:
                    return render_template(
                        "match_preview.html",
                        job=job,
                        preview=preview,
                        progress=get_review_progress(job),
                    )
            item = get_next_conflict(job)
            save_job(job, jobs_dir)
            if item is None:
                return redirect(url_for("sensitivity", job_id=job.job_id))
            return render_template(
                "conflict.html",
                job=job,
                item=item,
                progress=get_review_progress(job),
            )
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.post("/jobs/<job_id>/conflicts")
    def apply_conflict(job_id: str):
        try:
            job = load_job(jobs_dir, job_id)
            if request.form.get("preview_action") == "continue":
                acknowledge_current_preview(job)
            elif request.form.get("preview_action") == "accept_offered":
                accept_offered_for_current_match(job)
            elif request.form.get("preview_action") == "accept_selected_offered":
                accept_offered_fields_for_current_match(job, request.form.getlist("selected_fields"))
            else:
                apply_conflict_decision(job, request.form.to_dict())
            save_job(job, jobs_dir)
            return redirect(url_for("conflicts", job_id=job.job_id))
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.get("/jobs/<job_id>/sensitivity")
    def sensitivity(job_id: str):
        try:
            job = load_job(jobs_dir, job_id)
            item = get_next_sensitivity_item(job, _load_terms())
            save_job(job, jobs_dir)
            if item is None:
                return redirect(url_for("complete", job_id=job.job_id))
            return render_template(
                "sensitivity.html",
                job=job,
                item=item,
                progress=get_review_progress(job),
            )
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.post("/jobs/<job_id>/sensitivity")
    def apply_sensitivity(job_id: str):
        try:
            job = load_job(jobs_dir, job_id)
            apply_sensitivity_decision(job, request.form.to_dict())
            save_job(job, jobs_dir)
            return redirect(url_for("sensitivity", job_id=job.job_id))
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.get("/jobs/<job_id>/complete")
    def complete(job_id: str):
        try:
            job = load_job(jobs_dir, job_id)
            _require_completed_review(job, action="Completion")
            result = finalise_job(job)
            save_outputs(job, jobs_dir, result)
            save_job(job, jobs_dir)
            return render_template(
                "complete.html",
                job=job,
                progress=get_review_progress(job),
                api_servers=configured_server_summary(CONFIG),
            )
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @post_or_get(app, "/jobs/<job_id>/sync/<side>")
    def sync_side(job_id: str, side: str):
        if side not in {"left", "right"}:
            return render_template("error.html", error="Unknown sync side."), 404
        try:
            job = load_job(jobs_dir, job_id)
            _require_completed_review(job)
            _require_api_backed_side(job, side)
            if request.method == "GET":
                return render_template(
                    "sync_confirm.html",
                    job=job,
                    side=side,
                    server=_server_for_side(side),
                    progress=get_review_progress(job),
                )
            _start_sync_thread(app, jobs_dir, job_id, side)
            return redirect(url_for("sync_status", job_id=job_id, side=side))
        except (WebMergeError, GhostwriterApiError) as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.get("/jobs/<job_id>/sync/<side>/status")
    def sync_status(job_id: str, side: str):
        try:
            job = load_job(jobs_dir, job_id)
            return render_template(
                "sync_status.html",
                job=job,
                side=side,
                state=job.sync_results.get(side, {}),
                progress=get_review_progress(job),
            )
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404

    @app.get("/api-backups")
    def api_backups():
        return render_template("api_backups.html", backups=list_backups(backup_root_from_config(CONFIG)))

    @app.get("/api-backups/<side>/<filename>")
    def api_backup_detail(side: str, filename: str):
        try:
            backup_path = _safe_backup_path(side, filename)
            data = verify_backup(backup_path)
            return render_template("api_backup_detail.html", backup=data, side=side, filename=filename)
        except (GhostwriterApiError, ValueError) as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.get("/api-backups/<side>/<filename>/download")
    def api_backup_download(side: str, filename: str):
        try:
            backup_path = _safe_backup_path(side, filename)
            verify_backup(backup_path)
            return send_file(backup_path, as_attachment=True, download_name=filename, mimetype="application/json")
        except (GhostwriterApiError, ValueError) as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.post("/api-backups/<side>/<filename>/<int:index>/restore")
    def api_backup_restore(side: str, filename: str, index: int):
        try:
            backup_path = _safe_backup_path(side, filename)
            record = load_backup_record(backup_path, index)
            server = _server_for_side(side)
            _require_backup_target_match(record["backup"], server)
            api = GhostwriterApi(server)
            created_id = api.restore_backup_record(record)
            return render_template(
                "api_restore_complete.html",
                side=side,
                filename=filename,
                record=record["normalised_record"],
                created_id=created_id,
            )
        except (GhostwriterApiError, ValueError) as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.get("/jobs/<job_id>/download/<side>")
    def download(job_id: str, side: str):
        if side not in {"left", "right"}:
            return render_template("error.html", error="Unknown output side."), 404
        try:
            load_job(jobs_dir, job_id)
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404
        path = jobs_dir / job_id / f"{side}.json"
        if not path.exists():
            return redirect(url_for("complete", job_id=job_id))
        return send_file(path, as_attachment=True, download_name=f"ghostmerge-{side}.json")

    return app


def post_or_get(app: Flask, rule: str):
    return app.route(rule, methods=["GET", "POST"])


class ConfiguredReverseProxyPrefixMiddleware:
    """Apply the configured public URL prefix before Flask routes or builds URLs."""

    def __init__(self, app, access_config_provider):
        self.app = app
        self.access_config_provider = access_config_provider

    def __call__(self, environ, start_response):
        try:
            prefix = _normalise_reverse_proxy_prefix(self.access_config_provider().get("reverse_proxy_prefix", ""))
        except WebAccessError as exc:
            start_response("403 FORBIDDEN", [("Content-Type", "text/plain; charset=utf-8")])
            return [str(exc).encode("utf-8")]

        if not prefix:
            return self.app(environ, start_response)

        # SCRIPT_NAME is the WSGI mechanism Flask uses when url_for builds public URLs.
        environ["SCRIPT_NAME"] = prefix

        path_info = environ.get("PATH_INFO", "")
        if path_info == prefix:
            environ["PATH_INFO"] = "/"
        elif path_info.startswith(f"{prefix}/"):
            environ["PATH_INFO"] = path_info[len(prefix) :]

        return self.app(environ, start_response)


def _web_access_config() -> dict:
    return CONFIG.get("web_access") or {}


def _normalise_reverse_proxy_prefix(raw_prefix) -> str:
    prefix = str(raw_prefix or "").strip()
    if not prefix or prefix == "/":
        return ""
    if any(character.isspace() for character in prefix) or "\\" in prefix or "?" in prefix or "#" in prefix:
        raise WebAccessError(f"Reverse proxy prefix {prefix!r} is not supported.")
    if not prefix.startswith("/"):
        prefix = f"/{prefix}"
    return prefix.rstrip("/")


def _configure_session_cookie_policy(app: Flask) -> None:
    access_config = _web_access_config()
    if "session_cookie_samesite" in access_config:
        app.config["SESSION_COOKIE_SAMESITE"] = access_config["session_cookie_samesite"]
    if "session_cookie_secure" in access_config:
        app.config["SESSION_COOKIE_SECURE"] = bool(access_config["session_cookie_secure"])


def _require_allowed_source_ip():
    access_config = _web_access_config()
    if access_config.get("source_ip_restriction_enabled", True) is False:
        return None

    remote_addr = request.remote_addr
    if not remote_addr:
        return render_template("error.html", error="Source IP address could not be determined."), 403

    allowed_ranges = access_config.get("allowed_source_ips") or []
    if not allowed_ranges:
        return render_template(
            "error.html",
            error=f"Source IP restriction is enabled but no allowed IPs are configured. Your source IP is {remote_addr}.",
        ), 403

    try:
        candidate_ips = _source_ip_candidates(access_config, remote_addr)
        for source_label, candidate_ip in candidate_ips:
            if _ip_is_allowed(candidate_ip, allowed_ranges):
                return None
    except ValueError:
        return render_template(
            "error.html",
            error=f"Source IP restriction contains an invalid configured range. Your source IP is {remote_addr}.",
        ), 403
    except WebAccessError as exc:
        return render_template("error.html", error=str(exc)), 403

    checked_ips = ", ".join(f"{label} {candidate}" for label, candidate in candidate_ips)
    return render_template("error.html", error=f"Source IP address is not allowed. Checked: {checked_ips}."), 403


class WebAccessError(Exception):
    pass


def _source_ip_candidates(
    access_config: dict,
    remote_addr: str,
) -> list[tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    mode = str(access_config.get("source_ip_mode") or "direct")
    if mode not in SOURCE_IP_MODES:
        raise WebAccessError(f"Source IP restriction mode {mode!r} is not supported.")

    candidates: list[tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address]] = []
    direct_ip = _parse_source_ip(remote_addr, "direct source IP address")
    if mode in {"direct", "both"}:
        candidates.append(("direct", direct_ip))

    if mode in {"trusted_header", "both"}:
        # Header-derived client IPs are only trustworthy when the direct peer is a configured proxy.
        if not _ip_is_allowed(direct_ip, access_config.get("trusted_proxy_ips") or []):
            if mode == "both":
                return candidates
            raise WebAccessError(f"Direct source IP address {remote_addr} is not a trusted proxy.")
        header_name = str(access_config.get("trusted_source_ip_header") or "X-Forwarded-For")
        header_value = request.headers.get(header_name, "")
        if not header_value:
            if mode == "both":
                return candidates
            raise WebAccessError(f"Trusted source IP header {header_name} is missing.")
        candidates.append(
            (f"trusted header {header_name}", _parse_source_ip(_first_forwarded_ip(header_value), header_name))
        )

    return candidates


def _parse_source_ip(raw_ip: str, source_label: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(raw_ip)
    except ValueError as exc:
        raise WebAccessError(f"Source IP from {source_label} is invalid: {raw_ip}.") from exc


def _ip_is_allowed(candidate_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allowed_ranges: list) -> bool:
    for allowed_range in allowed_ranges:
        # strict=False allows exact IP strings and CIDR networks through one parser.
        if candidate_ip in ipaddress.ip_network(str(allowed_range), strict=False):
            return True
    return False


def _first_forwarded_ip(header_value: str) -> str:
    return header_value.split(",", 1)[0].strip()


def _require_get_api_key_authentication():
    access_config = _web_access_config()
    if access_config.get("api_key_auth_enabled", True) is False:
        return None

    expected_key = str(access_config.get("api_key") or "")
    query_param = str(access_config.get("api_key_query_param") or "api_key")
    if not expected_key:
        return render_template("error.html", error="API key authentication is enabled but no API key is configured."), 401

    if session.get("_web_api_key_authenticated") is True:
        return None

    if request.method != "GET":
        return render_template("error.html", error="API key authentication requires an authenticated GET session."), 401

    submitted_key = request.args.get(query_param, "")
    if not submitted_key or not secrets.compare_digest(submitted_key, expected_key):
        return render_template("error.html", error="Invalid or missing API key."), 401

    # The GET key is intentionally a bootstrap credential so existing CSRF-protected POST forms stay unchanged.
    session["_web_api_key_authenticated"] = True
    return None


def _apply_framing_policy(response: Response) -> Response:
    access_config = _web_access_config()
    if not access_config.get("allow_framing", False):
        return response

    frame_ancestors = access_config.get("frame_ancestors") or []
    if frame_ancestors:
        response.headers["Content-Security-Policy"] = f"frame-ancestors {' '.join(map(str, frame_ancestors))}"
    response.headers.pop("X-Frame-Options", None)
    return response


def _validate_input_sources(input_sources: dict[str, str]) -> None:
    for side in ("left", "right"):
        if input_sources.get(side) not in {"file", "api"}:
            raise WebMergeError(f"{side.title()} source must be file or API.")


def _load_records_for_side(side: str, uploaded_file, source: str) -> list[dict]:
    if source == "api":
        server = _server_for_side(side)
        return GhostwriterApi(server).fetch_findings()
    if uploaded_file is None or uploaded_file.filename == "":
        raise WebMergeError(f"{side.title()} JSON file is required when that side is file-backed.")
    return load_records_from_json_text(uploaded_file.read().decode("utf-8"))


def _start_api_source_check_thread(app: Flask, jobs_dir: Path, side: str) -> str:
    server = _server_for_side(side)
    check_id = uuid.uuid4().hex
    _save_api_source_check_state(
        jobs_dir,
        check_id,
        {
            "check_id": check_id,
            "side": side,
            "server_name": server.name,
            "status": "running",
            "stage": "queued",
            "message": "Queued API source check.",
            "complete": 0,
            "total": 0,
            "backup_filename": None,
            "record_count": None,
        },
    )
    thread = threading.Thread(target=_check_api_source, args=(app, jobs_dir, check_id), daemon=True)
    thread.start()
    return check_id


def _check_api_source(app: Flask, jobs_dir: Path, check_id: str) -> None:
    with app.app_context():
        state = {
            "check_id": check_id,
            "status": "error",
            "stage": "error",
            "message": "API source check failed before state could be loaded.",
            "complete": 0,
            "total": 0,
        }
        try:
            state = _load_api_source_check_state(jobs_dir, check_id)
            side = state["side"]
            server = _server_for_side(side)

            def update(event):
                current = _load_api_source_check_state(jobs_dir, check_id)
                current.update(
                    {
                        "status": "running",
                        "stage": event.stage,
                        "message": event.message,
                        "complete": event.complete,
                        "total": event.total,
                    }
                )
                _save_api_source_check_state(jobs_dir, check_id, current)

            backup_path = GhostwriterApi(server, progress=update).create_backup(backup_root_from_config(CONFIG))
            backup = verify_backup(backup_path)
            state = _load_api_source_check_state(jobs_dir, check_id)
            state.update(
                {
                    "status": "done",
                    "stage": "complete",
                    "message": f"Fetched and backed up {backup['record_count']} findings from {server.name}.",
                    "complete": backup["record_count"],
                    "total": backup["record_count"],
                    "backup_filename": backup_path.name,
                    "record_count": backup["record_count"],
                }
            )
            _save_api_source_check_state(jobs_dir, check_id, state)
        except Exception as exc:
            state.update({"status": "error", "stage": "error", "message": str(exc)})
            _save_api_source_check_state(jobs_dir, check_id, state)


def _start_import_thread(app: Flask, jobs_dir: Path, input_sources: dict[str, str], files) -> str:
    import_id = uuid.uuid4().hex
    file_records: dict[str, list[dict]] = {}
    for side in ("left", "right"):
        if input_sources[side] == "file":
            # Uploaded files only live for the request, so parse and persist them before the worker starts.
            file_records[side] = _load_records_for_side(side, files.get(f"{side}_file"), "file")
        else:
            _server_for_side(side)
    api_sides = [side for side in ("left", "right") if input_sources[side] == "api"]
    _save_import_state(
        jobs_dir,
        import_id,
        {
            "import_id": import_id,
            "status": "running",
            "stage": "queued",
            "message": "Queued API import.",
            "complete": 0,
            "total": len(api_sides),
            "input_sources": input_sources,
            "file_records": file_records,
            "job_id": None,
        },
    )
    thread = threading.Thread(target=_import_job_sources, args=(app, jobs_dir, import_id), daemon=True)
    thread.start()
    return import_id


def _import_job_sources(app: Flask, jobs_dir: Path, import_id: str) -> None:
    with app.app_context():
        state = {
            "import_id": import_id,
            "status": "error",
            "stage": "error",
            "message": "API import failed before state could be loaded.",
            "complete": 0,
            "total": 0,
            "job_id": None,
        }
        try:
            state = _load_import_state(jobs_dir, import_id)
            input_sources = state["input_sources"]
            records = dict(state.get("file_records") or {})
            api_sides = [side for side in ("left", "right") if input_sources[side] == "api"]
            for index, side in enumerate(api_sides, start=1):
                server = _server_for_side(side)

                def update(event, current_side=side, current_index=index):
                    current = _load_import_state(jobs_dir, import_id)
                    current.update(
                        {
                            "status": event.status if event.status != "done" else "running",
                            "stage": f"fetch_{current_side}",
                            "message": event.message,
                            "complete": current_index - 1,
                            "total": len(api_sides),
                        }
                    )
                    _save_import_state(jobs_dir, import_id, current)

                records[side] = GhostwriterApi(server, progress=update).fetch_findings()
                state = _load_import_state(jobs_dir, import_id)
                state.update(
                    {
                        "status": "running",
                        "stage": f"fetched_{side}",
                        "message": f"Fetched {side} API source.",
                        "complete": index,
                        "total": len(api_sides),
                    }
                )
                _save_import_state(jobs_dir, import_id, state)
            job = create_merge_job(records["left"], records["right"], input_sources=input_sources)
            save_job(job, jobs_dir)
            state = _load_import_state(jobs_dir, import_id)
            state.update(
                {
                    "status": "done",
                    "stage": "complete",
                    "message": "API import complete.",
                    "complete": len(api_sides),
                    "total": len(api_sides),
                    "job_id": job.job_id,
                }
            )
            # Drop copied records once the durable merge job exists so the import file does not duplicate data.
            state.pop("file_records", None)
            _save_import_state(jobs_dir, import_id, state)
        except Exception as exc:
            state.update({"status": "error", "stage": "error", "message": str(exc)})
            _save_import_state(jobs_dir, import_id, state)


def _import_state_path(jobs_dir: Path, import_id: str) -> Path:
    if not import_id or not import_id.isalnum():
        raise WebMergeError("Invalid import ID.")
    return jobs_dir / "api_imports" / f"{import_id}.json"


def _api_source_check_state_path(jobs_dir: Path, check_id: str) -> Path:
    if not check_id or not check_id.isalnum():
        raise WebMergeError("Invalid API source check ID.")
    return jobs_dir / "api_source_checks" / f"{check_id}.json"


def _save_api_source_check_state(jobs_dir: Path, check_id: str, state: dict) -> None:
    path = _api_source_check_state_path(jobs_dir, check_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    tmp_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def _load_api_source_check_state(jobs_dir: Path, check_id: str) -> dict:
    path = _api_source_check_state_path(jobs_dir, check_id)
    if not path.exists():
        raise WebMergeError("API source check not found.")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WebMergeError("API source check state could not be read. Please refresh and try again.") from exc


def _list_api_source_checks(jobs_dir: Path) -> list[dict[str, Any]]:
    checks = []
    checks_dir = jobs_dir / "api_source_checks"
    if not checks_dir.exists():
        return checks
    for path in sorted(checks_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        check_id = path.stem
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            state = {
                "check_id": check_id,
                "status": "error",
                "stage": "error",
                "message": f"API source check state could not be read: {exc}",
            }
        state.setdefault("check_id", check_id)
        checks.append(state)
    return checks


def _save_import_state(jobs_dir: Path, import_id: str, state: dict) -> None:
    path = _import_state_path(jobs_dir, import_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    tmp_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def _load_import_state(jobs_dir: Path, import_id: str) -> dict:
    path = _import_state_path(jobs_dir, import_id)
    if not path.exists():
        raise WebMergeError("API import not found.")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WebMergeError("API import state could not be read. Please refresh and try again.") from exc


def _list_api_imports(jobs_dir: Path) -> list[dict[str, Any]]:
    imports = []
    imports_dir = jobs_dir / "api_imports"
    if not imports_dir.exists():
        return imports
    for path in sorted(imports_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        import_id = path.stem
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            state = {
                "import_id": import_id,
                "status": "error",
                "stage": "error",
                "message": f"API import state could not be read: {exc}",
            }
        state.setdefault("import_id", import_id)
        imports.append(state)
    return imports


def _server_for_side(side: str):
    server = load_server_configs(CONFIG).get(side)
    if server is None:
        raise GhostwriterApiError(f"{side.title()} Ghostwriter server is not configured for API sync.")
    return server


def _start_sync_thread(app: Flask, jobs_dir: Path, job_id: str, side: str) -> None:
    lock_path = _sync_lock_path(jobs_dir, job_id, side)
    _acquire_sync_lock(lock_path, side)
    job = load_job(jobs_dir, job_id)
    try:
        _require_completed_review(job)
        _require_api_backed_side(job, side)
        _require_sync_not_active(job, side)
        job.sync_results[side] = {"status": "running", "stage": "queued", "message": "Queued", "complete": 0, "total": 0}
        save_job(job, jobs_dir)
        thread = threading.Thread(target=_sync_job_side, args=(app, jobs_dir, job_id, side), daemon=True)
        thread.start()
    except Exception:
        _release_sync_lock(lock_path)
        raise


def _sync_job_side(app: Flask, jobs_dir: Path, job_id: str, side: str) -> None:
    with app.app_context():
        def update(event):
            current = load_job(jobs_dir, job_id)
            current.sync_results[side] = {
                "status": event.status,
                "stage": event.stage,
                "message": event.message,
                "complete": event.complete,
                "total": event.total,
            }
            save_job(current, jobs_dir)

        try:
            job = load_job(jobs_dir, job_id)
            _require_completed_review(job)
            _require_api_backed_side(job, side)
            result = finalise_job(job)
            records = result.left_records if side == "left" else result.right_records
            api = GhostwriterApi(_server_for_side(side), progress=update)
            backup_path = api.replace_all_findings(records, backup_root_from_config(CONFIG))
            job = load_job(jobs_dir, job_id)
            job.sync_results[side] = {
                "status": "done",
                "stage": "complete",
                "message": "Sync complete.",
                "complete": len(records),
                "total": len(records),
                "backup_path": str(backup_path),
            }
            save_job(job, jobs_dir)
        except Exception as exc:
            job = load_job(jobs_dir, job_id)
            job.sync_results[side] = {
                "status": "error",
                "stage": "error",
                "message": str(exc),
                "complete": 0,
                "total": 0,
            }
            save_job(job, jobs_dir)
        finally:
            _release_sync_lock(_sync_lock_path(jobs_dir, job_id, side))


def _safe_backup_path(side: str, filename: str) -> Path:
    if side not in {"left", "right"} or "/" in filename or "\\" in filename or not filename.endswith(".json"):
        raise ValueError("Invalid backup path.")
    path = backup_root_from_config(CONFIG) / side / filename
    if not path.exists():
        raise ValueError("Backup not found.")
    return path


def _require_completed_review(job, action: str = "Live API sync") -> None:
    if not job.conflict_phase_complete:
        raise WebMergeError(f"{action} is only available after conflict review is complete.")
    if not job.sensitivity_phase_complete:
        raise WebMergeError(f"{action} is only available after sensitivity review is complete.")


def _require_api_backed_side(job, side: str) -> None:
    if job.input_sources.get(side) != "api":
        raise WebMergeError(f"{side.title()} live API sync is only available for API-backed merge jobs.")


def _require_sync_not_active(job, side: str) -> None:
    status = (job.sync_results.get(side) or {}).get("status")
    if status == "running":
        raise WebMergeError(f"{side.title()} live API sync is already running.")
    if status == "done":
        raise WebMergeError(f"{side.title()} live API sync has already completed.")


def _sync_lock_path(jobs_dir: Path, job_id: str, side: str) -> Path:
    if side not in {"left", "right"}:
        raise WebMergeError("Unknown sync side.")
    return jobs_dir / job_id / f"sync-{side}.lock"


def _acquire_sync_lock(lock_path: Path, side: str) -> None:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with lock_path.open("x", encoding="utf-8") as handle:
            handle.write("running\n")
    except FileExistsError as exc:
        raise WebMergeError(f"{side.title()} live API sync is already running.") from exc


def _release_sync_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink()
    except FileNotFoundError:
        pass


def _require_backup_target_match(backup: dict, server) -> None:
    backup_url = backup.get("graphql_url")
    if not backup_url:
        raise WebMergeError(
            "Backup target is not recorded. Refusing restore to avoid writing data to the wrong deployment."
        )
    if backup_url != server.graphql_url:
        raise WebMergeError(
            "Backup target does not match the currently configured Ghostwriter server. "
            "Refusing restore to avoid writing data to the wrong deployment."
        )


def _load_terms():
    if not CONFIG.get("sensitivity_check_enabled"):
        return None
    return load_sensitive_terms(
        CONFIG["sensitivity_check_terms_file"],
        CONFIG.get("script_dir", Path(__file__).resolve().parent),
    )


if __name__ == "__main__":
    create_app().run(debug=False)

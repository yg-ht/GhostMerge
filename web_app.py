from __future__ import annotations

import json
import hashlib
import hmac
import ipaddress
import os
import secrets
import shutil
import threading
import time
import urllib.parse
import urllib.request
import uuid
import fcntl
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

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
from sensitivity import load_sensitive_terms, sensitive_terms_digest
from utils import load_config
from web_service import (
    MergeResult,
    StaleReviewSubmission,
    WebMergeError,
    approve_output_preview,
    acknowledge_sensitivity_review,
    accept_offered_fields_for_current_match,
    accept_offered_for_current_match,
    acknowledge_current_preview,
    apply_preview_field_choices,
    apply_conflict_decision,
    apply_sensitivity_decision,
    create_manual_match,
    create_merge_job,
    consume_review_action_token,
    ensure_review_action_token,
    finalised_job_result,
    get_active_conflict_position,
    get_current_match_preview,
    get_next_conflict,
    get_orphan_reprocessing_prompt,
    get_manual_matching_prompt,
    get_next_sensitivity_item,
    get_review_progress,
    initialise_sensitivity_review,
    job_summary,
    list_previous_jobs,
    load_job,
    load_records_from_json_text,
    prepare_output_preview,
    reject_current_match,
    reprocess_orphans_for_current_kind,
    reset_match_to_preview,
    run_unattended_reconciliation,
    save_job,
    save_outputs,
    sensitivity_audit_summary,
    stop_orphan_reprocessing_for_current_kind,
    stop_manual_matching_for_current_kind,
)

CONFIG = get_config()
SOURCE_IP_MODES = {"direct", "trusted_header", "both"}
RUNNING_OPERATION_STATUSES = {"running", "cancelling"}
HOME_MERGE_JOB_LIMIT = 3
HISTORY_PAGE_SIZE = 25
_ACTIVE_API_SOURCE_CHECKS: set[str] = set()
_ACTIVE_API_IMPORTS: set[str] = set()


class ApiOperationCancelled(RuntimeError):
    """Raised inside a worker when the user requests cancellation."""


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

    @app.before_request
    def prevent_review_during_unattended_worker():
        review_endpoints = {
            "conflicts",
            "apply_conflict",
            "sensitivity",
            "acknowledge_sensitivity",
            "apply_sensitivity",
            "complete",
            "approve_output",
        }
        if request.endpoint not in review_endpoints:
            return None
        job_id = (request.view_args or {}).get("job_id")
        if not job_id:
            return None
        try:
            job = load_job(jobs_dir, job_id)
        except WebMergeError:
            return None
        if job.unattended.get("status") in {"queued", "running"}:
            return render_template(
                "error.html",
                error="Manual review is locked while the unattended merge worker is running.",
                resume_url=url_for("unattended_status", job_id=job_id),
            ), 409
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
        return render_template("upload.html", **_home_context(jobs_dir), root_page=True)

    @app.get("/api-sources/checks")
    def api_source_checks_history():
        checks, pagination = _paginate_history(
            _list_api_source_checks(jobs_dir),
            request.args.get("page"),
            endpoint="api_source_checks_history",
            label="API source check history pages",
        )
        return render_template("api_source_checks.html", api_source_checks=checks, pagination=pagination)

    @app.get("/imports")
    def api_imports_history():
        imports, pagination = _paginate_history(
            _list_api_imports(jobs_dir),
            request.args.get("page"),
            endpoint="api_imports_history",
            label="Inbound API import history pages",
        )
        return render_template("api_imports.html", api_imports=imports, pagination=pagination)

    @app.get("/jobs")
    def jobs_history():
        jobs, pagination = _paginate_history(
            list_previous_jobs(jobs_dir),
            request.args.get("page"),
            endpoint="jobs_history",
            label="Merge job history pages",
        )
        return render_template("jobs.html", previous_jobs=jobs, pagination=pagination)

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
            input_source_names = _input_source_names(input_sources, request.files)
            left_records = _load_records_for_side("left", request.files.get("left_file"), input_sources["left"])
            right_records = _load_records_for_side("right", request.files.get("right_file"), input_sources["right"])
            job = create_merge_job(
                left_records,
                right_records,
                input_sources=input_sources,
                input_source_names=input_source_names,
                sensitivity_snapshot=_build_sensitivity_snapshot(),
            )
            save_job(job, jobs_dir)
            return redirect(url_for("summary", job_id=job.job_id))
        except (UnicodeDecodeError, WebMergeError, GhostwriterApiError) as exc:
            return render_template(
                "upload.html",
                error=str(exc),
                **_home_context(jobs_dir),
                root_page=True,
            ), 400

    @app.post("/jobs/unattended")
    def create_unattended_job_route():
        try:
            settings = _unattended_settings()
            if not settings.get("enabled", False):
                raise WebMergeError("Unattended API merge is not enabled in configuration.")
            if request.form.get("confirm_unattended_sync") != "yes":
                raise WebMergeError("Confirm the backed-up full replacement of both API destinations.")
            for side in ("left", "right"):
                _server_for_side(side)
            with _unattended_start_lock(jobs_dir):
                running = next(
                    (state for state in _list_api_imports(jobs_dir) if state.get("unattended") and state.get("status") == "running"),
                    None,
                )
                if running:
                    return redirect(url_for("import_status", import_id=running["import_id"]))
                import_id = _start_import_thread(
                    app,
                    jobs_dir,
                    {"left": "api", "right": "api"},
                    request.files,
                    unattended=True,
                )
            return redirect(url_for("import_status", import_id=import_id))
        except (WebMergeError, GhostwriterApiError) as exc:
            return render_template(
                "upload.html",
                error=str(exc),
                **_home_context(jobs_dir),
                root_page=True,
            ), 400

    @app.post("/api-sources/<side>/check")
    def check_api_source(side: str):
        try:
            if side not in {"left", "right"}:
                return render_template("error.html", error="Unknown API source side."), 404
            running_check = _running_api_source_check_for_side(jobs_dir, side)
            if running_check:
                return redirect(url_for("api_source_check_status", check_id=running_check["check_id"]))
            check_id = _start_api_source_check_thread(app, jobs_dir, side)
            return redirect(url_for("api_source_check_status", check_id=check_id))
        except GhostwriterApiError as exc:
            return render_template(
                "upload.html",
                error=str(exc),
                **_home_context(jobs_dir),
                root_page=True,
            ), 400

    @app.get("/api-sources/checks/<check_id>/status")
    def api_source_check_status(check_id: str):
        try:
            state = _load_api_source_check_state(jobs_dir, check_id)
            return render_template("api_source_check_status.html", state=state)
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404

    @app.post("/api-sources/checks/<check_id>/stop")
    def stop_api_source_check(check_id: str):
        try:
            _request_api_source_check_stop(jobs_dir, check_id)
            return redirect(url_for("api_source_check_status", check_id=check_id))
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404

    @app.get("/imports/<import_id>/status")
    def import_status(import_id: str):
        try:
            state = _load_import_state(jobs_dir, import_id)
            if state.get("unattended") and state.get("job_id"):
                return redirect(url_for("unattended_status", job_id=state["job_id"]))
            return render_template("import_status.html", state=state)
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404

    @app.get("/jobs/<job_id>/summary")
    def summary(job_id: str):
        try:
            _recover_stale_unattended_job(jobs_dir, job_id)
            job = load_job(jobs_dir, job_id)
            return render_template(
                "summary.html",
                summary=job_summary(job),
                job=job,
                source_labels=_source_identity_labels(job),
                progress=_review_progress(job),
            )
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404

    @app.get("/jobs/<job_id>/unattended/status")
    def unattended_status(job_id: str):
        try:
            _recover_stale_unattended_job(jobs_dir, job_id)
            job = load_job(jobs_dir, job_id)
            if not job.unattended.get("enabled"):
                raise WebMergeError("This is not an unattended API merge job.")
            return render_template(
                "unattended_status.html",
                job=job,
                state=job.unattended,
                source_labels=_source_identity_labels(job),
                progress=_review_progress(job),
            )
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404

    @app.post("/jobs/<job_id>/unattended/retry/<side>")
    def retry_unattended_sync(job_id: str, side: str):
        try:
            _start_unattended_retry_thread(app, jobs_dir, job_id, side)
            return redirect(url_for("unattended_status", job_id=job_id))
        except (WebMergeError, GhostwriterApiError) as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.get("/jobs/<job_id>/conflicts")
    def conflicts(job_id: str):
        try:
            with _job_state_lock(jobs_dir, job_id):
                job = load_job(jobs_dir, job_id)
                initial_conflict_kind, initial_match_index = get_active_conflict_position(job)
                if not job.preview_acknowledged:
                    preview = get_current_match_preview(job)
                    if preview is not None:
                        ensure_review_action_token(job)
                    save_job(job, jobs_dir)
                    if preview is not None:
                        return render_template(
                            "match_preview.html",
                            job=job,
                            preview=preview,
                            source_labels=_source_identity_labels(job),
                            progress=_review_progress(job),
                        )
                item = get_next_conflict(job)
                if item is not None:
                    ensure_review_action_token(job)
                save_job(job, jobs_dir)
                if item is None:
                    orphan_prompt = get_orphan_reprocessing_prompt(job)
                    if orphan_prompt is not None:
                        ensure_review_action_token(job)
                        save_job(job, jobs_dir)
                        return render_template(
                            "orphan_reprocessing.html",
                            job=job,
                            orphan_prompt=orphan_prompt,
                            source_labels=_source_identity_labels(job),
                            progress=_review_progress(job),
                        )
                    manual_prompt = get_manual_matching_prompt(job)
                    if manual_prompt is not None:
                        save_job(job, jobs_dir)
                        return render_template(
                            "manual_matching.html",
                            job=job,
                            manual_prompt=manual_prompt,
                            source_labels=_source_identity_labels(job),
                            progress=_review_progress(job),
                        )
                    return redirect(url_for("sensitivity", job_id=job.job_id))
                if not job.preview_acknowledged and (
                    item.template_type != initial_conflict_kind or item.match_index != initial_match_index
                ):
                    reset_match_to_preview(job, item.template_type, item.match_index)
                    preview = get_current_match_preview(job)
                    if preview is not None:
                        ensure_review_action_token(job)
                    save_job(job, jobs_dir)
                    if preview is not None:
                        return render_template(
                            "match_preview.html",
                            job=job,
                            preview=preview,
                            source_labels=_source_identity_labels(job),
                            progress=_review_progress(job),
                        )
                    return redirect(url_for("conflicts", job_id=job.job_id))
                return render_template(
                    "conflict.html",
                    job=job,
                    item=item,
                    source_labels=_source_identity_labels(job),
                    progress=_review_progress(job),
                )
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.post("/jobs/<job_id>/conflicts")
    def apply_conflict(job_id: str):
        try:
            with _job_state_lock(jobs_dir, job_id):
                job = load_job(jobs_dir, job_id)
                preview_action = request.form.get("preview_action")
                if preview_action in {
                    "continue",
                    "accept_offered",
                    "accept_selected_offered",
                    "apply_field_choices",
                    "reject_match",
                    "reprocess_orphans",
                    "stop_orphan_reprocessing",
                } or not preview_action:
                    consume_review_action_token(job, request.form.get("review_action_token", ""))
                if preview_action == "continue":
                    acknowledge_current_preview(job)
                elif preview_action == "accept_offered":
                    accept_offered_for_current_match(job)
                elif preview_action == "accept_selected_offered":
                    accept_offered_fields_for_current_match(job, request.form.getlist("selected_fields"))
                elif preview_action == "apply_field_choices":
                    apply_preview_field_choices(job, _preview_field_choices_from_form(request.form))
                elif preview_action == "reject_match":
                    reject_current_match(job)
                elif preview_action == "reprocess_orphans":
                    reprocess_orphans_for_current_kind(job)
                elif preview_action == "stop_orphan_reprocessing":
                    stop_orphan_reprocessing_for_current_kind(job)
                elif preview_action == "create_manual_match":
                    create_manual_match(
                        job,
                        request.form.get("manual_matching_token", ""),
                        request.form.get("left_index"),
                        request.form.get("right_index"),
                    )
                elif preview_action == "stop_manual_matching":
                    stop_manual_matching_for_current_kind(
                        job,
                        request.form.get("manual_matching_token", ""),
                    )
                else:
                    apply_conflict_decision(job, request.form.to_dict())
                save_job(job, jobs_dir)
                return redirect(url_for("conflicts", job_id=job.job_id))
        except StaleReviewSubmission as exc:
            return render_template(
                "error.html",
                error=str(exc),
                resume_url=url_for("conflicts", job_id=job_id),
            ), 409
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.post("/jobs/<job_id>/abandon")
    def abandon_job(job_id: str):
        try:
            with _job_state_lock(jobs_dir, job_id):
                job = load_job(jobs_dir, job_id)
                _require_job_abandonable(job)
                _require_no_running_live_sync(jobs_dir, job)
                _delete_job_directory(jobs_dir, job.job_id)
                return redirect(url_for("index", abandoned=job.job_id))
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.get("/jobs/<job_id>/sensitivity")
    def sensitivity(job_id: str):
        try:
            with _job_state_lock(jobs_dir, job_id):
                job = load_job(jobs_dir, job_id)
                terms = _sensitivity_terms_for_job(job)
                if (
                    job.sensitivity_snapshot_version == 0
                    and CONFIG.get("sensitivity_check_enabled")
                    and terms is None
                ):
                    # Legacy jobs did not persist a load error. Preserve their live
                    # configuration lookup but fail closed when it is unavailable.
                    job.sensitivity_configuration_error = "Configured sensitive-term rules could not be loaded."
                initialise_sensitivity_review(job, terms)
                if job.sensitivity_review_status == "configuration_error":
                    save_job(job, jobs_dir)
                    return render_template(
                        "sensitivity_summary.html",
                        job=job,
                        audit=sensitivity_audit_summary(job),
                        source_labels=_source_identity_labels(job),
                        progress=_review_progress(job),
                    )

                item = get_next_sensitivity_item(job, terms)
                save_job(job, jobs_dir)
                if item is None:
                    return render_template(
                        "sensitivity_summary.html",
                        job=job,
                        audit=sensitivity_audit_summary(job),
                        source_labels=_source_identity_labels(job),
                        progress=_review_progress(job),
                    )
                return render_template(
                    "sensitivity.html",
                    job=job,
                    item=item,
                    source_labels=_source_identity_labels(job),
                    progress=_review_progress(job),
                )
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.post("/jobs/<job_id>/sensitivity/acknowledge")
    def acknowledge_sensitivity(job_id: str):
        try:
            with _job_state_lock(jobs_dir, job_id):
                job = load_job(jobs_dir, job_id)
                acknowledge_sensitivity_review(job)
                save_job(job, jobs_dir)
                return redirect(url_for("complete", job_id=job.job_id))
        except StaleReviewSubmission as exc:
            return render_template(
                "error.html",
                error=str(exc),
                resume_url=url_for("complete", job_id=job_id),
            ), 409
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.post("/jobs/<job_id>/sensitivity")
    def apply_sensitivity(job_id: str):
        try:
            with _job_state_lock(jobs_dir, job_id):
                job = load_job(jobs_dir, job_id)
                apply_sensitivity_decision(
                    job,
                    request.form.to_dict(),
                    terms=_sensitivity_terms_for_job(job),
                )
                save_job(job, jobs_dir)
                return redirect(url_for("sensitivity", job_id=job.job_id))
        except StaleReviewSubmission as exc:
            return render_template(
                "error.html",
                error=str(exc),
                resume_url=url_for("sensitivity", job_id=job_id),
            ), 409
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.get("/jobs/<job_id>/complete")
    def complete(job_id: str):
        try:
            with _job_state_lock(jobs_dir, job_id):
                job = load_job(jobs_dir, job_id)
                _require_completed_review(job, action="Completion")
                if not job.output_phase_complete:
                    preview = prepare_output_preview(job)
                    save_job(job, jobs_dir)
                    return render_template(
                        "final_output_preview.html",
                        job=job,
                        preview=preview,
                        source_labels=_source_identity_labels(job),
                        progress=_review_progress(job),
                    )
                return render_template(
                    "complete.html",
                    job=job,
                    source_labels=_source_identity_labels(job),
                    progress=_review_progress(job),
                    api_servers=configured_server_summary(CONFIG),
                )
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.post("/jobs/<job_id>/complete/approve")
    def approve_output(job_id: str):
        try:
            with _job_state_lock(jobs_dir, job_id):
                job = load_job(jobs_dir, job_id)
                _require_completed_review(job, action="Output approval")
                if job.output_phase_complete:
                    raise StaleReviewSubmission("Final output has already been approved and created.")
                result = approve_output_preview(job, request.form.get("approval_token", ""))
                save_outputs(job, jobs_dir, result)
                return redirect(url_for("complete", job_id=job.job_id))
        except StaleReviewSubmission as exc:
            return render_template(
                "error.html",
                error=str(exc),
                resume_url=url_for("complete", job_id=job_id),
            ), 409
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 400

    @post_or_get(app, "/jobs/<job_id>/sync/<side>")
    def sync_side(job_id: str, side: str):
        if side not in {"left", "right"}:
            return render_template("error.html", error="Unknown sync side."), 404
        try:
            job = load_job(jobs_dir, job_id)
            _require_output_ready(job)
            _require_api_backed_side(job, side)
            if request.method == "GET":
                return render_template(
                    "sync_confirm.html",
                    job=job,
                    side=side,
                    server=_server_for_side(side),
                    source_labels=_source_identity_labels(job),
                    progress=_review_progress(job),
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
                source_labels=_source_identity_labels(job),
                progress=_review_progress(job),
            )
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404

    @app.get("/api-backups")
    def api_backups():
        return render_template(
            "api_backups.html",
            backups=list_backups(backup_root_from_config(CONFIG)),
            deleted_backup=request.args.get("deleted"),
        )

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

    @app.post("/api-backups/<side>/<filename>/delete")
    def api_backup_delete(side: str, filename: str):
        try:
            backup_path = _safe_backup_path(side, filename)
            verify_backup(backup_path)
            backup_path.unlink()
            return redirect(url_for("api_backups", deleted=filename))
        except (GhostwriterApiError, ValueError, OSError) as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.post("/api-backups/<side>/<filename>/<int:index>/restore")
    @app.post("/api-backups/<side>/<filename>/<template_type>/<int:index>/restore")
    def api_backup_restore(side: str, filename: str, index: int, template_type: str = "finding"):
        try:
            if template_type not in {"finding", "observation"}:
                raise ValueError("Unknown backup template type.")
            backup_path = _safe_backup_path(side, filename)
            record = load_backup_record(backup_path, index, template_type=template_type)
            server = _server_for_side(side)
            _require_backup_target_match(record["backup"], server)
            api = GhostwriterApi(server)
            restore_action = request.form.get("restore_action") or "check"
            if restore_action not in {"check", "replace", "add", "skip"}:
                raise ValueError("Unknown restore action.")
            if template_type == "observation":
                candidates = api.find_observation_restore_candidates(record)
            else:
                candidates = api.find_restore_candidates(record)
            if restore_action == "check" and candidates:
                return render_template(
                    "api_restore_confirm.html",
                    template_type=template_type,
                    side=side,
                    server_name=server.name,
                    filename=filename,
                    index=index,
                    record=record["normalised_record"],
                    candidates=candidates,
                )
            if restore_action == "skip":
                return redirect(url_for("api_backup_detail", side=side, filename=filename))
            if restore_action == "replace":
                existing_id = _selected_restore_candidate_id(request.form.get("existing_id"), candidates)
                if template_type == "observation":
                    created_id = api.restore_observation_backup_record(record, replace_existing_id=existing_id)
                else:
                    created_id = api.restore_backup_record(record, replace_existing_id=existing_id)
                restore_mode = "replaced"
            else:
                if template_type == "observation":
                    created_id = api.restore_observation_backup_record(record)
                else:
                    created_id = api.restore_backup_record(record)
                restore_mode = "added"
            return render_template(
                "api_restore_complete.html",
                template_type=template_type,
                side=side,
                server_name=server.name,
                filename=filename,
                record=record["normalised_record"],
                created_id=created_id,
                restore_mode=restore_mode,
            )
        except (GhostwriterApiError, ValueError) as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.get("/jobs/<job_id>/download/<side>")
    def download(job_id: str, side: str):
        if side not in {"left", "right"}:
            return render_template("error.html", error="Unknown output side."), 404
        try:
            job = load_job(jobs_dir, job_id)
        except WebMergeError as exc:
            return render_template("error.html", error=str(exc)), 404
        path = jobs_dir / job_id / f"{side}.json"
        if not job.output_phase_complete or not path.exists():
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


def _home_context(jobs_dir: Path) -> dict[str, Any]:
    previous_jobs = list_previous_jobs(jobs_dir)
    api_servers = configured_server_summary(CONFIG)
    return {
        "previous_jobs": previous_jobs[:HOME_MERGE_JOB_LIMIT],
        "previous_jobs_total": len(previous_jobs),
        "running_api_source_checks": _running_api_source_checks_by_side(jobs_dir),
        "api_servers": api_servers,
        "unattended_available": bool(_unattended_settings().get("enabled", False)) and all(
            api_servers[side]["configured"] for side in ("left", "right")
        ),
        "abandoned_job": request.args.get("abandoned"),
    }


def _paginate_history(
    items: list[Any],
    requested_page: Any,
    *,
    endpoint: str,
    label: str,
) -> tuple[list[Any], dict[str, Any]]:
    """Return one stable history slice and accessible navigation metadata."""
    total_items = len(items)
    total_pages = max(1, (total_items + HISTORY_PAGE_SIZE - 1) // HISTORY_PAGE_SIZE)
    try:
        page = int(requested_page)
    except (TypeError, ValueError):
        page = 1
    page = min(max(1, page), total_pages)
    start = (page - 1) * HISTORY_PAGE_SIZE
    return (
        items[start : start + HISTORY_PAGE_SIZE],
        {
            "page": page,
            "total_pages": total_pages,
            "total_items": total_items,
            "previous_page": page - 1 if page > 1 else None,
            "next_page": page + 1 if page < total_pages else None,
            "endpoint": endpoint,
            "label": label,
        },
    )


def _human_file_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


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
        return _fetch_template_library(GhostwriterApi(server))
    if uploaded_file is None or uploaded_file.filename == "":
        raise WebMergeError(f"{side.title()} JSON file is required when that side is file-backed.")
    return load_records_from_json_text(uploaded_file.read().decode("utf-8"))


def _fetch_template_library(api: GhostwriterApi) -> dict[str, list[dict[str, Any]]] | list[dict[str, Any]]:
    if hasattr(api, "fetch_template_library"):
        return api.fetch_template_library()
    return api.fetch_findings()


def _preview_field_choices_from_form(form) -> dict[str, str]:
    prefix = "field_choice:"
    return {
        key[len(prefix) :]: value
        for key, value in form.items()
        if key.startswith(prefix) and value
    }


def _safe_display_name(value: Any, fallback: str, *, filename: bool = False) -> str:
    """Return bounded printable text suitable for an escaped UI label."""
    raw_value = str(value or "")
    if filename:
        # Browsers may submit either POSIX or Windows-style client paths.
        raw_value = raw_value.replace("\\", "/").rsplit("/", 1)[-1]
    printable = "".join(character if character.isprintable() else " " for character in raw_value)
    normalised = " ".join(printable.split()).strip()
    return (normalised or fallback)[:160]


def _input_source_names(input_sources: dict[str, str], files) -> dict[str, str]:
    """Snapshot stable human-readable source names at the request boundary."""
    names: dict[str, str] = {}
    for side in ("left", "right"):
        if input_sources.get(side) == "api":
            server = _server_for_side(side)
            names[side] = _safe_display_name(server.name, f"{side.title()} Ghostwriter")
        else:
            uploaded_file = files.get(f"{side}_file")
            names[side] = _safe_display_name(
                getattr(uploaded_file, "filename", ""),
                f"{side.title()} uploaded JSON",
                filename=True,
            )
    return names


def _source_identity_labels(job) -> dict[str, str]:
    """Return stable name-and-type labels, including safe legacy fallbacks."""
    labels: dict[str, str] = {}
    api_servers = configured_server_summary(CONFIG)

    for side in ("left", "right"):
        source_type = job.input_sources.get(side, "file")
        source_name = job.input_source_names.get(side)
        if not source_name and source_type == "api":
            server = api_servers.get(side)
            if server and server.get("configured"):
                source_name = server.get("name")
        fallback = f"{side.title()} Ghostwriter" if source_type == "api" else f"{side.title()} uploaded JSON"
        source_name = _safe_display_name(source_name, fallback)
        labels[side] = f"{source_name} ({'API' if source_type == 'api' else 'JSON file'})"

    return labels


def _review_progress(job) -> dict[str, Any]:
    """Attach source identity to the existing workflow progress metrics."""
    progress = get_review_progress(job)
    progress["source_labels"] = _source_identity_labels(job)
    return progress


@contextmanager
def _job_state_lock(jobs_dir: Path, job_id: str):
    """Serialise read-modify-write review transactions across threads and workers."""
    if not job_id or not job_id.isalnum():
        raise WebMergeError("Invalid job ID.")
    job_dir = jobs_dir / job_id
    if not job_dir.is_dir():
        raise WebMergeError("Job not found.")
    lock_path = job_dir / ".review.lock"
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


@contextmanager
def _unattended_start_lock(jobs_dir: Path):
    """Serialise the check-and-start operation across web workers."""
    lock_path = jobs_dir / ".unattended-start.lock"
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _start_api_source_check_thread(app: Flask, jobs_dir: Path, side: str) -> str:
    server = _server_for_side(side)
    check_id = uuid.uuid4().hex
    _ACTIVE_API_SOURCE_CHECKS.add(check_id)
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
            "worker_pid": os.getpid(),
        },
    )
    thread = threading.Thread(target=_check_api_source, args=(app, jobs_dir, check_id), daemon=True)
    try:
        thread.start()
    except Exception:
        _ACTIVE_API_SOURCE_CHECKS.discard(check_id)
        raise
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
            _raise_if_api_source_check_cancelled(jobs_dir, check_id)

            def update(event):
                current = _load_api_source_check_state(jobs_dir, check_id)
                if current.get("cancel_requested"):
                    raise ApiOperationCancelled("API source check was cancelled by the user.")
                current.update(
                    {
                        "status": "running",
                        "stage": event.stage,
                        "message": event.message,
                        "complete": event.complete,
                        "total": event.total,
                        "worker_pid": os.getpid(),
                    }
                )
                _save_api_source_check_state(jobs_dir, check_id, current)

            counts = GhostwriterApi(server, progress=update).fetch_template_counts()
            findings_count = counts["findings"]
            observations_count = counts["observations"]
            total_count = findings_count + observations_count
            state = _load_api_source_check_state(jobs_dir, check_id)
            state.update(
                {
                    "status": "done",
                    "stage": "complete",
                    "message": (
                        f"Connected to {server.name}; found {findings_count} Finding(s) "
                        f"and {observations_count} Observation(s)."
                    ),
                    "complete": total_count,
                    "total": total_count,
                    "backup_filename": None,
                    "record_count": findings_count,
                    "observation_count": observations_count,
                }
            )
            _save_api_source_check_state(jobs_dir, check_id, state)
        except ApiOperationCancelled as exc:
            state.update({"status": "cancelled", "stage": "cancelled", "message": str(exc)})
            _save_api_source_check_state(jobs_dir, check_id, state)
        except Exception as exc:
            state.update({"status": "error", "stage": "error", "message": str(exc)})
            _save_api_source_check_state(jobs_dir, check_id, state)
        finally:
            _ACTIVE_API_SOURCE_CHECKS.discard(check_id)


def _start_import_thread(
    app: Flask,
    jobs_dir: Path,
    input_sources: dict[str, str],
    files,
    *,
    unattended: bool = False,
) -> str:
    import_id = uuid.uuid4().hex
    input_source_names = _input_source_names(input_sources, files)
    file_records: dict[str, list[dict]] = {}
    for side in ("left", "right"):
        if input_sources[side] == "file":
            # Uploaded files only live for the request, so parse and persist them before the worker starts.
            file_records[side] = _load_records_for_side(side, files.get(f"{side}_file"), "file")
        else:
            _server_for_side(side)
    api_sides = [side for side in ("left", "right") if input_sources[side] == "api"]
    api_estimated_totals = {side: _last_known_api_template_counts(jobs_dir, side) for side in api_sides}
    sensitivity_snapshot = _build_sensitivity_snapshot()
    _ACTIVE_API_IMPORTS.add(import_id)
    _save_import_state(
        jobs_dir,
        import_id,
        {
            "import_id": import_id,
            "operation": "inbound_api_import",
            "direction": "inbound",
            "status": "running",
            "stage": "queued",
            "message": "Queued inbound API import.",
            "complete": 0,
            "total": len(api_sides),
            "api_estimated_totals": api_estimated_totals,
            "input_sources": input_sources,
            "input_source_names": input_source_names,
            "file_records": file_records,
            "sensitivity_snapshot": sensitivity_snapshot,
            "job_id": None,
            "unattended": unattended,
            "worker_pid": os.getpid(),
        },
    )
    thread = threading.Thread(target=_import_job_sources, args=(app, jobs_dir, import_id), daemon=True)
    try:
        thread.start()
    except Exception:
        _ACTIVE_API_IMPORTS.discard(import_id)
        raise
    return import_id


def _import_job_sources(app: Flask, jobs_dir: Path, import_id: str) -> None:
    with app.app_context():
        failure_source_context: Optional[tuple[str, str, int, int]] = None
        state = {
            "import_id": import_id,
            "operation": "inbound_api_import",
            "direction": "inbound",
            "status": "error",
            "stage": "error",
            "message": "Inbound API import failed before state could be loaded.",
            "complete": 0,
            "total": 0,
            "job_id": None,
        }
        try:
            state = _load_import_state(jobs_dir, import_id)
            input_sources = state["input_sources"]
            records = dict(state.get("file_records") or {})
            api_estimated_totals = state.get("api_estimated_totals") or {}
            api_sides = [side for side in ("left", "right") if input_sources[side] == "api"]
            for index, side in enumerate(api_sides, start=1):
                source_name = (state.get("input_source_names") or {}).get(side) or f"{side.title()} Ghostwriter"
                failure_source_context = (source_name, side, index, len(api_sides))
                estimate_fields = _api_estimate_state_fields(api_estimated_totals.get(side))
                state = _load_import_state(jobs_dir, import_id)
                state.update(
                    {
                        "status": "running",
                        "stage": f"fetch_{side}",
                        "message": f"Connecting to {source_name}.",
                        "complete": index - 1,
                        "total": len(api_sides),
                        "side": side,
                        "side_name": source_name,
                        "side_index": index,
                        "side_total": len(api_sides),
                        "api_stage": "connect",
                        "api_complete": 0,
                        "api_total": 0,
                        **estimate_fields,
                        "api_status": "running",
                        "worker_pid": os.getpid(),
                    }
                )
                _save_import_state(jobs_dir, import_id, state)

                server = _server_for_side(side)
                source_name = server.name
                failure_source_context = (source_name, side, index, len(api_sides))
                state = _load_import_state(jobs_dir, import_id)
                state["side_name"] = source_name
                _save_import_state(jobs_dir, import_id, state)

                def update(event, current_side=side, current_index=index):
                    current = _load_import_state(jobs_dir, import_id)
                    current_estimate_fields = _api_estimate_state_fields(api_estimated_totals.get(current_side))
                    current.update(
                        {
                            "status": event.status if event.status != "done" else "running",
                            "stage": f"fetch_{current_side}",
                            "message": event.message,
                            "complete": current_index - 1,
                            "total": len(api_sides),
                            "side": current_side,
                            "side_name": server.name,
                            "side_index": current_index,
                            "side_total": len(api_sides),
                            "api_stage": event.stage,
                            "api_complete": event.complete,
                            "api_total": event.total,
                            **current_estimate_fields,
                            # A template-library import emits a "done" event for
                            # Findings before Observations begin. Keep that
                            # component event visibly in progress until the
                            # complete library has returned below.
                            "api_status": event.status if event.status != "done" else "running",
                            "worker_pid": os.getpid(),
                        }
                    )
                    _save_import_state(jobs_dir, import_id, current)

                records[side] = _fetch_template_library(GhostwriterApi(server, progress=update))
                state = _load_import_state(jobs_dir, import_id)
                state.update(
                    {
                        "status": "running",
                        "stage": f"fetched_{side}",
                        "message": f"Fetched {side} API source.",
                        "complete": index,
                        "total": len(api_sides),
                        "side": side,
                        "side_name": server.name,
                        "side_index": index,
                        "side_total": len(api_sides),
                        "api_stage": "fetch",
                        "api_complete": _template_record_count(records[side]),
                        "api_total": _template_record_count(records[side]),
                        **estimate_fields,
                        "api_status": "done",
                        "worker_pid": os.getpid(),
                    }
                )
                _save_import_state(jobs_dir, import_id, state)
                failure_source_context = None
            job = create_merge_job(
                records["left"],
                records["right"],
                input_sources=input_sources,
                input_source_names=state.get("input_source_names"),
                sensitivity_snapshot=state.get("sensitivity_snapshot"),
            )
            save_job(job, jobs_dir)
            if state.get("unattended"):
                state = _load_import_state(jobs_dir, import_id)
                state.update(
                    {
                        "status": "running",
                        "stage": "automatic_merge",
                        "message": "Applying unattended merge rules.",
                        "job_id": job.job_id,
                    }
                )
                _save_import_state(jobs_dir, import_id, state)
                _run_unattended_job(app, jobs_dir, job.job_id)
                job = load_job(jobs_dir, job.job_id)
            state = _load_import_state(jobs_dir, import_id)
            unattended_status = job.unattended.get("status") if state.get("unattended") else None
            state.update(
                {
                    "status": "error" if unattended_status == "failed" else "done",
                    "stage": unattended_status or "complete",
                    "message": (
                        job.unattended.get("message", "Unattended API merge finished.")
                        if state.get("unattended")
                        else "Inbound API import complete."
                    ),
                    "complete": len(api_sides),
                    "total": len(api_sides),
                    "api_status": "done",
                    "job_id": job.job_id,
                }
            )
            # Drop copied records once the durable merge job exists so the import file does not duplicate data.
            state.pop("file_records", None)
            state.pop("sensitivity_snapshot", None)
            _save_import_state(jobs_dir, import_id, state)
        except Exception as exc:
            message = str(exc)
            if failure_source_context is not None:
                source_name, side, index, side_total = failure_source_context
                message = f"Failed to import {source_name} ({side.title()}, {index} / {side_total}): {message}"
            state.update({"status": "error", "stage": "error", "message": message})
            _save_import_state(jobs_dir, import_id, state)
        finally:
            _ACTIVE_API_IMPORTS.discard(import_id)


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


def _request_api_source_check_stop(jobs_dir: Path, check_id: str) -> None:
    state = _load_api_source_check_state(jobs_dir, check_id)
    if state.get("status") not in RUNNING_OPERATION_STATUSES:
        return
    state.update(
        {
            "status": "cancelling",
            "stage": "cancelling",
            "message": "Stop requested. Waiting for the current API request to finish.",
            "cancel_requested": True,
        }
    )
    _save_api_source_check_state(jobs_dir, check_id, state)


def _raise_if_api_source_check_cancelled(jobs_dir: Path, check_id: str) -> None:
    state = _load_api_source_check_state(jobs_dir, check_id)
    if state.get("cancel_requested"):
        raise ApiOperationCancelled("API source check was cancelled by the user.")


def _load_api_source_check_state(jobs_dir: Path, check_id: str) -> dict:
    path = _api_source_check_state_path(jobs_dir, check_id)
    if not path.exists():
        raise WebMergeError("API source check not found.")
    try:
        return _operation_state_with_liveness(
            json.loads(path.read_text(encoding="utf-8")),
            "API source check",
            _ACTIVE_API_SOURCE_CHECKS,
        )
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
        state["updated_at"] = _human_file_mtime(path)
        checks.append(_operation_state_with_liveness(state, "API source check", _ACTIVE_API_SOURCE_CHECKS))
    return checks


def _running_api_source_checks_by_side(jobs_dir: Path) -> dict[str, dict[str, Any]]:
    running = {}
    for state in _list_api_source_checks(jobs_dir):
        side = state.get("side")
        if side in {"left", "right"} and state.get("status") in RUNNING_OPERATION_STATUSES:
            running.setdefault(side, state)
    return running


def _running_api_source_check_for_side(jobs_dir: Path, side: str) -> Optional[dict[str, Any]]:
    return _running_api_source_checks_by_side(jobs_dir).get(side)


def _last_known_api_template_counts(jobs_dir: Path, side: str) -> Optional[dict[str, Optional[int]]]:
    """Return separated historical counts so unlike template types are not compared."""
    for state in _list_api_source_checks(jobs_dir):
        if state.get("side") == side and state.get("status") == "done":
            findings = _optional_positive_int(state.get("record_count"))
            if findings is not None:
                return {
                    "findings": findings,
                    "observations": _optional_positive_int(state.get("observation_count")),
                }

    for backup in list_backups(backup_root_from_config(CONFIG)):
        if backup.get("side") == side:
            findings = _optional_positive_int(backup.get("record_count"))
            if findings is not None:
                return {
                    "findings": findings,
                    "observations": _optional_positive_int(backup.get("observation_count")),
                }

    return None


def _api_estimate_state_fields(counts: Any) -> dict[str, Optional[int]]:
    """Flatten separated estimates into backwards-compatible import state fields."""
    if not isinstance(counts, dict):
        legacy_total = _optional_positive_int(counts)
        return {
            "api_estimated_total": legacy_total,
            "api_estimated_findings": None,
            "api_estimated_observations": None,
        }

    findings = _optional_positive_int(counts.get("findings"))
    observations = _optional_positive_int(counts.get("observations"))
    total = findings + observations if findings is not None and observations is not None else None
    return {
        "api_estimated_total": total,
        "api_estimated_findings": findings,
        "api_estimated_observations": observations,
    }


def _optional_positive_int(value: Any) -> Optional[int]:
    try:
        count = int(value)
    except (TypeError, ValueError):
        return None
    return count if count >= 0 else None


def _template_record_count(records: Any) -> int:
    if isinstance(records, list):
        return len(records)
    if isinstance(records, dict):
        return len(records.get("findings", [])) + len(records.get("observations", []))
    return 0


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
        state = json.loads(path.read_text(encoding="utf-8"))
        state.setdefault("operation", "inbound_api_import")
        state.setdefault("direction", "inbound")
        return _operation_state_with_liveness(
            state,
            "API import",
            _ACTIVE_API_IMPORTS,
        )
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
        state.setdefault("operation", "inbound_api_import")
        state.setdefault("direction", "inbound")
        state["updated_at"] = _human_file_mtime(path)
        imports.append(_operation_state_with_liveness(state, "API import", _ACTIVE_API_IMPORTS))
    return imports


def _operation_state_with_liveness(
    state: dict[str, Any],
    operation_name: str,
    active_operation_ids: set[str],
) -> dict[str, Any]:
    if state.get("status") not in RUNNING_OPERATION_STATUSES:
        return state
    worker_pid = state.get("worker_pid")
    operation_id = state.get("check_id") or state.get("import_id")
    if _worker_pid_is_alive(worker_pid) and operation_id in active_operation_ids:
        return state
    stale_state = dict(state)
    stale_state.update(
        {
            "status": "stale",
            "stage": "stale",
            "message": (
                f"{operation_name} was marked running, but its worker process is no longer active. "
                "It may have been interrupted by a service restart."
            ),
        }
    )
    return stale_state


def _worker_pid_is_alive(worker_pid: Any) -> bool:
    try:
        pid = int(worker_pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _server_for_side(side: str):
    server = load_server_configs(CONFIG).get(side)
    if server is None:
        raise GhostwriterApiError(f"{side.title()} Ghostwriter server is not configured for API sync.")
    return server


def _unattended_settings() -> dict[str, Any]:
    settings = CONFIG.get("unattended_api_merge") or {}
    return settings if isinstance(settings, dict) else {}


def _start_sync_thread(app: Flask, jobs_dir: Path, job_id: str, side: str) -> None:
    lock_path = _sync_lock_path(jobs_dir, job_id, side)
    _acquire_sync_lock(lock_path, side)
    job = load_job(jobs_dir, job_id)
    try:
        _require_output_ready(job)
        _require_api_backed_side(job, side)
        _require_sync_not_active(job, side)
        job.sync_results[side] = {
            "operation": "outbound_api_sync",
            "direction": "outbound",
            "side": side,
            "status": "running",
            "stage": "queued",
            "message": "Queued outbound API sync.",
            "complete": 0,
            "total": 0,
        }
        save_job(job, jobs_dir)
        thread = threading.Thread(target=_sync_job_side, args=(app, jobs_dir, job_id, side), daemon=True)
        thread.start()
    except Exception:
        _release_sync_lock(lock_path)
        raise


def _merge_result_from_state(state: dict[str, Any]) -> MergeResult:
    """Validate and reconstruct one persisted unattended output snapshot."""
    required_fields = (
        "left_records",
        "right_records",
        "left_observations",
        "right_observations",
    )
    if not all(isinstance(state.get(field_name), list) for field_name in required_fields):
        raise WebMergeError("Persisted unattended output is incomplete.")
    return MergeResult(**{field_name: list(state[field_name]) for field_name in required_fields})


def _run_unattended_job(app: Flask, jobs_dir: Path, job_id: str) -> None:
    """Reconcile and replace both API libraries while retaining manual work."""
    try:
        job = load_job(jobs_dir, job_id)
        job.unattended = {
            "enabled": True,
            "status": "queued",
            "stage": "automatic_merge",
            "message": "Applying unattended merge rules.",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "worker_pid": os.getpid(),
        }
        save_job(job, jobs_dir)
        run_unattended_reconciliation(job)
        job.unattended["message"] = "Automatic reconciliation completed."
        job.unattended["worker_pid"] = os.getpid()
        save_job(job, jobs_dir)
        _discard_superseded_unattended_jobs(jobs_dir, job.job_id)

        if job.unattended.get("sync_blocked_by_sensitivity"):
            job.unattended.update(
                {
                    "status": "needs_review",
                    "stage": "sensitivity_review_required",
                    "message": "Automatic work was saved, but sensitivity review is required before API sync.",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            job.unattended.pop("worker_pid", None)
            save_job(job, jobs_dir)
            _deliver_unattended_webhook(jobs_dir, job.job_id)
            return

        if job.conflict_phase_complete:
            job.sensitivity_phase_complete = True
            job.sensitivity_review_initialised = True
            job.sensitivity_review_status = "complete"
            job.sensitivity_review_outcome = "unattended_no_hits"
            job.sensitivity_review_started_at = datetime.now(timezone.utc).isoformat()
            job.sensitivity_review_completed_at = job.sensitivity_review_started_at
            prepare_output_preview(job)
            approved = approve_output_preview(job, job.output_preview_token or "")
            save_outputs(job, jobs_dir, approved)

        for side in ("left", "right"):
            job = load_job(jobs_dir, job_id)
            job.unattended.update(
                {
                    "status": "running",
                    "stage": f"sync_{side}",
                    "message": f"Synchronising {side} API destination.",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            job.sync_results[side] = {
                "operation": "unattended_outbound_sync",
                "direction": "outbound",
                "side": side,
                "status": "running",
                "stage": "queued",
                "message": "Queued unattended outbound API sync.",
                "complete": 0,
                "total": 0,
            }
            save_job(job, jobs_dir)
            lock_path = _sync_lock_path(jobs_dir, job_id, side)
            try:
                _acquire_sync_lock(lock_path, side)
            except Exception as exc:
                job = load_job(jobs_dir, job_id)
                job.sync_results[side].update(
                    {"status": "error", "stage": "error", "message": str(exc)}
                )
                save_job(job, jobs_dir)
                continue
            _sync_job_side(app, jobs_dir, job_id, side, unattended=True)

        _finalise_unattended_state(jobs_dir, job_id)
        _deliver_unattended_webhook(jobs_dir, job_id)
    except Exception as exc:
        try:
            job = load_job(jobs_dir, job_id)
            job.unattended.update(
                {
                    "enabled": True,
                    "status": "failed",
                    "stage": "failed",
                    "message": str(exc),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            job.unattended.pop("worker_pid", None)
            save_job(job, jobs_dir)
            _deliver_unattended_webhook(jobs_dir, job_id)
        except Exception:
            pass


def _finalise_unattended_state(jobs_dir: Path, job_id: str) -> None:
    job = load_job(jobs_dir, job_id)
    failed_sides = [
        side for side in ("left", "right")
        if (job.sync_results.get(side) or {}).get("status") != "done"
    ]
    pending_count = int(job.unattended.get("pending_findings", 0)) + int(
        job.unattended.get("pending_observations", 0)
    )
    if failed_sides:
        status = "partially_completed" if len(failed_sides) == 1 else "failed"
        message = f"Unattended sync failed for: {', '.join(failed_sides)}."
    elif pending_count:
        status = "needs_review"
        message = "Automatic work was synchronised; manual merge items remain."
    else:
        status = "complete"
        message = "Unattended API merge and bilateral synchronisation completed."
    job.unattended.update(
        {"status": status, "stage": status, "message": message, "updated_at": datetime.now(timezone.utc).isoformat()}
    )
    job.unattended.pop("worker_pid", None)
    save_job(job, jobs_dir)


def _start_unattended_retry_thread(app: Flask, jobs_dir: Path, job_id: str, side: str) -> None:
    if side not in {"left", "right"}:
        raise WebMergeError("Unknown sync side.")
    _recover_stale_unattended_job(jobs_dir, job_id)
    job = load_job(jobs_dir, job_id)
    if not job.unattended.get("enabled") or not isinstance(job.unattended_output, dict):
        raise WebMergeError("This job has no unattended output to retry.")
    if (job.sync_results.get(side) or {}).get("status") != "error":
        raise WebMergeError(f"{side.title()} unattended sync is not awaiting retry.")
    lock_path = _sync_lock_path(jobs_dir, job_id, side)
    _acquire_sync_lock(lock_path, side)
    job.unattended.update({"status": "running", "stage": f"retry_{side}", "message": f"Retrying {side} API sync.", "worker_pid": os.getpid()})
    save_job(job, jobs_dir)

    def worker() -> None:
        _sync_job_side(app, jobs_dir, job_id, side, unattended=True)
        _finalise_unattended_state(jobs_dir, job_id)
        _deliver_unattended_webhook(jobs_dir, job_id)

    try:
        threading.Thread(target=worker, daemon=True).start()
    except Exception:
        _release_sync_lock(lock_path)
        _finalise_unattended_state(jobs_dir, job_id)
        raise


def _discard_superseded_unattended_jobs(jobs_dir: Path, newest_job_id: str) -> None:
    """Keep only the latest durable unattended job containing unresolved review work."""
    for item in list_previous_jobs(jobs_dir):
        if item.job_id == newest_job_id or not item.unattended.get("enabled"):
            continue
        pending = int(item.unattended.get("pending_findings", 0)) + int(item.unattended.get("pending_observations", 0))
        if not pending and not item.unattended.get("sync_blocked_by_sensitivity"):
            continue
        try:
            _recover_stale_unattended_job(jobs_dir, item.job_id)
            old_job = load_job(jobs_dir, item.job_id)
            _require_no_running_live_sync(jobs_dir, old_job)
        except WebMergeError:
            continue
        _delete_job_directory(jobs_dir, item.job_id)
        imports_dir = jobs_dir / "api_imports"
        for import_path in imports_dir.glob("*.json") if imports_dir.exists() else ():
            try:
                import_state = json.loads(import_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if import_state.get("job_id") == item.job_id and import_state.get("unattended"):
                import_path.unlink(missing_ok=True)


def _recover_stale_unattended_job(jobs_dir: Path, job_id: str) -> None:
    """Turn an interrupted worker into a retryable durable state after restart."""
    try:
        job = load_job(jobs_dir, job_id)
    except WebMergeError:
        return
    if not job.unattended.get("enabled") or job.unattended.get("status") not in {"queued", "running"}:
        return
    if _worker_pid_is_alive(job.unattended.get("worker_pid")):
        return
    for side in ("left", "right"):
        state = job.sync_results.get(side) or {}
        if state.get("status") != "done":
            state.update({
                "operation": "unattended_outbound_sync",
                "direction": "outbound",
                "side": side,
                "status": "error",
                "stage": "interrupted",
                "message": "The unattended worker stopped before this API sync completed; retry is available.",
            })
            job.sync_results[side] = state
        _release_sync_lock(_sync_lock_path(jobs_dir, job_id, side))
    job.unattended.pop("worker_pid", None)
    job.unattended.update({
        "status": "failed",
        "stage": "interrupted",
        "message": "The unattended worker was interrupted; failed API sides can be retried.",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })
    save_job(job, jobs_dir)


def _deliver_unattended_webhook(jobs_dir: Path, job_id: str) -> None:
    settings = _unattended_settings().get("webhook") or {}
    if not isinstance(settings, dict) or not settings.get("enabled", False):
        return
    url = str(settings.get("url") or "").strip()
    secret = str(settings.get("secret") or "")
    parsed = urllib.parse.urlsplit(url)
    allow_http = bool(settings.get("allow_insecure_http", False))
    job = load_job(jobs_dir, job_id)
    if not url or not secret or parsed.scheme not in ({"https", "http"} if allow_http else {"https"}):
        _persist_unattended_webhook_state(jobs_dir, job_id, {
            "status": "failed",
            "error": "Webhook requires an HTTPS URL and a non-empty secret.",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        return
    fingerprint = f"{job.unattended.get('status')}:{','.join(str((job.sync_results.get(s) or {}).get('status')) for s in ('left', 'right'))}"
    previous = job.unattended.get("webhook") or {}
    if previous.get("fingerprint") == fingerprint and previous.get("status") == "delivered":
        return
    event_id = uuid.uuid4().hex
    base_url = str(settings.get("public_base_url") or "").rstrip("/")
    payload = {
        "event": "ghostmerge.unattended.completed",
        "event_id": event_id,
        "job_id": job.job_id,
        "status": job.unattended.get("status"),
        "counts": {key: int(job.unattended.get(key, 0)) for key in ("automatic_findings", "automatic_observations", "pending_findings", "pending_observations", "orphans_copied")},
        "sources": dict(job.input_source_names),
        "sync": {side: {"status": (job.sync_results.get(side) or {}).get("status"), "stage": (job.sync_results.get(side) or {}).get("stage")} for side in ("left", "right")},
        "resume_url": f"{base_url}/jobs/{job.job_id}/summary" if base_url else f"/jobs/{job.job_id}/summary",
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    try:
        attempts = max(1, min(int(settings.get("max_attempts", 3)), 5))
        timeout = max(1.0, min(float(settings.get("timeout_seconds", 5)), 30.0))
    except (TypeError, ValueError):
        _persist_unattended_webhook_state(jobs_dir, job_id, {
            "status": "failed",
            "error": "Webhook timeout and attempt settings are invalid.",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        return
    error = None
    delivered = False
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json",
            "X-GhostMerge-Event": payload["event"],
            "X-GhostMerge-Event-ID": event_id,
            "X-GhostMerge-Signature": f"sha256={signature}",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                delivered = 200 <= int(response.status) < 300
                if not delivered:
                    error = f"Webhook returned HTTP {response.status}."
        except Exception as exc:
            error = str(exc)
        if delivered:
            break
        if attempt < attempts:
            time.sleep(min(attempt, 2))
    _persist_unattended_webhook_state(jobs_dir, job_id, {
        "status": "delivered" if delivered else "failed",
        "event_id": event_id,
        "fingerprint": fingerprint,
        "attempts": attempt,
        "error": None if delivered else error,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


def _persist_unattended_webhook_state(jobs_dir: Path, job_id: str, state: dict[str, Any]) -> None:
    with _job_state_lock(jobs_dir, job_id):
        job = load_job(jobs_dir, job_id)
        job.unattended["webhook"] = state
        save_job(job, jobs_dir)


def _sync_job_side(
    app: Flask,
    jobs_dir: Path,
    job_id: str,
    side: str,
    *,
    unattended: bool = False,
) -> None:
    with app.app_context():
        operation = "unattended_outbound_sync" if unattended else "outbound_api_sync"

        def update(event):
            current = load_job(jobs_dir, job_id)
            previous_state = dict(current.sync_results.get(side) or {})
            next_state = {
                "operation": operation,
                "direction": "outbound",
                "side": side,
                # Fetch and backup helpers report their own local completion.  The outbound
                # operation is complete only after the final replacement event succeeds.
                "status": "done" if event.stage == "complete" and event.status == "done" else "running",
                "stage": event.stage,
                "message": event.message,
                "complete": event.complete,
                "total": event.total,
            }
            backup_path = event.backup_path or previous_state.get("backup_path")
            if backup_path:
                next_state["backup_path"] = backup_path
            current.sync_results[side] = next_state
            save_job(current, jobs_dir)

        try:
            job = load_job(jobs_dir, job_id)
            if unattended:
                if not isinstance(job.unattended_output, dict):
                    raise WebMergeError("Unattended output is not available for synchronisation.")
                if job.unattended.get("sync_blocked_by_sensitivity"):
                    raise WebMergeError("Unattended sync is blocked by sensitivity review.")
            else:
                _require_output_ready(job)
            _require_api_backed_side(job, side)
            result = (
                _merge_result_from_state(job.unattended_output)
                if unattended
                else finalised_job_result(job)
            )
            records = result.left_records if side == "left" else result.right_records
            observations = (
                result.left_observations if side == "left" else result.right_observations
            ) if job.includes_observations else None
            api = GhostwriterApi(_server_for_side(side), progress=update)
            backup_path = api.replace_all_findings(records, backup_root_from_config(CONFIG), observations=observations)
            job = load_job(jobs_dir, job_id)
            observation_count = 0 if observations is None else len(observations)
            job.sync_results[side] = {
                "operation": operation,
                "direction": "outbound",
                "side": side,
                "status": "done",
                "stage": "complete",
                "message": "Outbound API sync complete.",
                "complete": len(records) + observation_count,
                "total": len(records) + observation_count,
                "backup_path": str(backup_path),
            }
            save_job(job, jobs_dir)
        except Exception as exc:
            job = load_job(jobs_dir, job_id)
            failed_state = dict(job.sync_results.get(side) or {})
            failed_state.update(
                {
                    "operation": operation,
                    "direction": "outbound",
                    "side": side,
                    "status": "error",
                    "stage": "error",
                    "message": str(exc),
                }
            )
            failed_state.setdefault("complete", 0)
            failed_state.setdefault("total", 0)
            job.sync_results[side] = failed_state
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


def _require_completed_review(job, action: str = "Outbound API sync") -> None:
    if not job.conflict_phase_complete:
        raise WebMergeError(f"{action} is only available after conflict review is complete.")
    if not job.sensitivity_phase_complete:
        raise WebMergeError(f"{action} is only available after sensitivity review is complete.")


def _require_output_ready(job) -> None:
    _require_completed_review(job, action="Outbound API sync")
    if not job.output_approved or not job.output_phase_complete:
        raise WebMergeError("Outbound API sync is only available after final output approval and creation.")


def _require_api_backed_side(job, side: str) -> None:
    if job.input_sources.get(side) != "api":
        raise WebMergeError(f"{side.title()} outbound API sync is only available for API-backed merge jobs.")


def _require_sync_not_active(job, side: str) -> None:
    state = job.sync_results.get(side) or {}
    status = state.get("status")
    if status == "running":
        raise WebMergeError(f"{side.title()} outbound API sync is already running.")
    # A preliminary unattended sync deliberately preserves unresolved differences.
    # It must not prevent the later, manually approved final output replacing it.
    if status == "done" and state.get("operation") != "unattended_outbound_sync":
        raise WebMergeError(f"{side.title()} outbound API sync has already completed.")


def _require_no_running_live_sync(jobs_dir: Path, job) -> None:
    for side in ("left", "right"):
        status = (job.sync_results.get(side) or {}).get("status")
        if status in RUNNING_OPERATION_STATUSES or _sync_lock_path(jobs_dir, job.job_id, side).exists():
            raise WebMergeError("This merge job cannot be abandoned while outbound API sync is running.")


def _require_job_abandonable(job) -> None:
    """Protect durable completed output from deletion through abandonment."""
    if job.output_phase_complete:
        raise WebMergeError("A completed merge job cannot be abandoned because its output is ready.")


def _delete_job_directory(jobs_dir: Path, job_id: str) -> None:
    job_dir = jobs_dir / job_id
    if not job_id.isalnum() or not job_dir.exists():
        raise WebMergeError("Job not found.")
    shutil.rmtree(job_dir)


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
        raise WebMergeError(f"{side.title()} outbound API sync is already running.") from exc


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


def _selected_restore_candidate_id(raw_existing_id: str | None, candidates: list[dict[str, Any]]) -> int:
    try:
        existing_id = int(raw_existing_id or "")
    except ValueError as exc:
        raise ValueError("Selected restore target is invalid.") from exc
    candidate_ids = {int(candidate["id"]) for candidate in candidates}
    if existing_id not in candidate_ids:
        raise ValueError("Selected restore target is no longer a matching template.")
    return existing_id


def _load_terms():
    if not CONFIG.get("sensitivity_check_enabled"):
        return None
    return load_sensitive_terms(
        CONFIG["sensitivity_check_terms_file"],
        CONFIG.get("script_dir", Path(__file__).resolve().parent),
    )


def _build_sensitivity_snapshot() -> dict[str, Any]:
    """Freeze one Web job's protected sensitivity policy without logging it."""
    enabled = bool(CONFIG.get("sensitivity_check_enabled"))
    if not enabled:
        return {
            "version": 1,
            "enabled": False,
            "pre_match_enabled": bool(CONFIG.get("sensitivity_check_before_matching", False)),
            "terms": {},
            "terms_digest": None,
            "terms_source": None,
            "configuration_error": None,
        }

    terms = _load_terms()
    configured_source = Path(str(CONFIG.get("sensitivity_check_terms_file", ""))).name or None
    if terms is None:
        return {
            "version": 1,
            "enabled": True,
            "pre_match_enabled": bool(CONFIG.get("sensitivity_check_before_matching", False)),
            "terms": {},
            "terms_digest": None,
            "terms_source": configured_source,
            "configuration_error": "Configured sensitive-term rules could not be loaded.",
        }

    return {
        "version": 1,
        "enabled": True,
        "pre_match_enabled": bool(CONFIG.get("sensitivity_check_before_matching", False)),
        "terms": dict(terms),
        "terms_digest": sensitive_terms_digest(terms),
        "terms_source": configured_source,
        "configuration_error": None,
    }


def _sensitivity_terms_for_job(job) -> Optional[dict[str, Optional[str]]]:
    """Use a new job's immutable snapshot while preserving legacy job behaviour."""
    if job.sensitivity_snapshot_version >= 1:
        if not job.sensitivity_enabled or job.sensitivity_configuration_error:
            return None
        return dict(job.sensitivity_terms)
    return _load_terms()


if __name__ == "__main__":
    create_app().run(debug=False)

from __future__ import annotations

import threading
from pathlib import Path

from flask import Flask, redirect, render_template, request, send_file, url_for

from ghostwriter_api import (
    GhostwriterApi,
    GhostwriterApiError,
    backup_root_from_config,
    configured_server_summary,
    list_backups,
    load_backup_record,
    load_server_configs,
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


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="dev-change-me",
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        GHOSTMERGE_JOBS_DIR=Path("ghostmerge_web_jobs"),
    )
    if test_config:
        app.config.update(test_config)

    if not CONFIG.get("config_loaded"):
        load_config()

    jobs_dir = Path(app.config["GHOSTMERGE_JOBS_DIR"])
    jobs_dir.mkdir(parents=True, exist_ok=True)

    @app.get("/")
    def index():
        return render_template(
            "upload.html",
            previous_jobs=list_previous_jobs(jobs_dir),
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
                api_servers=configured_server_summary(CONFIG),
                backups=list_backups(backup_root_from_config(CONFIG)),
                root_page=True,
            ), 400

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
            result = finalise_job(job)
            save_outputs(job, jobs_dir, result)
            job.sensitivity_phase_complete = True
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
            data = load_backup_record(backup_path, 0)["backup"]
            return render_template("api_backup_detail.html", backup=data, side=side, filename=filename)
        except (GhostwriterApiError, ValueError) as exc:
            return render_template("error.html", error=str(exc)), 400

    @app.post("/api-backups/<side>/<filename>/<int:index>/restore")
    def api_backup_restore(side: str, filename: str, index: int):
        try:
            backup_path = _safe_backup_path(side, filename)
            record = load_backup_record(backup_path, index)
            api = GhostwriterApi(_server_for_side(side))
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


def _load_records_for_side(side: str, uploaded_file, source: str) -> list[dict]:
    if source == "api":
        server = _server_for_side(side)
        return GhostwriterApi(server).fetch_findings()
    if uploaded_file is None or uploaded_file.filename == "":
        raise WebMergeError(f"{side.title()} JSON file is required when that side is file-backed.")
    return load_records_from_json_text(uploaded_file.read().decode("utf-8"))


def _server_for_side(side: str):
    server = load_server_configs(CONFIG).get(side)
    if server is None:
        raise GhostwriterApiError(f"{side.title()} Ghostwriter server is not configured for API sync.")
    return server


def _start_sync_thread(app: Flask, jobs_dir: Path, job_id: str, side: str) -> None:
    job = load_job(jobs_dir, job_id)
    _require_completed_review(job)
    _require_api_backed_side(job, side)
    job.sync_results[side] = {"status": "running", "stage": "queued", "message": "Queued", "complete": 0, "total": 0}
    save_job(job, jobs_dir)
    thread = threading.Thread(target=_sync_job_side, args=(app, jobs_dir, job_id, side), daemon=True)
    thread.start()


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


def _safe_backup_path(side: str, filename: str) -> Path:
    if side not in {"left", "right"} or "/" in filename or "\\" in filename or not filename.endswith(".json"):
        raise ValueError("Invalid backup path.")
    path = backup_root_from_config(CONFIG) / side / filename
    if not path.exists():
        raise ValueError("Backup not found.")
    return path


def _require_completed_review(job) -> None:
    if not job.sensitivity_phase_complete:
        raise WebMergeError("Live API sync is only available after the merge review is complete.")


def _require_api_backed_side(job, side: str) -> None:
    if job.input_sources.get(side) != "api":
        raise WebMergeError(f"{side.title()} live API sync is only available for API-backed merge jobs.")


def _load_terms():
    if not CONFIG.get("sensitivity_check_enabled"):
        return None
    return load_sensitive_terms(
        CONFIG["sensitivity_check_terms_file"],
        CONFIG.get("script_dir", Path(__file__).resolve().parent),
    )


if __name__ == "__main__":
    create_app().run(debug=False)

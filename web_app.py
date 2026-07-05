from __future__ import annotations

import json
import secrets
import threading
import uuid
from pathlib import Path

from flask import Flask, redirect, render_template, request, send_file, session, url_for

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

    jobs_dir = Path(app.config["GHOSTMERGE_JOBS_DIR"])
    jobs_dir.mkdir(parents=True, exist_ok=True)

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
                api_servers=configured_server_summary(CONFIG),
                backups=list_backups(backup_root_from_config(CONFIG)),
                root_page=True,
            ), 400

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
            data = verify_backup(backup_path)
            return render_template("api_backup_detail.html", backup=data, side=side, filename=filename)
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


def _save_import_state(jobs_dir: Path, import_id: str, state: dict) -> None:
    path = _import_state_path(jobs_dir, import_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _load_import_state(jobs_dir: Path, import_id: str) -> dict:
    path = _import_state_path(jobs_dir, import_id)
    if not path.exists():
        raise WebMergeError("API import not found.")
    return json.loads(path.read_text(encoding="utf-8"))


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


def _require_completed_review(job) -> None:
    if not job.sensitivity_phase_complete:
        raise WebMergeError("Live API sync is only available after the merge review is complete.")


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

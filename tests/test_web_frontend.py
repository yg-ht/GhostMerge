import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from globals import get_config
from web_app import create_app
from web_service import (
    WebMergeError,
    accept_offered_fields_for_current_match,
    apply_conflict_decision,
    apply_sensitivity_decision,
    build_field_diff,
    create_merge_job,
    finalise_job,
    get_current_match_preview,
    get_next_conflict,
    get_next_sensitivity_item,
    load_job,
    load_records_from_json_text,
    list_previous_jobs,
    save_job,
    save_outputs,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def configure_for_web_tests(**overrides):
    config = get_config()
    with (PROJECT_ROOT / "ghostmerge_config.example.json").open("r", encoding="utf-8") as handle:
        baseline = json.load(handle)
    baseline.update(
        {
            "config_loaded": True,
            "script_dir": PROJECT_ROOT,
            "interactive_mode": False,
            "sensitivity_check_enabled": False,
            "log_file_enabled": False,
            "log_verbosity": "ERROR",
            "log_verbosity_cli": "ERROR",
            "log_verbosity_matching": "ERROR",
            "log_verbosity_merge": "ERROR",
            "log_verbosity_model": "ERROR",
            "log_verbosity_sensitivity": "ERROR",
            "log_verbosity_tui": "ERROR",
            "log_verbosity_utils": "ERROR",
            "fuzzy_match_threshold": [70],
        }
    )
    baseline.update(overrides)
    config.clear()
    config.update(baseline)
    return config


def record(**overrides):
    data = {
        "id": "1",
        "severity": "Medium",
        "cvss_score": "5.0",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "finding_type": "Web",
        "title": "Cross-site scripting",
        "description": "An attacker can execute JavaScript.",
        "impact": "Session tokens may be stolen.",
        "mitigation": "Encode output.",
        "replication_steps": "Open the payload.",
        "host_detection_techniques": "",
        "network_detection_techniques": "",
        "references": "",
        "finding_guidance": "",
        "tags": "web, xss",
        "extra_fields": None,
    }
    data.update(overrides)
    return data


class WebServiceTests(unittest.TestCase):
    def setUp(self):
        configure_for_web_tests()

    def test_upload_json_must_be_list_of_objects(self):
        with self.assertRaises(WebMergeError):
            load_records_from_json_text("{not json")
        with self.assertRaises(WebMergeError):
            load_records_from_json_text('{"id": 1}')
        with self.assertRaises(WebMergeError):
            load_records_from_json_text('["not a record"]')

    def test_conflict_decision_and_finalise_outputs_aligned_records(self):
        job = create_merge_job(
            [record(description="Left detail")],
            [record(id="2", description="Right detail")],
            job_id="abc123",
        )

        item = get_next_conflict(job)

        self.assertIsNotNone(item)
        self.assertEqual(item.field_name, "description")
        apply_conflict_decision(job, {"field_name": "description", "action": "right"})
        self.assertIsNone(get_next_conflict(job))

        result = finalise_job(job)

        self.assertEqual(result.left_records[0]["id"], "1")
        self.assertEqual(result.right_records[0]["id"], "1")
        self.assertEqual(result.left_records[0]["description"], "Right detail")
        self.assertEqual(result.right_records[0]["description"], "Right detail")

    def test_preview_and_diff_expose_changed_fields_for_review(self):
        job = create_merge_job(
            [record(description="Left detail")],
            [record(id="2", description="Right detail")],
            job_id="preview123",
        )

        preview = get_current_match_preview(job)
        diff = build_field_diff("Left detail", "Right detail", "Right detail")

        self.assertIsNotNone(preview)
        self.assertIn("description", [row["field_name"] for row in preview.rows if row["different"]])
        self.assertIn("removed", [row["class"] for row in diff])
        self.assertIn("added", [row["class"] for row in diff])
        self.assertIn("offered", [row["class"] for row in diff])

    def test_preview_selected_offered_values_leave_remaining_fields_for_review(self):
        job = create_merge_job(
            [record(description="Left detail", impact="Left impact")],
            [record(id="2", description="Right detail", impact="Right impact")],
            job_id="select123",
        )

        applied = accept_offered_fields_for_current_match(job, ["description"])
        item = get_next_conflict(job)

        self.assertEqual(applied, 1)
        self.assertEqual(job.matches[0]["left"].description, job.matches[0]["auto_value"].description)
        self.assertEqual(item.field_name, "impact")

    def test_job_persistence_round_trips_review_state(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            job = create_merge_job(
                [record(description="Left detail")],
                [record(id="2", description="Right detail")],
                job_id="persist123",
            )
            get_next_conflict(job)
            save_job(job, Path(tmp_dir))

            loaded = load_job(Path(tmp_dir), "persist123")

        self.assertEqual(loaded.job_id, "persist123")
        self.assertEqual(loaded.match_index, job.match_index)
        self.assertEqual(loaded.field_index, job.field_index)

    def test_previous_jobs_are_listed_from_job_store(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            jobs_dir = Path(tmp_dir)
            job = create_merge_job([record()], [], job_id="oldjob123")
            get_next_conflict(job)
            result = finalise_job(job)
            save_job(job, jobs_dir)
            save_outputs(job, jobs_dir, result)

            previous_jobs = list_previous_jobs(jobs_dir)

        self.assertEqual(previous_jobs[0].job_id, "oldjob123")
        self.assertTrue(previous_jobs[0].has_left_output)
        self.assertTrue(previous_jobs[0].has_right_output)

    def test_sensitivity_review_can_apply_offered_replacement(self):
        configure_for_web_tests(sensitivity_check_enabled=True)
        job = create_merge_job([record(description="ACME detail")], [], job_id="sens123")
        self.assertIsNone(get_next_conflict(job))

        item = get_next_sensitivity_item(job, {"acme": "[CLIENT]"})

        self.assertIsNotNone(item)
        self.assertTrue(any(part["hit"] for part in item.highlighted_parts))
        apply_sensitivity_decision(
            job,
            {
                "side": item.side,
                "record_index": item.record_index,
                "field_name": item.field_name,
                "sensitive_term": item.sensitive_term,
                "action": "offered",
                "offered": item.offered,
            },
        )
        self.assertIn("[CLIENT]", job.merged_left[0].description)


class FlaskRouteTests(unittest.TestCase):
    def setUp(self):
        configure_for_web_tests()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "GHOSTMERGE_JOBS_DIR": Path(self.tmp_dir.name),
                "SECRET_KEY": "test-secret",
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_upload_rejects_invalid_json(self):
        response = self.client.post(
            "/jobs",
            data={
                "left_file": (io.BytesIO(b"not json"), "left.json"),
                "right_file": (io.BytesIO(b"[]"), "right.json"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Invalid JSON", response.data)

    def test_home_shows_logo_and_previous_jobs(self):
        jobs_dir = Path(self.tmp_dir.name)
        job = create_merge_job([record()], [], job_id="homejob123")
        get_next_conflict(job)
        save_job(job, jobs_dir)

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"GhostMerge-logo.png", response.data)
        self.assertIn(b"root-logo-overlay", response.data)
        self.assertIn(b"homejob123", response.data)
        self.assertIn(b"Matched pairs reviewed", response.data)

    def test_upload_review_complete_and_download_outputs(self):
        left = json.dumps([record(description="Left detail")]).encode("utf-8")
        right = json.dumps([record(id="2", description="Right detail")]).encode("utf-8")

        upload = self.client.post(
            "/jobs",
            data={
                "left_file": (io.BytesIO(left), "left.json"),
                "right_file": (io.BytesIO(right), "right.json"),
            },
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        self.assertEqual(upload.status_code, 302)
        summary_path = upload.headers["Location"]
        job_id = summary_path.rstrip("/").split("/")[-2]

        summary = self.client.get(summary_path)
        self.assertEqual(summary.status_code, 200)
        self.assertIn(b"Matched pairs", summary.data)

        conflict = self.client.get(f"/jobs/{job_id}/conflicts")
        self.assertEqual(conflict.status_code, 200)
        self.assertIn(b"Record preview", conflict.data)
        self.assertIn(b"changed", conflict.data)
        self.assertIn(b"Accept selected offered values", conflict.data)

        conflict = self.client.post(
            f"/jobs/{job_id}/conflicts",
            data={"preview_action": "continue"},
            follow_redirects=True,
        )
        self.assertEqual(conflict.status_code, 200)
        self.assertIn(b"Conflict review", conflict.data)
        self.assertIn(b"data-shortcut=\"ArrowLeft\"", conflict.data)
        self.assertIn(b"Highlighted difference", conflict.data)

        completed = self.client.post(
            f"/jobs/{job_id}/conflicts",
            data={"field_name": "description", "action": "right"},
            follow_redirects=True,
        )
        self.assertEqual(completed.status_code, 200)
        self.assertIn(b"Merge complete", completed.data)

        left_download = self.client.get(f"/jobs/{job_id}/download/left")
        right_download = self.client.get(f"/jobs/{job_id}/download/right")

        self.assertEqual(left_download.status_code, 200)
        self.assertEqual(right_download.status_code, 200)
        self.assertEqual(left_download.get_json()[0]["description"], "Right detail")
        self.assertEqual(right_download.get_json()[0]["description"], "Right detail")

    def test_preview_can_accept_offered_values_for_current_match(self):
        left = json.dumps([record(description="Left detail")]).encode("utf-8")
        right = json.dumps([record(id="2", description="Right detail")]).encode("utf-8")

        upload = self.client.post(
            "/jobs",
            data={
                "left_file": (io.BytesIO(left), "left.json"),
                "right_file": (io.BytesIO(right), "right.json"),
            },
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        job_id = upload.headers["Location"].rstrip("/").split("/")[-2]
        response = self.client.post(
            f"/jobs/{job_id}/conflicts",
            data={"preview_action": "accept_offered"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Merge complete", response.data)

    def test_live_sync_rejects_completed_file_backed_job(self):
        jobs_dir = Path(self.tmp_dir.name)
        job = create_merge_job([record()], [], job_id="filebacked123")
        self.assertIsNone(get_next_conflict(job))
        result = finalise_job(job)
        job.sensitivity_phase_complete = True
        save_job(job, jobs_dir)
        save_outputs(job, jobs_dir, result)

        response = self.client.get("/jobs/filebacked123/sync/left")

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"only available for API-backed merge jobs", response.data)

    def test_live_sync_rejects_duplicate_running_sync(self):
        jobs_dir = Path(self.tmp_dir.name)
        job = create_merge_job([record()], [], job_id="running123", input_sources={"left": "api", "right": "file"})
        self.assertIsNone(get_next_conflict(job))
        result = finalise_job(job)
        job.sensitivity_phase_complete = True
        job.sync_results["left"] = {"status": "running"}
        save_job(job, jobs_dir)
        save_outputs(job, jobs_dir, result)

        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )
        response = self.client.post("/jobs/running123/sync/left")

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"already running", response.data)

    def test_backup_detail_allows_empty_backup(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "empty.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Left",
                    "created_at": "20260705T000000Z",
                    "record_count": 0,
                    "raw_records": [],
                    "normalised_records": [],
                }
            ),
            encoding="utf-8",
        )
        get_config()["ghostwriter_api"]["backup_dir"] = str(backup_root)

        response = self.client.get("/api-backups/left/empty.json")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Records", response.data)
        self.assertIn(b">0<", response.data)

    def test_config_debug_logging_redacts_bearer_token(self):
        from utils import load_config

        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "ghostmerge_config.json"
            log_path = Path(tmp_dir) / "ghostmerge.log"
            config_path.write_text(
                json.dumps(
                    {
                        "config_loaded": True,
                        "log_file_enabled": True,
                        "log_file_path": str(log_path),
                        "log_verbosity": "DEBUG",
                        "log_verbosity_utils": "DEBUG",
                        "verbosity_decision_log_enabled": False,
                        "ghostwriter_api": {
                            "servers": {
                                "left": {
                                    "bearer_token": "super-secret-token",
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            current_config = get_config()
            current_config["log_file_enabled"] = True
            current_config["log_file_path"] = str(log_path)
            current_config["log_verbosity"] = "DEBUG"
            current_config["log_verbosity_utils"] = "DEBUG"
            current_config["verbosity_decision_log_enabled"] = False
            with patch("builtins.print"):
                load_config(config_path)

            log_text = log_path.read_text(encoding="utf-8")

        self.assertIn("[REDACTED]", log_text)
        self.assertNotIn("super-secret-token", log_text)

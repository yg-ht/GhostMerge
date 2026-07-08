import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from globals import get_config
from web_app import create_app, _check_api_source, _import_job_sources
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


def web_access_disabled():
    return {
        "source_ip_restriction_enabled": False,
        "api_key_auth_enabled": False,
        "allow_framing": False,
    }


def web_access_enabled(**overrides):
    config = {
        "source_ip_restriction_enabled": True,
        "allowed_source_ips": ["127.0.0.1"],
        "source_ip_mode": "direct",
        "trusted_proxy_ips": [],
        "trusted_source_ip_header": "X-Forwarded-For",
        "api_key_auth_enabled": True,
        "api_key_query_param": "api_key",
        "api_key": "test-web-key",
        "allow_framing": True,
        "frame_ancestors": ["*"],
        "session_cookie_samesite": "None",
        "session_cookie_secure": True,
    }
    config.update(overrides)
    return config


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

    def test_finalise_rejects_incomplete_conflict_review(self):
        job = create_merge_job(
            [record(description="Left detail")],
            [record(id="2", description="Right detail")],
            job_id="incomplete123",
        )

        with self.assertRaisesRegex(WebMergeError, "Conflict review must be complete"):
            finalise_job(job)

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
        description_row = next(row for row in preview.rows if row["field_name"] == "description")
        self.assertTrue(description_row["different"])
        self.assertIn("removed", [row["class"] for row in description_row["diff_rows"]])
        self.assertIn("added", [row["class"] for row in description_row["diff_rows"]])
        self.assertIn("removed", [row["class"] for row in diff])
        self.assertIn("added", [row["class"] for row in diff])
        self.assertIn("offered", [row["class"] for row in diff])

    def test_preview_excludes_id_from_reviewable_differences(self):
        job = create_merge_job(
            [record(id="1", description="Same detail")],
            [record(id="99", description="Same detail")],
            job_id="previewid123",
        )

        preview = get_current_match_preview(job)
        item = get_next_conflict(job)

        self.assertIsNotNone(preview)
        id_row = next(row for row in preview.rows if row["field_name"] == "id")
        self.assertEqual(id_row["left_value"], "1")
        self.assertEqual(id_row["right_value"], "99")
        self.assertFalse(id_row["different"])
        self.assertEqual(id_row["diff_rows"], [])
        self.assertIsNone(item)

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
            job.sync_results["left"] = {"status": "running", "message": "Creating reviewed findings"}
            save_job(job, jobs_dir)
            save_outputs(job, jobs_dir, result)

            previous_jobs = list_previous_jobs(jobs_dir)

        self.assertEqual(previous_jobs[0].job_id, "oldjob123")
        self.assertTrue(previous_jobs[0].has_left_output)
        self.assertTrue(previous_jobs[0].has_right_output)
        self.assertEqual(previous_jobs[0].sync_results["left"]["status"], "running")

    def test_previous_jobs_include_unreadable_job_state(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            jobs_dir = Path(tmp_dir)
            corrupt_job_dir = jobs_dir / "corrupt123"
            corrupt_job_dir.mkdir()
            (corrupt_job_dir / "job.json").write_text("{partial", encoding="utf-8")

            previous_jobs = list_previous_jobs(jobs_dir)

        self.assertEqual(previous_jobs[0].job_id, "corrupt123")
        self.assertEqual(previous_jobs[0].phase, "error")
        self.assertIn("Job state could not be read", previous_jobs[0].error)

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

    def test_sensitivity_review_handles_multiple_terms_in_same_field(self):
        configure_for_web_tests(sensitivity_check_enabled=True)
        job = create_merge_job([record(description="ACME and secret detail")], [], job_id="sens456")
        self.assertIsNone(get_next_conflict(job))

        first = get_next_sensitivity_item(job, {"acme": "[CLIENT]", "secret": "[SECRET]"})
        self.assertIsNotNone(first)
        apply_sensitivity_decision(
            job,
            {
                "side": first.side,
                "record_index": first.record_index,
                "field_name": first.field_name,
                "sensitive_term": first.sensitive_term,
                "action": "offered",
                "offered": first.offered,
            },
        )
        second = get_next_sensitivity_item(job, {"acme": "[CLIENT]", "secret": "[SECRET]"})

        self.assertIsNotNone(second)
        self.assertEqual(second.field_name, "description")
        self.assertEqual(second.sensitive_term, "secret")

    def test_sensitivity_review_keep_advances_to_next_term_in_same_field(self):
        configure_for_web_tests(sensitivity_check_enabled=True)
        job = create_merge_job([record(description="ACME and secret detail")], [], job_id="sens789")
        self.assertIsNone(get_next_conflict(job))

        first = get_next_sensitivity_item(job, {"acme": "[CLIENT]", "secret": "[SECRET]"})
        self.assertIsNotNone(first)
        apply_sensitivity_decision(
            job,
            {
                "side": first.side,
                "record_index": first.record_index,
                "field_name": first.field_name,
                "sensitive_term": first.sensitive_term,
                "action": "keep",
            },
        )
        second = get_next_sensitivity_item(job, {"acme": "[CLIENT]", "secret": "[SECRET]"})

        self.assertIsNotNone(second)
        self.assertEqual(second.field_name, "description")
        self.assertEqual(second.sensitive_term, "secret")


class FlaskRouteTests(unittest.TestCase):
    def setUp(self):
        configure_for_web_tests(web_access=web_access_disabled())
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

    def csrf_token(self):
        with self.client.session_transaction() as session:
            session.setdefault("_csrf_token", "test-csrf-token")
            return session["_csrf_token"]

    def with_csrf(self, data=None):
        submitted = dict(data or {})
        submitted["_csrf_token"] = self.csrf_token()
        return submitted

    def test_upload_rejects_invalid_json(self):
        response = self.client.post(
            "/jobs",
            data=self.with_csrf({
                "left_file": (io.BytesIO(b"not json"), "left.json"),
                "right_file": (io.BytesIO(b"[]"), "right.json"),
            }),
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Invalid JSON", response.data)

    def test_home_shows_logo_and_previous_jobs(self):
        jobs_dir = Path(self.tmp_dir.name)
        job = create_merge_job([record()], [], job_id="homejob123")
        get_next_conflict(job)
        job.sync_results["left"] = {"status": "running", "message": "Creating reviewed findings"}
        save_job(job, jobs_dir)

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"GhostMerge-logo.png", response.data)
        self.assertIn(b"root-logo-overlay", response.data)
        self.assertIn(b"color-scheme: dark", response.data)
        self.assertIn(b"data-theme-toggle", response.data)
        self.assertIn(b"you-gotta-hack-that-icon.svg", response.data)
        self.assertIn(b"A project by", response.data)
        self.assertIn(b"You Gotta Hack That", response.data)
        self.assertIn(b"https://yougottahackthat.com", response.data)
        self.assertIn(b">Home<", response.data)
        self.assertNotIn(b"New merge", response.data)
        self.assertIn(b"homejob123", response.data)
        self.assertIn(b"Matched pairs reviewed", response.data)
        self.assertIn(b"Left sync status", response.data)
        self.assertIn(b"/jobs/homejob123/sync/left/status", response.data)

    def test_home_shows_unreadable_previous_jobs(self):
        jobs_dir = Path(self.tmp_dir.name)
        corrupt_job_dir = jobs_dir / "corrupt123"
        corrupt_job_dir.mkdir()
        (corrupt_job_dir / "job.json").write_text("{partial", encoding="utf-8")

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"corrupt123", response.data)
        self.assertIn(b"Job state could not be read", response.data)

    def test_home_limits_previous_jobs_and_links_to_full_history(self):
        get_config()["web_ui"]["home_previous_jobs_limit"] = 2
        jobs_dir = Path(self.tmp_dir.name)
        for index, job_id in enumerate(("oldjob", "midjob", "newjob"), start=1):
            job_dir = jobs_dir / job_id
            job_dir.mkdir()
            job_path = job_dir / "job.json"
            job_path.write_text("{partial", encoding="utf-8")
            os.utime(job_path, (index, index))

        response = self.client.get("/")
        full_response = self.client.get("/jobs")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"newjob", response.data)
        self.assertIn(b"midjob", response.data)
        self.assertNotIn(b"oldjob", response.data)
        self.assertIn(b"Showing 2 of 3 previous merge jobs.", response.data)
        self.assertIn(b"/jobs", response.data)
        self.assertEqual(full_response.status_code, 200)
        self.assertIn(b"oldjob", full_response.data)
        self.assertIn(b"midjob", full_response.data)
        self.assertIn(b"newjob", full_response.data)

    def test_home_shows_api_source_check_status_links(self):
        checks_dir = Path(self.tmp_dir.name) / "api_source_checks"
        checks_dir.mkdir()
        (checks_dir / "check123.json").write_text(
            json.dumps(
                {
                    "check_id": "check123",
                    "side": "left",
                    "server_name": "YGHT Ghostwriter",
                    "status": "running",
                    "stage": "backup_fetch",
                    "message": "Fetched 192 backup record(s) from YGHT Ghostwriter",
                    "complete": 192,
                    "total": 0,
                    "worker_pid": os.getpid(),
                }
            ),
            encoding="utf-8",
        )

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"API source checks", response.data)
        self.assertIn(b"YGHT Ghostwriter", response.data)
        self.assertIn(b"worker process is no longer active", response.data)
        self.assertIn(b"/api-sources/checks/check123/status", response.data)

    def test_home_limits_api_source_checks_and_links_to_full_history(self):
        get_config()["web_ui"]["home_api_source_checks_limit"] = 2
        checks_dir = Path(self.tmp_dir.name) / "api_source_checks"
        checks_dir.mkdir()
        for index, check_id in enumerate(("oldcheck", "midcheck", "newcheck"), start=1):
            check_path = checks_dir / f"{check_id}.json"
            check_path.write_text(
                json.dumps(
                    {
                        "check_id": check_id,
                        "side": "left",
                        "server_name": f"Server {check_id}",
                        "status": "done",
                        "stage": "done",
                        "message": f"Finished {check_id}",
                        "complete": 1,
                        "total": 1,
                    }
                ),
                encoding="utf-8",
            )
            os.utime(check_path, (index, index))

        response = self.client.get("/")
        full_response = self.client.get("/api-sources/checks")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"newcheck", response.data)
        self.assertIn(b"midcheck", response.data)
        self.assertNotIn(b"oldcheck", response.data)
        self.assertIn(b"Showing 2 of 3 API source checks.", response.data)
        self.assertIn(b"/api-sources/checks", response.data)
        self.assertEqual(full_response.status_code, 200)
        self.assertIn(b"oldcheck", full_response.data)
        self.assertIn(b"midcheck", full_response.data)
        self.assertIn(b"newcheck", full_response.data)

    def test_home_marks_api_source_checks_without_live_worker_as_stale(self):
        checks_dir = Path(self.tmp_dir.name) / "api_source_checks"
        checks_dir.mkdir()
        (checks_dir / "stalecheck123.json").write_text(
            json.dumps(
                {
                    "check_id": "stalecheck123",
                    "side": "left",
                    "server_name": "YGHT Ghostwriter",
                    "status": "running",
                    "stage": "backup_fetch",
                    "message": "Fetched 192 backup record(s) from YGHT Ghostwriter",
                    "complete": 192,
                    "total": 0,
                }
            ),
            encoding="utf-8",
        )

        response = self.client.get("/")
        status_response = self.client.get("/api-sources/checks/stalecheck123/status")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"stale", response.data)
        self.assertIn(b"worker process is no longer active", response.data)
        self.assertEqual(status_response.status_code, 200)
        self.assertIn(b"stale", status_response.data)
        self.assertNotIn(b'http-equiv="refresh"', status_response.data)

    def test_home_shows_api_import_status_links(self):
        imports_dir = Path(self.tmp_dir.name) / "api_imports"
        imports_dir.mkdir()
        (imports_dir / "import123.json").write_text(
            json.dumps(
                {
                    "import_id": "import123",
                    "status": "running",
                    "stage": "fetch_left",
                    "message": "Fetching left API source.",
                    "complete": 0,
                    "total": 1,
                    "job_id": None,
                    "worker_pid": os.getpid(),
                }
            ),
            encoding="utf-8",
        )

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"API imports", response.data)
        self.assertIn(b"worker process is no longer active", response.data)
        self.assertIn(b"/imports/import123/status", response.data)

    def test_upload_review_complete_and_download_outputs(self):
        left = json.dumps([record(description="Left detail")]).encode("utf-8")
        right = json.dumps([record(id="2", description="Right detail")]).encode("utf-8")

        upload = self.client.post(
            "/jobs",
            data=self.with_csrf({
                "left_file": (io.BytesIO(left), "left.json"),
                "right_file": (io.BytesIO(right), "right.json"),
            }),
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
        self.assertIn(b"Highlighted difference for description", conflict.data)
        self.assertIn(b"class=\"diff-line removed\"", conflict.data)
        self.assertIn(b"class=\"diff-line added\"", conflict.data)
        self.assertIn(b"Accept selected offered values", conflict.data)

        conflict = self.client.post(
            f"/jobs/{job_id}/conflicts",
            data=self.with_csrf({"preview_action": "continue"}),
            follow_redirects=True,
        )
        self.assertEqual(conflict.status_code, 200)
        self.assertIn(b"Conflict review", conflict.data)
        self.assertIn(b"data-shortcut=\"ArrowLeft\"", conflict.data)
        self.assertIn(b"Highlighted difference", conflict.data)

        completed = self.client.post(
            f"/jobs/{job_id}/conflicts",
            data=self.with_csrf({"field_name": "description", "action": "right"}),
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

    def test_record_preview_does_not_mark_id_only_difference_for_review(self):
        left = json.dumps([record(id="1", description="Same detail")]).encode("utf-8")
        right = json.dumps([record(id="99", description="Same detail")]).encode("utf-8")

        upload = self.client.post(
            "/jobs",
            data=self.with_csrf({
                "left_file": (io.BytesIO(left), "left.json"),
                "right_file": (io.BytesIO(right), "right.json"),
            }),
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        job_id = upload.headers["Location"].rstrip("/").split("/")[-2]

        preview = self.client.get(f"/jobs/{job_id}/conflicts")

        self.assertEqual(preview.status_code, 200)
        self.assertIn(b"Record preview", preview.data)
        self.assertIn(b"<th class=\"field-cell\">id</th>", preview.data)
        self.assertNotIn(b"changed selectable", preview.data)
        self.assertNotIn(b"Accept offered id", preview.data)
        self.assertNotIn(b"diff-line removed", preview.data)
        self.assertNotIn(b"diff-line added", preview.data)

    def test_abandon_merge_deletes_local_job_and_returns_home(self):
        job = create_merge_job(
            [record(description="Left detail")],
            [record(id="2", description="Right detail")],
            job_id="abandon123",
        )
        save_job(job, Path(self.tmp_dir.name))

        preview = self.client.get("/jobs/abandon123/conflicts")
        response = self.client.post(
            "/jobs/abandon123/abandon",
            data=self.with_csrf(),
            follow_redirects=True,
        )

        self.assertEqual(preview.status_code, 200)
        self.assertIn(b"Abandon merge", preview.data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Abandoned merge job abandon123.", response.data)
        self.assertFalse((Path(self.tmp_dir.name) / "abandon123").exists())
        self.assertEqual(self.client.get("/jobs/abandon123/summary").status_code, 404)

    def test_abandon_merge_rejects_running_live_sync(self):
        job = create_merge_job([record()], [], job_id="syncabandon123")
        job.sync_results["left"] = {"status": "running"}
        save_job(job, Path(self.tmp_dir.name))

        response = self.client.post(
            "/jobs/syncabandon123/abandon",
            data=self.with_csrf(),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"cannot be abandoned while live API sync is running", response.data)
        self.assertTrue((Path(self.tmp_dir.name) / "syncabandon123").exists())

    def test_preview_can_accept_offered_values_for_current_match(self):
        left = json.dumps([record(description="Left detail")]).encode("utf-8")
        right = json.dumps([record(id="2", description="Right detail")]).encode("utf-8")

        upload = self.client.post(
            "/jobs",
            data=self.with_csrf({
                "left_file": (io.BytesIO(left), "left.json"),
                "right_file": (io.BytesIO(right), "right.json"),
            }),
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        job_id = upload.headers["Location"].rstrip("/").split("/")[-2]
        response = self.client.post(
            f"/jobs/{job_id}/conflicts",
            data=self.with_csrf({"preview_action": "accept_offered"}),
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

    def test_direct_complete_does_not_unlock_live_sync_for_incomplete_review(self):
        jobs_dir = Path(self.tmp_dir.name)
        job = create_merge_job(
            [record(description="Left detail")],
            [record(id="2", description="Right detail")],
            job_id="bypass123",
            input_sources={"left": "api", "right": "file"},
        )
        save_job(job, jobs_dir)

        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        complete_response = self.client.get("/jobs/bypass123/complete")
        sync_response = self.client.get("/jobs/bypass123/sync/left")
        reloaded = load_job(jobs_dir, "bypass123")

        self.assertEqual(complete_response.status_code, 400)
        self.assertIn(b"conflict review is complete", complete_response.data)
        self.assertEqual(sync_response.status_code, 400)
        self.assertIn(b"conflict review is complete", sync_response.data)
        self.assertFalse(reloaded.sensitivity_phase_complete)

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
        response = self.client.post("/jobs/running123/sync/left", data=self.with_csrf())

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"already running", response.data)

    def test_complete_page_links_to_existing_sync_status(self):
        jobs_dir = Path(self.tmp_dir.name)
        job = create_merge_job([record()], [], job_id="rejoin123", input_sources={"left": "api", "right": "file"})
        self.assertIsNone(get_next_conflict(job))
        result = finalise_job(job)
        job.sensitivity_phase_complete = True
        job.sync_results["left"] = {
            "status": "running",
            "stage": "create",
            "message": "Creating reviewed findings",
            "complete": 1,
            "total": 2,
        }
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

        response = self.client.get("/jobs/rejoin123/complete")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"View sync status", response.data)
        self.assertIn(b"/jobs/rejoin123/sync/left/status", response.data)

        summary_response = self.client.get("/jobs/rejoin123/summary")
        self.assertEqual(summary_response.status_code, 200)
        self.assertIn(b"Left sync status", summary_response.data)
        self.assertIn(b"/jobs/rejoin123/sync/left/status", summary_response.data)

    def test_live_sync_rejects_existing_side_lock(self):
        jobs_dir = Path(self.tmp_dir.name)
        job = create_merge_job([record()], [], job_id="locked123", input_sources={"left": "api", "right": "file"})
        self.assertIsNone(get_next_conflict(job))
        result = finalise_job(job)
        job.sensitivity_phase_complete = True
        save_job(job, jobs_dir)
        save_outputs(job, jobs_dir, result)
        (jobs_dir / "locked123" / "sync-left.lock").write_text("running\n", encoding="utf-8")

        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        response = self.client.post("/jobs/locked123/sync/left", data=self.with_csrf())

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"already running", response.data)

    def test_live_sync_status_handles_partial_job_state(self):
        jobs_dir = Path(self.tmp_dir.name)
        job = create_merge_job([record()], [], job_id="partial123", input_sources={"left": "api", "right": "file"})
        self.assertIsNone(get_next_conflict(job))
        job.sensitivity_phase_complete = True
        save_job(job, jobs_dir)
        (jobs_dir / "partial123" / "job.json").write_text("{partial", encoding="utf-8")

        response = self.client.get("/jobs/partial123/sync/left/status")

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"Job state could not be read", response.data)

    def test_live_sync_rejects_missing_csrf_token(self):
        jobs_dir = Path(self.tmp_dir.name)
        job = create_merge_job([record()], [], job_id="csrf123", input_sources={"left": "api", "right": "file"})
        self.assertIsNone(get_next_conflict(job))
        result = finalise_job(job)
        job.sensitivity_phase_complete = True
        save_job(job, jobs_dir)
        save_outputs(job, jobs_dir, result)

        response = self.client.post("/jobs/csrf123/sync/left")

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Invalid or missing form token", response.data)

    def test_api_backed_upload_redirects_to_visible_import_status(self):
        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        with patch("web_app.threading.Thread") as thread_class:
            thread_class.return_value.start.return_value = None
            response = self.client.post(
                "/jobs",
                data=self.with_csrf({
                    "left_source": "api",
                    "right_source": "file",
                    "right_file": (io.BytesIO(json.dumps([record()]).encode("utf-8")), "right.json"),
                }),
                content_type="multipart/form-data",
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/imports/", response.headers["Location"])
        status = self.client.get(response.headers["Location"])
        self.assertEqual(status.status_code, 200)
        self.assertIn(b"API import status", status.data)
        self.assertIn(b"Queued API import", status.data)

    def test_api_import_status_shows_current_source_and_record_progress(self):
        imports_dir = Path(self.tmp_dir.name) / "api_imports"
        imports_dir.mkdir()
        (imports_dir / "importprogress123.json").write_text(
            json.dumps(
                {
                    "import_id": "importprogress123",
                    "status": "running",
                    "stage": "fetch_left",
                    "message": "Fetched 42 finding(s) from YGHT Ghostwriter",
                    "complete": 0,
                    "total": 2,
                    "side": "left",
                    "side_name": "YGHT Ghostwriter",
                    "side_index": 1,
                    "side_total": 2,
                    "api_stage": "fetch",
                    "api_complete": 42,
                    "api_total": 0,
                    "api_status": "running",
                    "worker_pid": os.getpid(),
                }
            ),
            encoding="utf-8",
        )

        response = self.client.get("/imports/importprogress123/status")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Source progress", response.data)
        self.assertIn(b"Current source", response.data)
        self.assertIn(b"YGHT Ghostwriter", response.data)
        self.assertIn(b"Current API stage", response.data)
        self.assertIn(b"Records fetched", response.data)
        self.assertIn(b"At least 42", response.data)

    def test_api_import_worker_records_incremental_fetch_progress(self):
        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "Left Test Ghostwriter",
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )
        captured_progress_state = {}
        jobs_dir = Path(self.tmp_dir.name)

        class ProgressApi:
            def __init__(self, server, progress):
                self.server = server
                self.progress = progress

            def fetch_findings(self):
                event = type("Event", (), {})()
                event.stage = "fetch"
                event.message = f"Fetched 7 finding(s) from {self.server.name}"
                event.complete = 7
                event.total = 0
                event.status = "running"
                self.progress(event)
                progress_files = list((jobs_dir / "api_imports").glob("*.json"))
                captured_progress_state.update(json.loads(progress_files[0].read_text(encoding="utf-8")))
                return [record()]

        with patch("web_app.threading.Thread") as thread_class:
            thread_class.return_value.start.return_value = None
            response = self.client.post(
                "/jobs",
                data=self.with_csrf({
                    "left_source": "api",
                    "right_source": "file",
                    "right_file": (io.BytesIO(json.dumps([record(id="2")]).encode("utf-8")), "right.json"),
                }),
                content_type="multipart/form-data",
                follow_redirects=False,
            )
        import_id = response.headers["Location"].rsplit("/", 2)[-2]

        with patch("web_app.GhostwriterApi", ProgressApi):
            _import_job_sources(self.app, jobs_dir, import_id)

        self.assertEqual(captured_progress_state["api_complete"], 7)
        self.assertEqual(captured_progress_state["api_total"], 0)
        state = json.loads((jobs_dir / "api_imports" / f"{import_id}.json").read_text(encoding="utf-8"))
        self.assertEqual(state["api_complete"], 1)
        self.assertEqual(state["api_total"], 1)
        self.assertEqual(state["side_name"], "Left Test Ghostwriter")

    def test_home_shows_api_fetch_check_for_configured_sources(self):
        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "Left Test Ghostwriter",
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"Check API source", response.data)
        self.assertIn(b"Fetch Left Test Ghostwriter", response.data)
        self.assertIn(b'action="/api-sources/left/check"', response.data)

    def test_create_merge_form_is_not_nested_with_fetch_forms(self):
        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "Left Test Ghostwriter",
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        response = self.client.get("/")
        html = response.data.decode("utf-8")
        create_form = '<form id="create_merge_form" action="/jobs" method="post" enctype="multipart/form-data"></form>'

        self.assertEqual(response.status_code, 200)
        self.assertIn(create_form, html)
        self.assertIn('form="create_merge_form"', html)
        self.assertIn('action="/api-sources/left/check"', html)
        self.assertLess(html.index(create_form), html.index('action="/api-sources/left/check"'))

    def test_api_fetch_check_redirects_to_visible_status(self):
        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "Left Test Ghostwriter",
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        with patch("web_app.threading.Thread") as thread_class:
            thread_class.return_value.start.return_value = None
            response = self.client.post("/api-sources/left/check", data=self.with_csrf(), follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/api-sources/checks/", response.headers["Location"])
        status = self.client.get(response.headers["Location"])
        self.assertEqual(status.status_code, 200)
        self.assertIn(b"API source check status", status.data)
        self.assertIn(b"Queued API source check", status.data)

    def test_api_fetch_check_reuses_running_source_check(self):
        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "Left Test Ghostwriter",
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        with patch("web_app.threading.Thread") as thread_class:
            thread_class.return_value.start.return_value = None
            first = self.client.post("/api-sources/left/check", data=self.with_csrf(), follow_redirects=False)
            second = self.client.post("/api-sources/left/check", data=self.with_csrf(), follow_redirects=False)

        self.assertEqual(first.status_code, 302)
        self.assertEqual(second.status_code, 302)
        self.assertEqual(second.headers["Location"], first.headers["Location"])

    def test_home_fetch_button_links_to_running_source_check(self):
        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "Left Test Ghostwriter",
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        with patch("web_app.threading.Thread") as thread_class:
            thread_class.return_value.start.return_value = None
            check = self.client.post("/api-sources/left/check", data=self.with_csrf(), follow_redirects=False)
            response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Fetch Left Test Ghostwriter", response.data)
        self.assertIn(check.headers["Location"].encode("utf-8"), response.data)
        self.assertNotIn(b'action="/api-sources/left/check"', response.data)

    def test_api_source_check_status_can_request_stop(self):
        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "Left Test Ghostwriter",
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        with patch("web_app.threading.Thread") as thread_class:
            thread_class.return_value.start.return_value = None
            check = self.client.post("/api-sources/left/check", data=self.with_csrf(), follow_redirects=False)
            status = self.client.get(check.headers["Location"])
            stop = self.client.post(
                check.headers["Location"].replace("/status", "/stop"),
                data=self.with_csrf(),
                follow_redirects=True,
            )

        self.assertEqual(status.status_code, 200)
        self.assertIn(b">Stop<", status.data)
        self.assertEqual(stop.status_code, 200)
        self.assertIn(b"cancelling", stop.data)
        self.assertIn(b"Stop requested", stop.data)

    def test_api_source_check_worker_creates_backup_without_creating_merge_job(self):
        config = get_config()
        backup_root = Path(self.tmp_dir.name) / "backups"
        config["ghostwriter_api"]["backup_dir"] = str(backup_root)
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "Left Test Ghostwriter",
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "checked-backup.json"
        backup_data = {
            "server_side": "left",
            "server_name": "Left Test Ghostwriter",
            "graphql_url": "https://left.example/v1/graphql",
            "created_at": "20260705T000000Z",
            "record_count": 2,
            "raw_records": [
                {"record": {"id": 1, "title": "First"}, "tags": []},
                {"record": {"id": 2, "title": "Second"}, "tags": []},
            ],
            "normalised_records": [record(), record(id="2")],
        }

        def create_backup(root):
            backup_path.write_text(json.dumps(backup_data), encoding="utf-8")
            return backup_path

        with patch("web_app.threading.Thread") as thread_class, patch("web_app.GhostwriterApi") as api_class:
            thread_class.return_value.start.return_value = None
            api_class.return_value.create_backup.side_effect = create_backup
            response = self.client.post("/api-sources/left/check", data=self.with_csrf(), follow_redirects=False)
            check_id = response.headers["Location"].rsplit("/", 2)[-2]
            _check_api_source(self.app, Path(self.tmp_dir.name), check_id)

        status = self.client.get(response.headers["Location"])
        self.assertEqual(status.status_code, 200)
        self.assertIn(b"Fetched and backed up 2 findings from Left Test Ghostwriter", status.data)
        self.assertIn(b"Open backup browser", status.data)
        self.assertEqual(list_previous_jobs(Path(self.tmp_dir.name)), [])
        backup_files = list((backup_root / "left").glob("*.json"))
        self.assertEqual(len(backup_files), 1)
        api_class.return_value.create_backup.assert_called_once_with(backup_root)

    def test_api_source_check_worker_honours_stop_request(self):
        config = get_config()
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "Left Test Ghostwriter",
                "base_url": "https://left.example",
                "bearer_token": "left-token",
            }
        )

        class CancellableApi:
            def __init__(self, server, progress):
                self.progress = progress

            def create_backup(self, root):
                self.progress(None)

        with patch("web_app.threading.Thread") as thread_class, patch("web_app.GhostwriterApi", CancellableApi):
            thread_class.return_value.start.return_value = None
            response = self.client.post("/api-sources/left/check", data=self.with_csrf(), follow_redirects=False)
            check_id = response.headers["Location"].rsplit("/", 2)[-2]
            self.client.post(response.headers["Location"].replace("/status", "/stop"), data=self.with_csrf())
            _check_api_source(self.app, Path(self.tmp_dir.name), check_id)

        status = self.client.get(response.headers["Location"])
        self.assertEqual(status.status_code, 200)
        self.assertIn(b"cancelled", status.data)

    def test_api_import_status_handles_partial_import_state(self):
        import_dir = Path(self.tmp_dir.name) / "api_imports"
        import_dir.mkdir(parents=True)
        (import_dir / "partialimport123.json").write_text("{partial", encoding="utf-8")

        response = self.client.get("/imports/partialimport123/status")

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"API import state could not be read", response.data)

    def test_api_import_worker_records_error_when_state_file_is_corrupt(self):
        import_dir = Path(self.tmp_dir.name) / "api_imports"
        import_dir.mkdir(parents=True)
        import_path = import_dir / "badstate123.json"
        import_path.write_text("{not json", encoding="utf-8")

        _import_job_sources(self.app, Path(self.tmp_dir.name), "badstate123")

        state = json.loads(import_path.read_text(encoding="utf-8"))
        self.assertEqual(state["status"], "error")
        self.assertIn("API import state could not be read", state["message"])

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
        self.assertIn(b"Delete this API backup? This cannot be undone.", response.data)

    def test_backup_detail_shows_expandable_finding_detail(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "finding-detail.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Left",
                    "graphql_url": "https://left.example/v1/graphql",
                    "created_at": "20260705T000000Z",
                    "record_count": 1,
                    "raw_records": [{"record": {"id": 1}, "tags": []}],
                    "normalised_records": [
                        record(
                            title="Detailed finding",
                            description="Detailed description",
                            impact="Detailed impact",
                            mitigation="Detailed mitigation",
                            replication_steps="Detailed steps",
                            references="https://example.test/reference",
                            extra_fields={"owner": "security"},
                        )
                    ],
                }
            ),
            encoding="utf-8",
        )
        get_config()["ghostwriter_api"]["backup_dir"] = str(backup_root)

        response = self.client.get("/api-backups/left/finding-detail.json")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'data-backup-finding-filter', response.data)
        self.assertIn(b'data-sort-column="title"', response.data)
        self.assertIn(b'data-sort-column="severity"', response.data)
        self.assertIn(b'data-sort-column="type"', response.data)
        self.assertNotIn(b'data-sort-column="actions"', response.data)
        self.assertIn(b"View finding detail", response.data)
        self.assertIn(b"Detailed description", response.data)
        self.assertIn(b"Detailed impact", response.data)
        self.assertIn(b"Detailed mitigation", response.data)
        self.assertIn(b"Detailed steps", response.data)
        self.assertIn(b"https://example.test/reference", response.data)
        self.assertIn(b"owner", response.data)

    def test_backup_list_delete_button_requires_confirmation(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "listed.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Left",
                    "graphql_url": "https://left.example/v1/graphql",
                    "created_at": "20260705T000000Z",
                    "record_count": 0,
                    "raw_records": [],
                    "normalised_records": [],
                }
            ),
            encoding="utf-8",
        )
        get_config()["ghostwriter_api"]["backup_dir"] = str(backup_root)

        response = self.client.get("/api-backups")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Delete this API backup? This cannot be undone.", response.data)

    def test_backup_download_returns_full_verified_backup_json(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "full-backup.json"
        backup_data = {
            "server_side": "left",
            "server_name": "Left",
            "graphql_url": "https://left.example/v1/graphql",
            "created_at": "20260705T000000Z",
            "record_count": 1,
            "raw_records": [{"record": {"id": 1, "title": "Raw finding"}, "tags": ["web"]}],
            "normalised_records": [record(title="Normalised finding", tags="web")],
        }
        backup_path.write_text(json.dumps(backup_data), encoding="utf-8")
        get_config()["ghostwriter_api"]["backup_dir"] = str(backup_root)

        response = self.client.get("/api-backups/left/full-backup.json/download")

        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertIn("full-backup.json", response.headers["Content-Disposition"])
        downloaded = response.get_json()
        self.assertEqual(downloaded["record_count"], 1)
        self.assertEqual(downloaded["raw_records"][0]["record"]["title"], "Raw finding")
        self.assertEqual(downloaded["normalised_records"][0]["title"], "Normalised finding")

    def test_backup_download_rejects_invalid_backup_json(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "invalid.json"
        backup_path.write_text(json.dumps({"record_count": 1, "raw_records": []}), encoding="utf-8")
        get_config()["ghostwriter_api"]["backup_dir"] = str(backup_root)

        response = self.client.get("/api-backups/left/invalid.json/download")

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"normalised_records", response.data)

    def test_backup_delete_removes_verified_backup(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "delete-me.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Left",
                    "graphql_url": "https://left.example/v1/graphql",
                    "created_at": "20260705T000000Z",
                    "record_count": 1,
                    "raw_records": [{"record": {"id": 1}, "tags": []}],
                    "normalised_records": [record()],
                }
            ),
            encoding="utf-8",
        )
        get_config()["ghostwriter_api"]["backup_dir"] = str(backup_root)

        response = self.client.post(
            "/api-backups/left/delete-me.json/delete",
            data=self.with_csrf(),
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(backup_path.exists())
        self.assertIn(b"Deleted backup delete-me.json.", response.data)

    def test_backup_delete_rejects_missing_csrf_token(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "csrf-delete.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Left",
                    "graphql_url": "https://left.example/v1/graphql",
                    "created_at": "20260705T000000Z",
                    "record_count": 0,
                    "raw_records": [],
                    "normalised_records": [],
                }
            ),
            encoding="utf-8",
        )
        get_config()["ghostwriter_api"]["backup_dir"] = str(backup_root)

        response = self.client.post("/api-backups/left/csrf-delete.json/delete")

        self.assertEqual(response.status_code, 400)
        self.assertTrue(backup_path.exists())
        self.assertIn(b"Invalid or missing form token", response.data)

    def test_backup_restore_complete_names_configured_server(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "restore.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Original backup name",
                    "graphql_url": "https://left.example/v1/graphql",
                    "created_at": "20260705T000000Z",
                    "record_count": 1,
                    "raw_records": [{"record": {"id": 1}, "tags": []}],
                    "normalised_records": [record()],
                }
            ),
            encoding="utf-8",
        )
        config = get_config()
        config["ghostwriter_api"]["backup_dir"] = str(backup_root)
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "YGHT Ghostwriter",
                "base_url": "https://left.example",
                "graphql_endpoint": "/v1/graphql",
                "bearer_token": "left-token",
            }
        )

        with patch("web_app.GhostwriterApi") as api_class:
            api_class.return_value.find_restore_candidates.return_value = []
            api_class.return_value.restore_backup_record.return_value = 1234
            response = self.client.post("/api-backups/left/restore.json/0/restore", data=self.with_csrf())

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"The selected Finding Template was added on YGHT Ghostwriter.", response.data)
        self.assertNotIn(b"restored to the left server", response.data)
        api_class.return_value.restore_backup_record.assert_called_once()

    def test_backup_restore_prompts_when_finding_already_exists(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "restore-existing.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Original backup name",
                    "graphql_url": "https://left.example/v1/graphql",
                    "created_at": "20260705T000000Z",
                    "record_count": 1,
                    "raw_records": [{"record": {"id": 99}, "tags": []}],
                    "normalised_records": [record(title="Existing finding")],
                }
            ),
            encoding="utf-8",
        )
        config = get_config()
        config["ghostwriter_api"]["backup_dir"] = str(backup_root)
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "YGHT Ghostwriter",
                "base_url": "https://left.example",
                "graphql_endpoint": "/v1/graphql",
                "bearer_token": "left-token",
            }
        )

        with patch("web_app.GhostwriterApi") as api_class:
            api_class.return_value.find_restore_candidates.return_value = [
                {
                    "id": 99,
                    "title": "Existing finding",
                    "finding_type": "Web",
                    "severity": "Medium",
                    "match_reason": "same original Ghostwriter ID",
                }
            ]
            response = self.client.post("/api-backups/left/restore-existing.json/0/restore", data=self.with_csrf())

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Finding already exists", response.data)
        self.assertIn(b"Replace existing finding", response.data)
        self.assertIn(b"Add as duplicate", response.data)
        self.assertIn(b"Do not restore", response.data)
        api_class.return_value.restore_backup_record.assert_not_called()

    def test_backup_restore_replace_rechecks_candidate_before_delete(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "replace-existing.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Original backup name",
                    "graphql_url": "https://left.example/v1/graphql",
                    "created_at": "20260705T000000Z",
                    "record_count": 1,
                    "raw_records": [{"record": {"id": 99}, "tags": []}],
                    "normalised_records": [record(title="Existing finding")],
                }
            ),
            encoding="utf-8",
        )
        config = get_config()
        config["ghostwriter_api"]["backup_dir"] = str(backup_root)
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "name": "YGHT Ghostwriter",
                "base_url": "https://left.example",
                "graphql_endpoint": "/v1/graphql",
                "bearer_token": "left-token",
            }
        )

        with patch("web_app.GhostwriterApi") as api_class:
            api_class.return_value.find_restore_candidates.return_value = [
                {
                    "id": 99,
                    "title": "Existing finding",
                    "finding_type": "Web",
                    "severity": "Medium",
                    "match_reason": "same original Ghostwriter ID",
                }
            ]
            api_class.return_value.restore_backup_record.return_value = 1234
            response = self.client.post(
                "/api-backups/left/replace-existing.json/0/restore",
                data=self.with_csrf({"restore_action": "replace", "existing_id": "99"}),
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"The selected Finding Template was replaced on YGHT Ghostwriter.", response.data)
        api_class.return_value.restore_backup_record.assert_called_once()
        self.assertEqual(api_class.return_value.restore_backup_record.call_args.kwargs["replace_existing_id"], 99)

    def test_backup_restore_rejects_mismatched_configured_target(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "mismatch.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Old Left",
                    "graphql_url": "https://old.example/v1/graphql",
                    "created_at": "20260705T000000Z",
                    "record_count": 1,
                    "raw_records": [{"record": {"id": 1}, "tags": []}],
                    "normalised_records": [record()],
                }
            ),
            encoding="utf-8",
        )
        config = get_config()
        config["ghostwriter_api"]["backup_dir"] = str(backup_root)
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "base_url": "https://new.example",
                "graphql_endpoint": "/v1/graphql",
                "bearer_token": "left-token",
            }
        )

        response = self.client.post("/api-backups/left/mismatch.json/0/restore", data=self.with_csrf())

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Backup target does not match", response.data)

    def test_backup_restore_rejects_missing_backup_target(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "missing-target.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Unknown Left",
                    "created_at": "20260705T000000Z",
                    "record_count": 1,
                    "raw_records": [{"record": {"id": 1}, "tags": []}],
                    "normalised_records": [record()],
                }
            ),
            encoding="utf-8",
        )
        config = get_config()
        config["ghostwriter_api"]["backup_dir"] = str(backup_root)
        config["ghostwriter_api"]["servers"]["left"].update(
            {
                "enabled": True,
                "base_url": "https://left.example",
                "graphql_endpoint": "/v1/graphql",
                "bearer_token": "left-token",
            }
        )

        response = self.client.post("/api-backups/left/missing-target.json/0/restore", data=self.with_csrf())

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Backup target is not recorded", response.data)

    def test_backup_restore_rejects_missing_csrf_token(self):
        backup_root = Path(self.tmp_dir.name) / "backups"
        backup_dir = backup_root / "left"
        backup_dir.mkdir(parents=True)
        backup_path = backup_dir / "csrf-restore.json"
        backup_path.write_text(
            json.dumps(
                {
                    "server_side": "left",
                    "server_name": "Left",
                    "graphql_url": "https://left.example/v1/graphql",
                    "created_at": "20260705T000000Z",
                    "record_count": 1,
                    "raw_records": [{"record": {"id": 1}, "tags": []}],
                    "normalised_records": [record()],
                }
            ),
            encoding="utf-8",
        )
        get_config()["ghostwriter_api"]["backup_dir"] = str(backup_root)

        response = self.client.post("/api-backups/left/csrf-restore.json/0/restore")

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Invalid or missing form token", response.data)

    def test_config_debug_logging_redacts_bearer_token_and_web_api_key(self):
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
                        "web_access": {
                            "api_key": "super-secret-web-key",
                        },
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
        self.assertNotIn("super-secret-web-key", log_text)


class WebAccessControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def make_client(self, web_access):
        configure_for_web_tests(web_access=web_access)
        app = create_app(
            {
                "TESTING": True,
                "GHOSTMERGE_JOBS_DIR": Path(self.tmp_dir.name),
                "SECRET_KEY": "test-secret",
            }
        )
        return app.test_client(), app

    def csrf_token(self, client):
        with client.session_transaction() as session:
            session.setdefault("_csrf_token", "test-csrf-token")
            return session["_csrf_token"]

    def test_valid_get_api_key_authenticates_session_for_later_post(self):
        client, _app = self.make_client(web_access_enabled())

        initial = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        response = client.post(
            "/jobs",
            data={
                "_csrf_token": self.csrf_token(client),
                "left_file": (io.BytesIO(b"not json"), "left.json"),
                "right_file": (io.BytesIO(b"[]"), "right.json"),
            },
            content_type="multipart/form-data",
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )

        self.assertEqual(initial.status_code, 200)
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Invalid JSON", response.data)

    def test_missing_api_key_is_rejected(self):
        client, _app = self.make_client(web_access_enabled())

        response = client.get("/", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid or missing API key", response.data)

    def test_invalid_api_key_is_rejected(self):
        client, _app = self.make_client(web_access_enabled())

        response = client.get("/?api_key=wrong", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid or missing API key", response.data)

    def test_empty_api_key_fails_closed_when_auth_is_enabled(self):
        client, _app = self.make_client(web_access_enabled(api_key=""))

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 401)
        self.assertIn(b"no API key is configured", response.data)

    def test_disallowed_source_ip_is_rejected_before_api_key_authentication(self):
        client, _app = self.make_client(web_access_enabled(allowed_source_ips=["10.0.0.1"]))

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Source IP address is not allowed", response.data)
        self.assertIn(b"direct 127.0.0.1", response.data)

    def test_empty_allowed_source_ips_fail_closed(self):
        client, _app = self.make_client(web_access_enabled(allowed_source_ips=[]))

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"no allowed IPs are configured", response.data)
        self.assertIn(b"Your source IP is 127.0.0.1", response.data)

    def test_absent_web_access_config_fails_closed(self):
        client, _app = self.make_client(None)

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"no allowed IPs are configured", response.data)
        self.assertIn(b"Your source IP is 127.0.0.1", response.data)

    def test_cidr_source_ip_range_is_allowed(self):
        client, _app = self.make_client(web_access_enabled(allowed_source_ips=["127.0.0.0/24"]))

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.42"})

        self.assertEqual(response.status_code, 200)

    def test_x_forwarded_for_is_not_trusted_for_source_ip(self):
        client, _app = self.make_client(web_access_enabled(allowed_source_ips=["203.0.113.10"]))

        response = client.get(
            "/?api_key=test-web-key",
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Source IP address is not allowed", response.data)
        self.assertIn(b"direct 127.0.0.1", response.data)
        self.assertNotIn(b"203.0.113.10 is not allowed", response.data)

    def test_trusted_header_mode_allows_header_ip_from_trusted_proxy(self):
        client, _app = self.make_client(
            web_access_enabled(
                source_ip_mode="trusted_header",
                allowed_source_ips=["203.0.113.10"],
                trusted_proxy_ips=["127.0.0.1"],
            )
        )

        response = client.get(
            "/?api_key=test-web-key",
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )

        self.assertEqual(response.status_code, 200)

    def test_trusted_header_mode_accepts_trusted_proxy_cidr(self):
        client, _app = self.make_client(
            web_access_enabled(
                source_ip_mode="trusted_header",
                allowed_source_ips=["203.0.113.10"],
                trusted_proxy_ips=["127.0.0.0/24"],
            )
        )

        response = client.get(
            "/?api_key=test-web-key",
            environ_base={"REMOTE_ADDR": "127.0.0.42"},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )

        self.assertEqual(response.status_code, 200)

    def test_trusted_header_mode_rejects_header_from_untrusted_proxy(self):
        client, _app = self.make_client(
            web_access_enabled(
                source_ip_mode="trusted_header",
                allowed_source_ips=["203.0.113.10"],
                trusted_proxy_ips=["10.0.0.1"],
            )
        )

        response = client.get(
            "/?api_key=test-web-key",
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"127.0.0.1 is not a trusted proxy", response.data)

    def test_trusted_header_mode_rejects_missing_header(self):
        client, _app = self.make_client(
            web_access_enabled(
                source_ip_mode="trusted_header",
                allowed_source_ips=["203.0.113.10"],
                trusted_proxy_ips=["127.0.0.1"],
            )
        )

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Trusted source IP header X-Forwarded-For is missing", response.data)

    def test_trusted_header_mode_rejects_invalid_header_ip(self):
        client, _app = self.make_client(
            web_access_enabled(
                source_ip_mode="trusted_header",
                allowed_source_ips=["203.0.113.10"],
                trusted_proxy_ips=["127.0.0.1"],
            )
        )

        response = client.get(
            "/?api_key=test-web-key",
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "not-an-ip"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Source IP from X-Forwarded-For is invalid", response.data)

    def test_both_mode_allows_direct_ip_without_header(self):
        client, _app = self.make_client(
            web_access_enabled(
                source_ip_mode="both",
                allowed_source_ips=["127.0.0.1"],
                trusted_proxy_ips=["127.0.0.1"],
            )
        )

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 200)

    def test_both_mode_allows_trusted_header_ip_when_direct_ip_is_not_allowed(self):
        client, _app = self.make_client(
            web_access_enabled(
                source_ip_mode="both",
                allowed_source_ips=["203.0.113.10"],
                trusted_proxy_ips=["127.0.0.1"],
            )
        )

        response = client.get(
            "/?api_key=test-web-key",
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )

        self.assertEqual(response.status_code, 200)

    def test_unsupported_source_ip_mode_fails_closed(self):
        client, _app = self.make_client(web_access_enabled(source_ip_mode="proxy_magic"))

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"source ip restriction mode", response.data.lower())

    def test_framing_headers_and_session_cookie_policy_are_applied(self):
        client, app = self.make_client(web_access_enabled(frame_ancestors=["https://portal.example"]))

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Security-Policy"], "frame-ancestors https://portal.example")
        self.assertNotIn("X-Frame-Options", response.headers)
        self.assertEqual(app.config["SESSION_COOKIE_SAMESITE"], "None")
        self.assertTrue(app.config["SESSION_COOKIE_SECURE"])

    def test_configured_reverse_proxy_prefix_is_used_for_generated_urls(self):
        client, _app = self.make_client(web_access_enabled(reverse_proxy_prefix="/merge"))

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'src="/merge/static/GhostMerge-logo.png"', response.data)
        self.assertIn(b'src="/merge/static/review_shortcuts.js"', response.data)
        self.assertIn(b'href="/merge/"', response.data)
        self.assertIn(b'action="/merge/jobs"', response.data)

    def test_configured_reverse_proxy_prefix_accepts_prefixed_incoming_paths(self):
        client, _app = self.make_client(web_access_enabled(reverse_proxy_prefix="/merge"))

        response = client.get("/merge/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        asset_response = client.get("/merge/static/GhostMerge-logo.png", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'src="/merge/static/GhostMerge-logo.png"', response.data)
        self.assertEqual(asset_response.status_code, 200)
        self.assertEqual(asset_response.content_type, "image/png")

    def test_configured_reverse_proxy_prefix_can_be_written_without_leading_slash(self):
        client, _app = self.make_client(web_access_enabled(reverse_proxy_prefix="merge"))

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'src="/merge/static/GhostMerge-logo.png"', response.data)

    def test_invalid_reverse_proxy_prefix_fails_closed(self):
        client, _app = self.make_client(web_access_enabled(reverse_proxy_prefix="/bad prefix"))

        response = client.get("/?api_key=test-web-key", environ_base={"REMOTE_ADDR": "127.0.0.1"})

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Reverse proxy prefix", response.data)

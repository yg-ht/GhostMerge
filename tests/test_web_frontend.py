import io
import json
import tempfile
import unittest
from pathlib import Path

from globals import get_config
from web_app import create_app
from web_service import (
    WebMergeError,
    apply_conflict_decision,
    apply_sensitivity_decision,
    create_merge_job,
    finalise_job,
    get_next_conflict,
    get_next_sensitivity_item,
    load_job,
    load_records_from_json_text,
    save_job,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def configure_for_web_tests(**overrides):
    config = get_config()
    with (PROJECT_ROOT / "ghostmerge_config.json").open("r", encoding="utf-8") as handle:
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

    def test_sensitivity_review_can_apply_offered_replacement(self):
        configure_for_web_tests(sensitivity_check_enabled=True)
        job = create_merge_job([record(description="ACME detail")], [], job_id="sens123")
        self.assertIsNone(get_next_conflict(job))

        item = get_next_sensitivity_item(job, {"acme": "[CLIENT]"})

        self.assertIsNotNone(item)
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
        self.assertIn(b"description", conflict.data)

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

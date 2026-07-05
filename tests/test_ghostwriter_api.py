import json
import tempfile
import unittest
from pathlib import Path

from ghostwriter_api import (
    GhostwriterApi,
    GhostwriterApiError,
    GhostwriterServerConfig,
    backup_root_from_config,
    ghostmerge_record_to_api_input,
    list_backups,
    load_server_configs,
    verify_backup,
)


def server_config(**overrides):
    data = {
        "side": "left",
        "name": "Test Ghostwriter",
        "graphql_url": "https://ghostwriter.example/v1/graphql",
        "bearer_token": "secret-token",
        "rate_limit_per_second": 1000.0,
    }
    data.update(overrides)
    return GhostwriterServerConfig(**data)


def finding_record(**overrides):
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
        "extra_fields": {},
    }
    data.update(overrides)
    return data


class FakeGraphQLClient:
    def __init__(self):
        self.calls = []
        self.deleted_ids = []
        self.created_objects = []
        self.tag_sets = []

    def execute(self, query, variables=None):
        variables = variables or {}
        self.calls.append((query, variables))
        if "FetchRawFindings" in query:
            if variables.get("offset", 0) > 0:
                return {"finding": []}
            return {
                "finding": [
                    {
                        "id": 99,
                        "title": "Existing finding",
                        "cvssScore": 4.2,
                        "cvssVector": "",
                        "description": "Existing description",
                        "impact": "",
                        "mitigation": "",
                        "replication_steps": "",
                        "hostDetectionTechniques": "",
                        "networkDetectionTechniques": "",
                        "references": "",
                        "findingGuidance": "",
                        "extraFields": {},
                        "severity": {"id": 3, "severity": "Medium"},
                        "type": {"id": 7, "findingType": "Web"},
                    }
                ]
            }
        if "FindingIds" in query:
            return {"finding": [{"id": 99}]}
        if "FindingLookups" in query:
            return {
                "findingSeverity": [{"id": 3, "severity": "Medium"}],
                "findingType": [{"id": 7, "findingType": "Web"}],
            }
        if "DeleteFinding" in query:
            self.deleted_ids.append(variables["id"])
            return {"delete_finding_by_pk": {"id": variables["id"]}}
        if "CreateFinding" in query:
            self.created_objects.append(variables["object"])
            return {"insert_finding_one": {"id": 101}}
        if "SetFindingTags" in query:
            self.tag_sets.append((variables["id"], variables["tags"]))
            return {"setTags": {"tags": variables["tags"]}}
        if "Tags(" in query:
            return {"tags": {"tags": ["existing"]}}
        raise AssertionError(f"Unexpected query: {query}")


class GhostwriterApiTests(unittest.TestCase):
    def test_server_config_requires_enabled_url_and_token(self):
        config = {
            "script_dir": "/tmp",
            "ghostwriter_api": {
                "default_rate_limit_per_second": 1.0,
                "servers": {
                    "left": {
                        "enabled": True,
                        "name": "Left",
                        "base_url": "https://left.example",
                        "bearer_token": "left-token",
                        "rate_limit_per_second": 2.5,
                    },
                    "right": {"enabled": False, "base_url": "https://right.example", "bearer_token": "right-token"},
                },
            },
        }

        servers = load_server_configs(config)

        self.assertEqual(servers["left"].graphql_url, "https://left.example/v1/graphql")
        self.assertEqual(servers["left"].rate_limit_per_second, 2.5)
        self.assertIsNone(servers["right"])

    def test_backup_root_uses_configured_relative_path(self):
        root = backup_root_from_config({"script_dir": "/tmp/project", "ghostwriter_api": {"backup_dir": "backups"}})

        self.assertEqual(root, Path("/tmp/project/backups"))

    def test_record_conversion_uses_lookup_ids_and_tags_are_excluded(self):
        converted = ghostmerge_record_to_api_input(
            finding_record(),
            {"severity": {"Medium": 3}, "finding_type": {"Web": 7}},
        )

        self.assertEqual(converted["severityId"], 3)
        self.assertEqual(converted["findingTypeId"], 7)
        self.assertEqual(converted["cvssScore"], 5.0)
        self.assertNotIn("tags", converted)

    def test_record_conversion_rejects_missing_lookup(self):
        with self.assertRaises(GhostwriterApiError):
            ghostmerge_record_to_api_input(finding_record(severity="Unknown"), {"severity": {}, "finding_type": {"Web": 7}})

    def test_replace_all_creates_verified_backup_then_deletes_and_reloads(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_client = FakeGraphQLClient()
            api = GhostwriterApi(server_config(), client=fake_client)

            backup_path = api.replace_all_findings([finding_record()], Path(tmp_dir))

            backup = verify_backup(backup_path)
            self.assertEqual(backup["record_count"], 1)
            self.assertEqual(fake_client.deleted_ids, [99])
            self.assertEqual(len(fake_client.created_objects), 1)
            self.assertEqual(fake_client.tag_sets, [(101, ["web", "xss"])])
            self.assertEqual(list_backups(Path(tmp_dir))[0]["record_count"], 1)

    def test_verify_backup_rejects_incomplete_backup(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "bad.json"
            path.write_text(json.dumps({"raw_records": []}), encoding="utf-8")

            with self.assertRaises(GhostwriterApiError):
                verify_backup(path)


if __name__ == "__main__":
    unittest.main()

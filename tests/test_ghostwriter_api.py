import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from ghostwriter_api import (
    GHOSTMERGE_LAST_SYNCED_AT_FIELD,
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
    def __init__(self, missing_query_fields=None, missing_mutation_fields=None):
        self.calls = []
        self.deleted_ids = []
        self.created_objects = []
        self.tag_sets = []
        self.missing_query_fields = set(missing_query_fields or [])
        self.missing_mutation_fields = set(missing_mutation_fields or [])

    def execute(self, query, variables=None):
        variables = variables or {}
        self.calls.append((query, variables))
        if "SyncPreflight" in query:
            query_fields = {"finding", "findingSeverity", "findingType", "tags"} - self.missing_query_fields
            mutation_fields = {"delete_finding_by_pk", "insert_finding_one", "setTags"} - self.missing_mutation_fields
            return {
                "__schema": {
                    "queryType": {"fields": [{"name": name} for name in sorted(query_fields)]},
                    "mutationType": {"fields": [{"name": name} for name in sorted(mutation_fields)]},
                }
            }
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


class FakeUrlResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return b'{"data": {"ok": true}}'


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
                        "graphql_endpoint": "/v1/graphql",
                        "bearer_token": "left-token",
                        "rate_limit_per_second": 2.5,
                        "strict_x509_verification": False,
                    },
                    "right": {"enabled": False, "base_url": "https://right.example", "bearer_token": "right-token"},
                },
            },
        }

        servers = load_server_configs(config)

        self.assertEqual(servers["left"].graphql_url, "https://left.example/v1/graphql")
        self.assertEqual(servers["left"].rate_limit_per_second, 2.5)
        self.assertFalse(servers["left"].strict_x509_verification)
        self.assertIsNone(servers["right"])

    def test_server_config_defaults_to_conservative_rate_limit(self):
        config = {
            "ghostwriter_api": {
                "servers": {
                    "left": {
                        "enabled": True,
                        "base_url": "https://left.example",
                        "bearer_token": "left-token",
                    }
                }
            }
        }

        servers = load_server_configs(config)

        self.assertEqual(servers["left"].rate_limit_per_second, 0.2)

    def test_server_config_accepts_full_graphql_endpoint(self):
        config = {
            "ghostwriter_api": {
                "servers": {
                    "left": {
                        "enabled": True,
                        "name": "Left",
                        "graphql_endpoint": "https://api.example/v1/graphql",
                        "bearer_token": "left-token",
                    }
                }
            }
        }

        servers = load_server_configs(config)

        self.assertEqual(servers["left"].graphql_url, "https://api.example/v1/graphql")

    def test_graphql_client_honours_disabled_tls_verification(self):
        sentinel_context = object()
        with patch("ghostwriter_api.ssl._create_unverified_context", return_value=sentinel_context), patch(
            "ghostwriter_api.urllib.request.urlopen",
            return_value=FakeUrlResponse(),
        ) as urlopen:
            from ghostwriter_api import GhostwriterGraphQLClient

            client = GhostwriterGraphQLClient(server_config(verify_tls=False))
            result = client.execute("query Test { ok }")

        self.assertEqual(result, {"ok": True})
        self.assertIs(urlopen.call_args.kwargs["context"], sentinel_context)

    def test_graphql_client_uses_default_tls_verification_by_default(self):
        with patch("ghostwriter_api.urllib.request.urlopen", return_value=FakeUrlResponse()) as urlopen:
            from ghostwriter_api import GhostwriterGraphQLClient

            GhostwriterGraphQLClient(server_config()).execute("query Test { ok }")

        self.assertIsNone(urlopen.call_args.kwargs["context"])

    def test_graphql_client_can_relax_strict_x509_without_disabling_tls_verification(self):
        import ssl

        with patch("ghostwriter_api.urllib.request.urlopen", return_value=FakeUrlResponse()) as urlopen:
            from ghostwriter_api import GhostwriterGraphQLClient

            GhostwriterGraphQLClient(server_config(strict_x509_verification=False)).execute("query Test { ok }")

        context = urlopen.call_args.kwargs["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            self.assertFalse(context.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_graphql_client_sends_opaque_token_as_bearer_header(self):
        with patch("ghostwriter_api.urllib.request.urlopen", return_value=FakeUrlResponse()) as urlopen:
            from ghostwriter_api import GhostwriterGraphQLClient

            GhostwriterGraphQLClient(server_config(bearer_token="gwat_example-token")).execute("query Test { ok }")

        request = urlopen.call_args.args[0]
        self.assertEqual(request.headers["Authorization"], "Bearer gwat_example-token")

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
            extra_fields = fake_client.created_objects[0]["extraFields"]
            self.assertIn(GHOSTMERGE_LAST_SYNCED_AT_FIELD, extra_fields)
            self.assertTrue(extra_fields[GHOSTMERGE_LAST_SYNCED_AT_FIELD].endswith("Z"))
            self.assertIn("T", extra_fields[GHOSTMERGE_LAST_SYNCED_AT_FIELD])
            self.assertEqual(fake_client.tag_sets, [(101, ["web", "xss"])])
            self.assertEqual(list_backups(Path(tmp_dir))[0]["record_count"], 1)

    def test_replace_all_preserves_extra_fields_when_adding_sync_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_client = FakeGraphQLClient()
            api = GhostwriterApi(server_config(), client=fake_client)

            api.replace_all_findings([finding_record(extra_fields={"owner": "red-team"})], Path(tmp_dir))

            extra_fields = fake_client.created_objects[0]["extraFields"]
            self.assertEqual(extra_fields["owner"], "red-team")
            self.assertIn(GHOSTMERGE_LAST_SYNCED_AT_FIELD, extra_fields)

    def test_preflight_rejects_missing_sync_capabilities_before_writes(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_client = FakeGraphQLClient(missing_mutation_fields={"delete_finding_by_pk"})
            api = GhostwriterApi(server_config(), client=fake_client)

            with self.assertRaisesRegex(GhostwriterApiError, "delete_finding_by_pk"):
                api.replace_all_findings([finding_record()], Path(tmp_dir))

            self.assertEqual(fake_client.deleted_ids, [])
            self.assertEqual(fake_client.created_objects, [])
            self.assertEqual(list_backups(Path(tmp_dir)), [])

    def test_preflight_error_redacts_configured_token(self):
        token = "gwat_secret-token"
        fake_client = FakeGraphQLClient()
        api = GhostwriterApi(server_config(bearer_token=token), client=fake_client)
        with patch.object(fake_client, "execute", side_effect=GhostwriterApiError(f"bad token {token}")):
            with self.assertRaises(GhostwriterApiError) as caught:
                api.preflight_sync_permissions()

        self.assertNotIn(token, str(caught.exception))
        self.assertIn("[REDACTED]", str(caught.exception))

    def test_backups_created_in_same_second_have_unique_paths(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_client = FakeGraphQLClient()
            api = GhostwriterApi(server_config(), client=fake_client)

            first = api.create_backup(Path(tmp_dir))
            second = api.create_backup(Path(tmp_dir))

            self.assertNotEqual(first, second)
            self.assertTrue(first.exists())
            self.assertTrue(second.exists())

    def test_create_backup_reports_fetch_progress(self):
        events = []
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_client = FakeGraphQLClient()
            api = GhostwriterApi(server_config(), client=fake_client, progress=events.append)

            api.create_backup(Path(tmp_dir))

        self.assertIn("backup_fetch", [event.stage for event in events])
        self.assertIn("backup", [event.stage for event in events])
        self.assertTrue(any(event.complete == 1 for event in events if event.stage == "backup_fetch"))

    def test_replace_all_validates_records_before_backup_or_delete(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_client = FakeGraphQLClient()
            api = GhostwriterApi(server_config(), client=fake_client)

            with self.assertRaises(GhostwriterApiError):
                api.replace_all_findings([finding_record(severity="Unknown")], Path(tmp_dir))

            self.assertEqual(fake_client.deleted_ids, [])
            self.assertEqual(fake_client.created_objects, [])
            self.assertEqual(list_backups(Path(tmp_dir)), [])

    def test_replace_all_rejects_non_object_extra_fields_before_backup_or_delete(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_client = FakeGraphQLClient()
            api = GhostwriterApi(server_config(), client=fake_client)

            with self.assertRaises(GhostwriterApiError):
                api.replace_all_findings([finding_record(extra_fields="[]")], Path(tmp_dir))

            self.assertEqual(fake_client.deleted_ids, [])
            self.assertEqual(fake_client.created_objects, [])
            self.assertEqual(list_backups(Path(tmp_dir)), [])

    def test_replace_all_rejects_invalid_cvss_before_backup_or_delete(self):
        invalid_scores = ["nan", "inf", "-inf", "-0.1", "10.1"]
        for score in invalid_scores:
            with self.subTest(score=score):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    fake_client = FakeGraphQLClient()
                    api = GhostwriterApi(server_config(), client=fake_client)

                    with self.assertRaises(GhostwriterApiError):
                        api.replace_all_findings([finding_record(cvss_score=score)], Path(tmp_dir))

                    self.assertEqual(fake_client.deleted_ids, [])
                    self.assertEqual(fake_client.created_objects, [])
                    self.assertEqual(list_backups(Path(tmp_dir)), [])

    def test_verify_backup_rejects_incomplete_backup(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "bad.json"
            path.write_text(json.dumps({"raw_records": []}), encoding="utf-8")

            with self.assertRaises(GhostwriterApiError):
                verify_backup(path)

    def test_verify_backup_rejects_mismatched_raw_and_normalised_records(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "mismatched.json"
            path.write_text(
                json.dumps(
                    {
                        "record_count": 1,
                        "raw_records": [{"record": {"id": 1}, "tags": []}],
                        "normalised_records": [finding_record(), finding_record(id="2")],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(GhostwriterApiError, "raw and normalised record counts"):
                verify_backup(path)


if __name__ == "__main__":
    unittest.main()

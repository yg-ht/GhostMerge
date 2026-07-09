import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from globals import get_config
from matching import fuzzy_match_findings, score_finding_similarity
from merge import (
    ResolvedWinner,
    get_compliance_reference_placeholder_choice,
    get_auto_suggest_values,
    get_single_sided_content_choice,
    renumber_findings,
    resolve_conflict,
)
from model import Finding, Observation
from sensitivity import (
    apply_sensitive_replacement,
    check_for_sensitivities,
    load_sensitive_terms,
)
from utils import (
    Aborting,
    apply_formatting_cleanup,
    apply_configured_normalisation,
    load_config,
    normalise_line_endings,
    remove_double_spaces_from_string,
    remove_pointless_html_tags,
)


def configure_for_tests(**overrides):
    """Reset global config so each test starts from a predictable baseline."""
    config = get_config()
    with (PROJECT_ROOT / "ghostmerge_config.example.json").open("r", encoding="utf-8") as handle:
        baseline = json.load(handle)

    baseline.update(
        {
            "config_loaded": True,
            "script_dir": PROJECT_ROOT,
            "log_file_enabled": False,
            "log_verbosity": "ERROR",
            "log_verbosity_cli": "ERROR",
            "log_verbosity_matching": "ERROR",
            "log_verbosity_merge": "ERROR",
            "log_verbosity_model": "ERROR",
            "log_verbosity_sensitivity": "ERROR",
            "log_verbosity_tui": "ERROR",
            "log_verbosity_utils": "ERROR",
            "verbosity_decision_log_enabled": False,
            "interactive_mode": False,
            "sensitivity_check_enabled": False,
        }
    )
    baseline.update(overrides)
    config.clear()
    config.update(baseline)
    return config


def finding(**overrides):
    data = {
        "id": 1,
        "severity": "Medium",
        "cvss_score": 5.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "finding_type": "Web",
        "title": "Cross-site scripting",
        "description": "An attacker can execute JavaScript.",
        "impact": "Session tokens may be stolen.",
        "mitigation": "Encode output.",
        "replication_steps": "Open the payload.",
        "host_detection_techniques": "",
        "network_detection_techniques": "",
        "references": "https://example.test/xss",
        "finding_guidance": "",
        "tags": ["web", "xss"],
        "extra_fields": {},
    }
    data.update(overrides)
    return Finding(**data)


class ConfigRegressionTests(unittest.TestCase):
    def setUp(self):
        configure_for_tests()

    def test_load_config_accepts_path_and_local_override(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "ghostmerge_config.json"
            config_path.write_text(
                json.dumps({"log_file_enabled": False, "interactive_mode": True}),
                encoding="utf-8",
            )
            Path(f"{config_path}.local").write_text(
                json.dumps({"interactive_mode": False}),
                encoding="utf-8",
            )

            load_config(config_path)

        self.assertFalse(get_config()["interactive_mode"])
        self.assertTrue(get_config()["config_loaded"])

    def test_load_config_deep_merges_local_override(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "ghostmerge_config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "log_file_enabled": False,
                        "ghostwriter_api": {
                            "backup_dir": "backups",
                            "servers": {
                                "left": {
                                    "enabled": True,
                                    "base_url": "https://left.example",
                                    "graphql_endpoint": "/v1/graphql",
                                },
                                "right": {
                                    "enabled": False,
                                },
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            Path(f"{config_path}.local").write_text(
                json.dumps({"ghostwriter_api": {"servers": {"left": {"bearer_token": "local-token"}}}}),
                encoding="utf-8",
            )

            load_config(config_path)

        self.assertEqual(get_config()["ghostwriter_api"]["backup_dir"], "backups")
        self.assertTrue(get_config()["ghostwriter_api"]["servers"]["left"]["enabled"])
        self.assertEqual(get_config()["ghostwriter_api"]["servers"]["left"]["base_url"], "https://left.example")
        self.assertEqual(get_config()["ghostwriter_api"]["servers"]["left"]["bearer_token"], "local-token")
        self.assertIn("right", get_config()["ghostwriter_api"]["servers"])
        self.assertTrue(get_config()["config_loaded"])

    def test_load_config_uses_project_defaults_when_user_config_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "ghostmerge_config.json"

            load_config(config_path)

        self.assertTrue(get_config()["config_loaded"])
        self.assertIn("ghostwriter_api", get_config())
        self.assertEqual(get_config()["script_dir"], PROJECT_ROOT)

    def test_sparse_user_config_overrides_project_defaults(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "ghostmerge_config.json"
            config_path.write_text(
                json.dumps({"interactive_mode": False}),
                encoding="utf-8",
            )

            load_config(config_path)

        self.assertFalse(get_config()["interactive_mode"])
        self.assertIn("ghostwriter_api", get_config())


class FindingModelRegressionTests(unittest.TestCase):
    def setUp(self):
        configure_for_tests()

    def test_from_dict_coerces_ghostwriter_style_values(self):
        record = {
            "id": "7",
            "severity": "High",
            "cvss_score": "8.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "finding_type": "Web",
            "title": "  Login  bypass  ",
            "description": "<p></p>Allows access.\r\nSecond line.",
            "impact": "Privilege escalation",
            "mitigation": "Patch the application",
            "replication_steps": "",
            "host_detection_techniques": "",
            "network_detection_techniques": "",
            "references": "",
            "finding_guidance": "",
            "tags": "auth, web",
            "extra_fields": '{"owner": "red-team"}',
        }

        parsed = Finding.from_dict(record)

        self.assertEqual(parsed.id, 7)
        self.assertEqual(parsed.cvss_score, 8.1)
        self.assertEqual(parsed.title, "Login bypass")
        self.assertEqual(parsed.description, "Allows access.\nSecond line.")
        self.assertEqual(parsed.tags, ["auth", "web"])
        self.assertEqual(parsed.extra_fields, {"owner": "red-team"})

    def test_from_dict_migrates_finding_extra_field_prefixes(self):
        record = finding(
            description="kept",
            extra_fields={
                "extra_compliance_reference": None,
                "owner": "red-team",
            },
        ).to_dict()

        parsed = Finding.from_dict(record)

        self.assertEqual(parsed.extra_fields, {"compliance_reference": None, "owner": "red-team"})

    def test_from_dict_preserves_existing_extra_field_on_collision(self):
        record = finding(
            description="kept",
            extra_fields={
                "extra_compliance_reference": "old",
                "compliance_reference": "new",
            },
        ).to_dict()

        parsed = Finding.from_dict(record)

        self.assertEqual(parsed.extra_fields, {"compliance_reference": "new"})

    def test_extra_field_key_migration_does_not_change_observations(self):
        parsed = Observation.from_dict(
            {
                "id": 1,
                "title": "Observation",
                "description": "kept",
                "tags": [],
                "extra_fields": {"extra_compliance_reference": None},
            }
        )

        self.assertEqual(parsed.extra_fields, {"extra_compliance_reference": None})

    def test_to_dict_preserves_import_compatible_string_fields(self):
        parsed = finding(id=3, cvss_score=4.2, tags=["api", "auth"], extra_fields={"owner": "blue"})

        serialised = parsed.to_dict()

        self.assertEqual(serialised["id"], "3")
        self.assertEqual(serialised["cvss_score"], "4.2")
        self.assertEqual(serialised["tags"], "api, auth")
        self.assertEqual(json.loads(serialised["extra_fields"]), {"owner": "blue"})

    def test_invalid_severity_aborts_instead_of_silently_accepting(self):
        record = finding(severity="Urgent", references="").to_dict()

        with redirect_stdout(StringIO()):
            with self.assertRaises(Aborting):
                Finding.from_dict(record)

    def test_invalid_cvss_scores_abort_instead_of_silently_accepting(self):
        for score in ("nan", "inf", "-inf", "-0.1", "10.1"):
            with self.subTest(score=score):
                record = finding(cvss_score=score, references="").to_dict()

                with redirect_stdout(StringIO()):
                    with self.assertRaises(Aborting):
                        Finding.from_dict(record)


class NormalisationRegressionTests(unittest.TestCase):
    def setUp(self):
        configure_for_tests()

    def test_string_normalisation_helpers_cover_common_format_noise(self):
        self.assertEqual(remove_double_spaces_from_string("alpha  beta   gamma"), "alpha beta gamma")
        self.assertEqual(normalise_line_endings("<p>a</p>\r\n<p>b</p>"), "<p>a</p><p>b</p>")
        self.assertEqual(remove_pointless_html_tags("<p></p><span>  </span><p>kept</p>"), "<p>kept</p>")

    def test_configured_normalisation_is_recursive(self):
        value = {"a": " one  two ", "b": ["<p></p>kept\r\ntext"]}

        normalised = apply_configured_normalisation(value)

        self.assertEqual(normalised, {"a": "one two", "b": ["kept\ntext"]})

    def test_formatting_cleanup_replaces_legacy_highlight_span(self):
        value = '<span class="highlight" style="background-color: yellow">secret</span>'

        self.assertEqual(apply_formatting_cleanup(value), "<mark>secret</mark>")

    def test_formatting_cleanup_unwraps_legacy_formatting_spans(self):
        value = '<span style="font-weight: 400;">secret</span>'

        self.assertEqual(apply_formatting_cleanup(value), "secret")

    def test_formatting_cleanup_preserves_unrelated_angle_bracket_text(self):
        value = 'Keep 5 < 10 > 3 and <span style="font-weight: 400;">secret</span>.'

        self.assertEqual(apply_formatting_cleanup(value), "Keep 5 < 10 > 3 and secret.")

    def test_formatting_cleanup_allows_harmless_attribute_variants(self):
        value = '<span style="background-color: yellow;" class="highlight extra">secret</span>'

        self.assertEqual(apply_formatting_cleanup(value), "<mark>secret</mark>")

    def test_formatting_cleanup_only_unwraps_red_span_inside_mark(self):
        highlighted = '<mark><span data-color="#f00" style="color: #f00;">secret</span></mark>'
        standalone = '<span data-color="#f00" style="color: #f00;">secret</span>'

        self.assertEqual(apply_formatting_cleanup(highlighted), "<mark>secret</mark>")
        self.assertEqual(apply_formatting_cleanup(standalone), standalone)

    def test_formatting_cleanup_adds_spellcheck_to_code_tags(self):
        self.assertEqual(
            apply_formatting_cleanup("<code>payload</code>"),
            '<code spellcheck="false">payload</code>',
        )
        self.assertEqual(
            apply_formatting_cleanup('<code class="language-python">payload</code>'),
            '<code class="language-python" spellcheck="false">payload</code>',
        )
        self.assertEqual(
            apply_formatting_cleanup('<code spellcheck="true">payload</code>'),
            '<code spellcheck="false">payload</code>',
        )

    def test_formatting_cleanup_replaces_pre_tags_with_code_tags(self):
        self.assertEqual(
            apply_formatting_cleanup('<pre class="rich-code">payload</pre>'),
            '<code spellcheck="false">payload</code>',
        )
        self.assertEqual(
            apply_formatting_cleanup("<pre>payload</pre>"),
            '<code spellcheck="false">payload</code>',
        )

    def test_formatting_cleanup_removes_editor_offsets_from_code_tags(self):
        self.assertEqual(
            apply_formatting_cleanup('<code data-end="653" start="645" spellcheck="false">payload</code>'),
            '<code spellcheck="false">payload</code>',
        )
        self.assertEqual(
            apply_formatting_cleanup('<code class="language-python" data-end="1" start="0">payload</code>'),
            '<code class="language-python" spellcheck="false">payload</code>',
        )

    def test_list_item_normalisation_unwraps_single_inner_paragraphs(self):
        self.assertEqual(
            remove_pointless_html_tags("<ul><li><p>First</p></li><li>Second</li></ul>"),
            "<ul><li>First</li><li>Second</li></ul>",
        )
        self.assertEqual(
            remove_pointless_html_tags("<ul><li><p>First</p><p>Second</p></li></ul>"),
            "<ul><li><p>First</p><p>Second</p></li></ul>",
        )

    def test_formatting_cleanup_preserves_unconfigured_spans(self):
        value = '<span class="note" style="background-color: yellow">secret</span>'

        self.assertEqual(apply_formatting_cleanup(value), value)

    def test_formatting_cleanup_runs_for_finding_and_observation_imports(self):
        value = '<span class="highlight" style="background-color: yellow">secret</span>'

        parsed_finding = Finding.from_dict(finding(description=value).to_dict())
        parsed_observation = Observation.from_dict(
            {
                "id": 1,
                "title": "Observation",
                "description": value,
                "tags": [],
                "extra_fields": {},
            }
        )

        self.assertEqual(parsed_finding.description, "<mark>secret</mark>")
        self.assertEqual(parsed_observation.description, "<mark>secret</mark>")

    def test_formatting_cleanup_removes_deprecated_markup_review_noise(self):
        legacy = '<span class="highlight" style="background-color: yellow">secret</span>'
        current = "<mark>secret</mark>"

        legacy_finding = Finding.from_dict(finding(description=legacy).to_dict())
        current_finding = Finding.from_dict(finding(description=current).to_dict())

        self.assertEqual(legacy_finding.description, current_finding.description)

    def test_default_sensitive_terms_do_not_contain_formatting_cleanup_rules(self):
        terms = load_sensitive_terms("sensitive_terms.txt", PROJECT_ROOT)

        formatting_terms = [term for term in terms if "<" in term and ">" in term and term != "{{.evidence}}"]

        self.assertEqual(formatting_terms, [])


class MatchingRegressionTests(unittest.TestCase):
    def setUp(self):
        configure_for_tests()

    def test_exact_findings_score_highly(self):
        left = finding()
        right = finding(id=2)

        self.assertGreaterEqual(score_finding_similarity(left, right), 90)

    def test_fuzzy_matching_returns_matches_and_unmatched_records(self):
        left_match = finding(id=1, title="Cross site scripting in login")
        right_match = finding(id=10, title="Login cross-site scripting")
        left_orphan = finding(id=2, title="Missing TLS certificate", description="TLS is absent.")
        right_orphan = finding(id=11, title="Weak password policy", description="Passwords are short.")

        matches, unmatched_left, unmatched_right = fuzzy_match_findings(
            [left_match, left_orphan],
            [right_match, right_orphan],
            threshold=70,
        )

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["left"].id, 1)
        self.assertEqual(matches[0]["right"].id, 10)
        self.assertEqual([item.id for item in unmatched_left], [2])
        self.assertEqual([item.id for item in unmatched_right], [11])


class MergeRegressionTests(unittest.TestCase):
    def setUp(self):
        configure_for_tests()

    def test_resolve_conflict_prefers_populated_and_more_complete_values(self):
        self.assertEqual(resolve_conflict("", "right value"), (ResolvedWinner.RIGHT, "right value"))
        self.assertEqual(resolve_conflict("left value", ""), (ResolvedWinner.LEFT, "left value"))
        self.assertEqual(
            resolve_conflict("short value", "longer value with more tokens"),
            (ResolvedWinner.RIGHT, "longer value with more tokens"),
        )

    def test_single_sided_content_choice_detects_low_risk_auto_accept(self):
        should_accept, winner, value = get_single_sided_content_choice([], ["web"])

        self.assertTrue(should_accept)
        self.assertEqual(winner, ResolvedWinner.RIGHT)
        self.assertEqual(value, ["web"])

    def test_auto_suggest_combines_tags_and_extra_field_winners(self):
        left = finding(tags=["web", "auth"], extra_fields={"owner": "left", "left_only": "yes"})
        right = finding(tags=["xss", "web"], extra_fields={"owner": "right team", "right_only": "yes"})

        suggested, winners = get_auto_suggest_values(left, right)

        self.assertEqual(set(suggested.tags), {"web", "auth", "xss"})
        self.assertEqual(suggested.extra_fields["owner"], "right team")
        self.assertEqual(winners["extra_fields"]["owner"], ResolvedWinner.RIGHT)
        self.assertEqual(suggested.extra_fields["left_only"], "yes")
        self.assertEqual(suggested.extra_fields["right_only"], "yes")

    def test_compliance_reference_placeholder_auto_accepts_richer_extra_fields(self):
        left = finding(extra_fields={"compliance_reference": None})
        right = finding(extra_fields={"compliance_reference": "PCI DSS", "owner": "right team"})

        should_accept, winner, value = get_compliance_reference_placeholder_choice(left.extra_fields, right.extra_fields)
        suggested, winners = get_auto_suggest_values(left, right)

        self.assertTrue(should_accept)
        self.assertEqual(winner, ResolvedWinner.RIGHT)
        self.assertEqual(value, right.extra_fields)
        self.assertEqual(suggested.extra_fields, right.extra_fields)
        self.assertEqual(winners["extra_fields"], ResolvedWinner.RIGHT)

    def test_renumber_findings_aligns_ids_and_rejects_mismatched_lengths(self):
        left = [finding(id=9), finding(id=10)]
        right = [finding(id=20), finding(id=21)]

        renumbered_left, renumbered_right = renumber_findings(left, right, start_id=3)

        self.assertEqual([item.id for item in renumbered_left], [3, 4])
        self.assertEqual([item.id for item in renumbered_right], [3, 4])
        with self.assertRaises(ValueError):
            renumber_findings([finding()], [], start_id=1)


class SensitivityRegressionTests(unittest.TestCase):
    def setUp(self):
        configure_for_tests(sensitivity_check_enabled=True)

    def test_sensitive_terms_load_flag_only_and_replacements(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            terms_path = Path(tmp_dir) / "terms.txt"
            terms_path.write_text("# comment\nsecret\nacme => [CLIENT]\n", encoding="utf-8")

            terms = load_sensitive_terms("terms.txt", tmp_dir)

        self.assertEqual(terms["secret"], None)
        self.assertEqual(terms["acme"], "[CLIENT]")

    def test_check_for_sensitivities_finds_normalised_terms(self):
        hits = check_for_sensitivities("The ACME platform is secret.", {"acme": "[CLIENT]", "secret": None})

        self.assertEqual(hits, [("acme", "[CLIENT]"), ("secret", None)])

    def test_replacement_handles_literals_and_legacy_opening_tag_pairs(self):
        configure_for_tests(
            sensitivity_check_enabled=True,
            remove_pointless_html_tags=False,
            normalise_line_endings=False,
        )

        self.assertEqual(
            apply_sensitive_replacement("ACME and acme", "acme", "[CLIENT]"),
            "[CLIENT] and [CLIENT]",
        )
        self.assertEqual(
            apply_sensitive_replacement("<mark>secret</mark> text", "<mark>", ""),
            "secret text",
        )
        self.assertEqual(
            apply_sensitive_replacement("<b>secret</b>", "<b>", "<strong>"),
            "<strong>secret</strong>",
        )


class CliRegressionTests(unittest.TestCase):
    def setUp(self):
        configure_for_tests()

    def test_cli_help_works_in_project_virtualenv(self):
        python_bin = PROJECT_ROOT / ".venv" / "bin" / "python"
        self.skipTest("project virtualenv is not present") if not python_bin.exists() else None

        result = subprocess.run(
            [str(python_bin), "ghostmerge.py", "--help"],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--file-left", result.stdout)
        self.assertIn("--file-right", result.stdout)

    def test_cli_can_merge_sample_files_with_config_path(self):
        python_bin = PROJECT_ROOT / ".venv" / "bin" / "python"
        self.skipTest("project virtualenv is not present") if not python_bin.exists() else None

        left_record = finding(id=1, title="Cross-site scripting", description="Left detail").to_dict()
        right_record = finding(id=2, title="Cross site scripting", description="Right detail").to_dict()

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            left_path = tmp_path / "left.json"
            right_path = tmp_path / "right.json"
            out_left = tmp_path / "left-out.json"
            out_right = tmp_path / "right-out.json"
            config_path = tmp_path / "ghostmerge_config.json"

            left_path.write_text(json.dumps([left_record]), encoding="utf-8")
            right_path.write_text(json.dumps([right_record]), encoding="utf-8")

            with (PROJECT_ROOT / "ghostmerge_config.example.json").open("r", encoding="utf-8") as handle:
                config = json.load(handle)
            config.update(
                {
                    "interactive_mode": False,
                    "sensitivity_check_enabled": False,
                    "log_file_enabled": False,
                    "fuzzy_match_threshold": [70],
                }
            )
            config_path.write_text(json.dumps(config), encoding="utf-8")

            result = subprocess.run(
                [
                    str(python_bin),
                    "ghostmerge.py",
                    "--file-left",
                    str(left_path),
                    "--file-right",
                    str(right_path),
                    "--out-left",
                    str(out_left),
                    "--out-right",
                    str(out_right),
                    "--config",
                    str(config_path),
                ],
                cwd=PROJECT_ROOT,
                text=True,
                input="\n",
                capture_output=True,
                timeout=10,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(out_left.exists())
            self.assertTrue(out_right.exists())

            merged_left = json.loads(out_left.read_text(encoding="utf-8"))
            merged_right = json.loads(out_right.read_text(encoding="utf-8"))

        self.assertEqual(len(merged_left), 1)
        self.assertEqual(len(merged_right), 1)
        self.assertEqual(merged_left[0]["id"], "1")
        self.assertEqual(merged_right[0]["id"], "1")
        self.assertEqual(merged_left[0]["description"], merged_right[0]["description"])


if __name__ == "__main__":
    unittest.main()

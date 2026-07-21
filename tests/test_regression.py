import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from globals import get_config
from matching import fuzzy_match_findings, fuzzy_match_records, score_finding_similarity
from merge import (
    ResolvedWinner,
    append_unmatched_records,
    build_manual_match,
    get_compliance_reference_placeholder_choice,
    get_auto_suggest_values,
    get_single_sided_content_choice,
    merge_main,
    reject_matched_record,
    renumber_findings,
    reprocess_orphan_matches,
    resolve_conflict,
    set_record_pair_field_values,
)
from model import Finding, Observation
from sensitivity import (
    apply_pre_match_sensitivity_replacements,
    apply_sensitive_replacement,
    check_for_sensitivities,
    load_sensitive_terms,
    sensitivities_checker_single_field,
    sensitive_terms_digest,
)
from utils import (
    Aborting,
    apply_formatting_cleanup,
    apply_configured_normalisation,
    load_json,
    load_config,
    normalise_cvss_vector,
    normalise_line_endings,
    normalise_references,
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

    def test_invalid_json_diagnostics_do_not_include_input_content(self):
        private_content = '{"private-customer-detail": '

        with patch("utils.log") as mocked_log:
            with self.assertRaises(json.JSONDecodeError):
                load_json(json_string=private_content)

        logged_text = " ".join(str(call) for call in mocked_log.call_args_list)
        self.assertNotIn("private-customer-detail", logged_text)


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

    def test_non_interactive_invalid_field_aborts_without_terminal_prompt(self):
        record = finding(references="").to_dict()
        record["id"] = "not-an-integer"

        with patch("model.prompt_user_to_fix_field") as prompt:
            with redirect_stdout(StringIO()):
                with self.assertRaises(Aborting):
                    Finding.from_dict(record)

        prompt.assert_not_called()

    def test_interactive_invalid_field_can_be_corrected(self):
        configure_for_tests(interactive_mode=True)
        record = finding(references="").to_dict()
        record["id"] = "not-an-integer"

        with patch("model.prompt_user_to_fix_field", return_value=(0, 7)) as prompt:
            parsed = Finding.from_dict(record)

        prompt.assert_called_once()
        self.assertEqual(parsed.id, 7)


class NormalisationRegressionTests(unittest.TestCase):
    def setUp(self):
        configure_for_tests()

    def test_string_normalisation_helpers_cover_common_format_noise(self):
        self.assertEqual(remove_double_spaces_from_string("alpha  beta   gamma"), "alpha beta gamma")
        self.assertEqual(normalise_line_endings("<p>a</p>\r\n<p>b</p>"), "<p>a</p><p>b</p>")
        self.assertEqual(remove_pointless_html_tags("<p></p><span>  </span><p>kept</p>"), "<p>kept</p>")

    def test_references_are_trimmed_and_deduplicated(self):
        value = " https://example.test/a \n\nhttps://example.test/a\nNote\n Note "

        self.assertEqual(normalise_references(value), "https://example.test/a\nNote")

    def test_cvss_vectors_are_case_and_whitespace_normalised(self):
        self.assertEqual(
            normalise_cvss_vector(" cvss:3.1 / av:n / ac:l / pr:n "),
            "CVSS:3.1/AV:N/AC:L/PR:N",
        )

    def test_configured_normalisation_is_recursive(self):
        value = {"a": " one  two ", "b": ["<p></p>kept\r\ntext"]}

        normalised = apply_configured_normalisation(value)

        self.assertEqual(normalised, {"a": "one two", "b": ["kept\ntext"]})

    def test_field_specific_normalisation_runs_on_finding_import(self):
        parsed = Finding.from_dict(
            finding(
                cvss_vector=" cvss:3.1 / av:n / ac:l / pr:n ",
                references=" https://example.test/a \nhttps://example.test/a\n Note ",
            ).to_dict()
        )

        self.assertEqual(parsed.cvss_vector, "CVSS:3.1/AV:N/AC:L/PR:N")
        self.assertEqual(parsed.references, "https://example.test/a\nNote")

    def test_unicode_whitespace_normalisation_handles_nbsp_and_tabs(self):
        parsed = Finding.from_dict(finding(title="Login\xa0\t bypass").to_dict())

        self.assertEqual(parsed.title, "Login bypass")

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

    def test_formatting_cleanup_collapses_redundant_nested_code_tags(self):
        nested = '<pre><code><mark>&lt;EVIDENCE&gt;</mark></code></pre>'
        expected = '<code spellcheck="false"><mark>&lt;EVIDENCE&gt;</mark></code>'

        self.assertEqual(apply_formatting_cleanup(nested), expected)
        self.assertEqual(apply_formatting_cleanup(expected), expected)
        self.assertEqual(
            apply_formatting_cleanup("<code><code><code>payload</code></code></code>"),
            '<code spellcheck="false">payload</code>',
        )

    def test_formatting_cleanup_repairs_existing_nested_code_and_preserves_attributes(self):
        nested = (
            '<code spellcheck="false">\n'
            '<code class="language-python" data-end="653" start="645">payload</code>\n'
            '</code>'
        )

        self.assertEqual(
            apply_formatting_cleanup(nested),
            '<code class="language-python" spellcheck="false">\npayload\n</code>',
        )

    def test_formatting_cleanup_keeps_nested_code_with_meaningful_sibling_content(self):
        nested = '<code>prefix <code>payload</code> suffix</code>'

        self.assertEqual(
            apply_formatting_cleanup(nested),
            '<code spellcheck="false">prefix <code spellcheck="false">payload</code> suffix</code>',
        )

    def test_formatting_cleanup_preserves_nested_code_classes(self):
        nested = '<code class="OuterClass"><code class="inner-class">payload</code></code>'

        self.assertEqual(
            apply_formatting_cleanup(nested),
            '<code class="OuterClass inner-class" spellcheck="false">payload</code>',
        )

    def test_formatting_cleanup_does_not_collapse_malformed_or_multi_child_code(self):
        malformed = '<code><code>payload</code>'
        multiple_children = '<code><code>payload</code><span>note</span></code>'

        self.assertEqual(
            apply_formatting_cleanup(malformed),
            '<code spellcheck="false"><code spellcheck="false">payload</code>',
        )
        self.assertEqual(
            apply_formatting_cleanup(multiple_children),
            '<code spellcheck="false"><code spellcheck="false">payload</code><span>note</span></code>',
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

    def test_formatting_cleanup_outputs_stable_attributes_and_inline_tags(self):
        self.assertEqual(
            apply_formatting_cleanup('<code start="0" data-end="1" class="zulu alpha">payload</code>'),
            '<code class="alpha zulu" spellcheck="false">payload</code>',
        )
        self.assertEqual(apply_formatting_cleanup("<b>bold</b> and <i>italic</i>"), "<strong>bold</strong> and <em>italic</em>")

    def test_list_item_normalisation_unwraps_single_inner_paragraphs(self):
        self.assertEqual(
            remove_pointless_html_tags("<ul><li><p>First</p></li><li>Second</li></ul>"),
            "<ul><li>First</li><li>Second</li></ul>",
        )
        self.assertEqual(
            remove_pointless_html_tags("<ul><li><p>First</p><p>Second</p></li></ul>"),
            "<ul><li><p>First</p><p>Second</p></li></ul>",
        )
        self.assertEqual(
            remove_pointless_html_tags("<div><p>Only child</p></div>"),
            "<div>Only child</div>",
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

    def test_nested_code_cleanup_runs_for_finding_and_observation_imports(self):
        value = '<pre><code><mark>&lt;EVIDENCE&gt;</mark></code></pre>'
        expected = '<code spellcheck="false"><mark>&lt;EVIDENCE&gt;</mark></code>'

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

        self.assertEqual(parsed_finding.description, expected)
        self.assertEqual(parsed_observation.description, expected)

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

    def test_matching_text_normalisation_does_not_change_stored_titles(self):
        left = finding(id=1, title="Cross-site scripting (login)")
        right = finding(id=2, title="cross site scripting  ( login )")

        score = score_finding_similarity(left, right)

        self.assertGreaterEqual(score, 60)
        self.assertEqual(left.title, "Cross-site scripting (login)")
        self.assertEqual(right.title, "cross site scripting  ( login )")

    def test_finding_similarity_ignores_only_last_synced_extra_field(self):
        baseline_score = score_finding_similarity(
            finding(extra_fields={}),
            finding(id=2, extra_fields={}),
        )
        timestamp_score = score_finding_similarity(
            finding(extra_fields={"ghostmerge_last_synced_at": "2026-07-20T10:00:00Z"}),
            finding(id=2, extra_fields={"ghostmerge_last_synced_at": "2026-07-21T10:00:00Z"}),
        )
        meaningful_difference_score = score_finding_similarity(
            finding(extra_fields={"owner": "red-team"}),
            finding(id=2, extra_fields={"owner": "blue-team"}),
        )

        self.assertEqual(timestamp_score, baseline_score)
        self.assertLess(meaningful_difference_score, baseline_score)

    def test_finding_records_are_normalised_before_matching(self):
        legacy_markup = '<span class="highlight" style="background-color: yellow">secret</span>'
        normalised_markup = "<mark>secret</mark>"
        left = finding(
            description=legacy_markup,
            extra_fields={"nested": {"detail": "  repeated   text  "}},
        )
        right = finding(
            id=2,
            description=normalised_markup,
            extra_fields={"nested": {"detail": "repeated text"}},
        )

        matches, unmatched_left, unmatched_right = fuzzy_match_findings([left], [right], threshold=70)

        self.assertEqual(len(matches), 1)
        self.assertEqual(unmatched_left, [])
        self.assertEqual(unmatched_right, [])
        self.assertEqual(matches[0]["left"].description, normalised_markup)
        self.assertEqual(matches[0]["right"].description, normalised_markup)
        self.assertEqual(matches[0]["left"].extra_fields, matches[0]["right"].extra_fields)

    def test_observation_records_are_normalised_before_matching(self):
        legacy_markup = '<span class="highlight" style="background-color: yellow">secret</span>'
        normalised_markup = "<mark>secret</mark>"
        left = Observation(
            id=1,
            title="Formatting observation",
            description=legacy_markup,
            extra_fields={"detail": "  repeated   text  "},
        )
        right = Observation(
            id=2,
            title="Formatting observation",
            description=normalised_markup,
            extra_fields={"detail": "repeated text"},
        )

        matches, unmatched_left, unmatched_right = fuzzy_match_records([left], [right], threshold=70)

        self.assertEqual(len(matches), 1)
        self.assertEqual(unmatched_left, [])
        self.assertEqual(unmatched_right, [])
        self.assertEqual(matches[0]["left"].description, normalised_markup)
        self.assertEqual(matches[0]["right"].description, normalised_markup)
        self.assertEqual(matches[0]["left"].extra_fields, matches[0]["right"].extra_fields)


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

        self.assertEqual(suggested.tags, ["auth", "web", "xss"])
        self.assertEqual(set(suggested.tags), {"web", "auth", "xss"})
        self.assertEqual(suggested.extra_fields["owner"], "right team")
        self.assertEqual(winners["extra_fields"]["owner"], ResolvedWinner.RIGHT)
        self.assertEqual(suggested.extra_fields["left_only"], "yes")
        self.assertEqual(suggested.extra_fields["right_only"], "yes")

    def test_auto_suggest_excludes_last_synced_extra_field(self):
        left = finding(
            extra_fields={"owner": "left", "ghostmerge_last_synced_at": "2026-07-20T10:00:00Z"},
        )
        right = finding(
            extra_fields={"owner": "right team", "ghostmerge_last_synced_at": "2026-07-21T10:00:00Z"},
        )

        suggested, winners = get_auto_suggest_values(left, right)

        self.assertEqual(suggested.extra_fields, {"owner": "right team"})
        self.assertEqual(winners["extra_fields"], {"owner": ResolvedWinner.RIGHT})

    def test_non_interactive_merge_preserves_side_specific_last_synced_values(self):
        left_timestamp = "2026-07-20T10:00:00Z"
        right_timestamp = "2026-07-21T10:00:00Z"
        left = finding(extra_fields={"ghostmerge_last_synced_at": left_timestamp})
        right = finding(id=2, extra_fields={"ghostmerge_last_synced_at": right_timestamp})

        merged_left, merged_right = merge_main({"left": left, "right": right, "score": 95.0})

        self.assertEqual(merged_left.extra_fields, {"ghostmerge_last_synced_at": left_timestamp})
        self.assertEqual(merged_right.extra_fields, {"ghostmerge_last_synced_at": right_timestamp})

    def test_resolved_extra_fields_do_not_copy_last_synced_to_a_side_without_one(self):
        left_timestamp = "2026-07-20T10:00:00Z"
        left = finding(extra_fields={"owner": "left", "ghostmerge_last_synced_at": left_timestamp})
        right = finding(id=2, extra_fields={"owner": "right"})

        set_record_pair_field_values(
            left,
            right,
            "extra_fields",
            left.extra_fields,
            left.extra_fields,
        )

        self.assertEqual(
            left.extra_fields,
            {"owner": "left", "ghostmerge_last_synced_at": left_timestamp},
        )
        self.assertEqual(right.extra_fields, {"owner": "left"})

    def test_cli_record_preview_excludes_last_synced_metadata(self):
        from rich.console import Console
        from tui import TUI

        left = finding(
            extra_fields={"owner": "left", "ghostmerge_last_synced_at": "2026-07-20T10:00:00Z"},
        )
        right = finding(
            id=2,
            extra_fields={"owner": "right", "ghostmerge_last_synced_at": "2026-07-21T10:00:00Z"},
        )
        # Rendering this table does not require TUI runtime state. Avoid the
        # constructor because it intentionally registers a process-wide TUI
        # singleton that earlier CLI tests may already have initialised.
        terminal = TUI.__new__(TUI)

        with patch.object(terminal, "update_data") as update_data:
            terminal.render_left_and_right_whole_finding_record(
                {"left": left, "right": right, "score": 95.0},
                "extra_fields",
            )

        rendered = StringIO()
        Console(file=rendered, width=500, color_system=None).print(update_data.call_args.args[0])
        preview_text = rendered.getvalue()
        self.assertIn("owner", preview_text)
        self.assertNotIn("ghostmerge_last_synced_at", preview_text)

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

    def test_non_interactive_merge_preserves_equal_blank_optional_strings(self):
        left = finding(id=1, title="Shared title", description="Left detail", finding_guidance="")
        right = finding(id=2, title="Shared title", description="Right detail", finding_guidance="")

        merged_left, merged_right = merge_main({"left": left, "right": right, "score": 95.0})

        self.assertEqual(merged_left.finding_guidance, "")
        self.assertEqual(merged_right.finding_guidance, "")

    def test_non_interactive_merge_fails_closed_when_no_offered_value_exists(self):
        left = finding(id=1, title="Shared title", finding_guidance="")
        right = finding(id=2, title="Shared title", finding_guidance=None)

        with patch("merge.get_tui") as get_tui:
            with redirect_stdout(StringIO()):
                with self.assertRaises(Aborting):
                    merge_main({"left": left, "right": right, "score": 95.0})

        get_tui.assert_not_called()


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

    def test_sensitive_rules_and_scanned_content_are_not_written_to_logs(self):
        sensitive_term = "customer-private-codename"
        sensitive_replacement = "internal-replacement-value"
        sensitive_content = f"Finding contains {sensitive_term} and confidential context"

        with tempfile.TemporaryDirectory() as tmp_dir:
            terms_path = Path(tmp_dir) / "terms.txt"
            terms_path.write_text(
                f"{sensitive_term} => {sensitive_replacement}\n",
                encoding="utf-8",
            )
            with patch("sensitivity.log") as mocked_log:
                terms = load_sensitive_terms("terms.txt", tmp_dir)
                hits = check_for_sensitivities(sensitive_content, terms)

        logged_text = " ".join(str(call) for call in mocked_log.call_args_list)
        self.assertEqual(hits, [(sensitive_term, sensitive_replacement)])
        self.assertNotIn(sensitive_term, logged_text)
        self.assertNotIn(sensitive_replacement, logged_text)
        self.assertNotIn("confidential context", logged_text)

    def test_non_interactive_flag_only_term_fails_without_terminal_prompt(self):
        record = finding(description="Contains a private codename")

        with patch("sensitivity.get_tui") as get_tui:
            with redirect_stdout(StringIO()):
                with self.assertRaises(Aborting):
                    sensitivities_checker_single_field(
                        "description",
                        record,
                        "Left",
                        {"private codename": None},
                        interactive_override=False,
                    )

        get_tui.assert_not_called()

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

    def test_pre_match_processing_applies_replacements_and_defers_flag_only_hits(self):
        record = finding(title="ACME portal", description="Contains a secret value")

        stats = apply_pre_match_sensitivity_replacements(
            [record],
            {"acme": "[CLIENT]", "secret": None},
        )

        self.assertEqual(record.title, "[CLIENT] portal")
        self.assertEqual(record.description, "Contains a secret value")
        self.assertEqual(stats["records_scanned"], 1)
        self.assertGreater(stats["fields_scanned"], 0)
        self.assertEqual(stats["hits_found"], 2)
        self.assertEqual(stats["replacements_applied"], 1)
        self.assertEqual(stats["flag_only_hits_deferred"], 1)

    def test_sensitive_terms_digest_is_stable_without_exposing_term_order(self):
        first = sensitive_terms_digest({"secret": None, "acme": "[CLIENT]"})
        second = sensitive_terms_digest({"acme": "[CLIENT]", "secret": None})

        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)


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

    def test_non_interactive_cli_rejects_invalid_record_with_failure_status(self):
        python_bin = PROJECT_ROOT / ".venv" / "bin" / "python"
        self.skipTest("project virtualenv is not present") if not python_bin.exists() else None

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            left_path = tmp_path / "left.json"
            right_path = tmp_path / "right.json"
            output_left = tmp_path / "left-output.json"
            output_right = tmp_path / "right-output.json"
            config_path = tmp_path / "config.json"
            invalid_record = finding().to_dict()
            invalid_record["id"] = "not-an-integer"

            left_path.write_text(json.dumps([invalid_record]), encoding="utf-8")
            right_path.write_text("[]", encoding="utf-8")
            with (PROJECT_ROOT / "ghostmerge_config.example.json").open("r", encoding="utf-8") as handle:
                config = json.load(handle)
            config.update({
                "interactive_mode": False,
                "sensitivity_check_enabled": False,
                "log_file_enabled": False,
            })
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
                    str(output_left),
                    "--out-right",
                    str(output_right),
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

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output_left.exists())
            self.assertFalse(output_right.exists())

    def test_cli_fails_closed_when_enabled_sensitivity_rules_are_unavailable(self):
        python_bin = PROJECT_ROOT / ".venv" / "bin" / "python"
        self.skipTest("project virtualenv is not present") if not python_bin.exists() else None

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            left_path = tmp_path / "left.json"
            right_path = tmp_path / "right.json"
            output_left = tmp_path / "left-output.json"
            output_right = tmp_path / "right-output.json"
            config_path = tmp_path / "config.json"
            left_path.write_text(json.dumps([finding().to_dict()]), encoding="utf-8")
            right_path.write_text("[]", encoding="utf-8")

            with (PROJECT_ROOT / "ghostmerge_config.example.json").open("r", encoding="utf-8") as handle:
                config = json.load(handle)
            config.update({
                "interactive_mode": False,
                "sensitivity_check_enabled": True,
                "sensitivity_check_terms_file": "missing-sensitive-rules.txt",
                "log_file_enabled": False,
            })
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
                    str(output_left),
                    "--out-right",
                    str(output_right),
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

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("configured rules could not be loaded", result.stdout)
            self.assertFalse(output_left.exists())
            self.assertFalse(output_right.exists())

    def test_cli_entrypoint_applies_shared_pre_match_sensitivity_replacements(self):
        python_bin = PROJECT_ROOT / ".venv" / "bin" / "python"
        self.skipTest("project virtualenv is not present") if not python_bin.exists() else None

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            left_path = tmp_path / "left.json"
            right_path = tmp_path / "right.json"
            output_left = tmp_path / "left-output.json"
            output_right = tmp_path / "right-output.json"
            terms_path = tmp_path / "terms.txt"
            config_path = tmp_path / "config.json"
            input_record = finding(title="ACME portal").to_dict()

            left_path.write_text(json.dumps([input_record]), encoding="utf-8")
            right_path.write_text(json.dumps([input_record]), encoding="utf-8")
            terms_path.write_text("acme => [CLIENT]\nsecret\n", encoding="utf-8")
            with (PROJECT_ROOT / "ghostmerge_config.example.json").open("r", encoding="utf-8") as handle:
                config = json.load(handle)
            config.update(
                {
                    "interactive_mode": False,
                    "sensitivity_check_enabled": True,
                    "sensitivity_check_before_matching": True,
                    "sensitivity_check_terms_file": str(terms_path),
                    "log_file_enabled": False,
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
                    str(output_left),
                    "--out-right",
                    str(output_right),
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
            merged_left = json.loads(output_left.read_text(encoding="utf-8"))
            merged_right = json.loads(output_right.read_text(encoding="utf-8"))

        self.assertEqual(merged_left[0]["title"], "[CLIENT] portal")
        self.assertEqual(merged_right[0]["title"], "[CLIENT] portal")

    def test_unmatched_records_are_copied_between_outputs(self):
        left_only = finding(title="Left only")
        right_only = finding(title="Right only")
        merged_left = []
        merged_right = []

        appended = append_unmatched_records(merged_left, merged_right, [left_only], [right_only])
        merged_left[0].description = "left output edited"
        merged_right[1].description = "right output edited"

        self.assertEqual(appended, 2)
        self.assertIsNot(merged_left[0], merged_right[0])
        self.assertIsNot(merged_left[1], merged_right[1])
        self.assertNotEqual(merged_right[0].description, "left output edited")
        self.assertNotEqual(merged_left[1].description, "right output edited")

    def test_rejected_match_returns_records_to_unmatched_pools(self):
        left_record = finding(title="Left candidate")
        right_record = finding(id=2, title="Right candidate")
        unmatched_left = []
        unmatched_right = []

        reject_matched_record(
            {"left": left_record, "right": right_record, "score": 92.5},
            unmatched_left,
            unmatched_right,
        )

        self.assertEqual(unmatched_left, [left_record])
        self.assertEqual(unmatched_right, [right_record])

    def test_manual_match_builds_a_normal_review_candidate_for_both_record_types(self):
        original_left = finding(title="  Manual left  ")
        finding_match = build_manual_match(
            original_left,
            finding(id=2, title="Manual right"),
            set(),
        )
        observation_match = build_manual_match(
            Observation(id=1, title="Manual observation left", description="Left", tags=[]),
            Observation(id=2, title="Manual observation right", description="Right", tags=[]),
            set(),
        )

        self.assertEqual(finding_match["origin"], "manual")
        self.assertEqual(original_left.title, "  Manual left  ")
        self.assertEqual(finding_match["left"].title, "Manual left")
        self.assertIn("auto_value", finding_match)
        self.assertIn("auto_side", finding_match)
        self.assertEqual(observation_match["origin"], "manual")
        self.assertIsInstance(observation_match["score"], float)

    def test_manual_match_rejects_mixed_types_and_previously_rejected_pair(self):
        left_record = finding(title="Rejected left")
        right_record = finding(id=2, title="Rejected right")
        rejected_key = reject_matched_record(
            {"left": left_record, "right": right_record, "score": 10.0},
            [],
            [],
        )

        with self.assertRaisesRegex(ValueError, "previously rejected"):
            build_manual_match(left_record, right_record, {rejected_key})
        with self.assertRaisesRegex(ValueError, "same template type"):
            build_manual_match(
                left_record,
                Observation(id=2, title="Observation", description="Detail", tags=[]),
                set(),
            )

    def test_cli_manual_matching_selects_one_based_candidates_without_mutating_others(self):
        configure_for_tests(interactive_mode=True)
        import ghostmerge

        left_records = [finding(id=1, title="Left one"), finding(id=2, title="Left two")]
        right_records = [finding(id=3, title="Right one"), finding(id=4, title="Right two")]
        with (
            patch.object(ghostmerge.tui, "render_user_choice", side_effect=["c", "2", "1", "k"]),
            patch.object(ghostmerge.tui, "render_manual_match_candidates") as render_candidates,
            patch.object(ghostmerge.tui, "render_left_and_right_whole_finding_record") as render_preview,
        ):
            matches, remaining_left, remaining_right = ghostmerge._maybe_create_cli_manual_match(
                [], left_records, right_records, []
            )

        self.assertEqual(matches[0]["left"].title, "Left two")
        self.assertEqual(matches[0]["right"].title, "Right one")
        self.assertEqual(matches[0]["origin"], "manual")
        self.assertEqual([item.title for item in remaining_left], ["Left one"])
        self.assertEqual([item.title for item in remaining_right], ["Right two"])
        render_candidates.assert_called_once()
        render_preview.assert_called_once()

    def test_cli_manual_matching_is_skipped_in_non_interactive_mode(self):
        configure_for_tests(interactive_mode=False)
        import ghostmerge

        left_records = [finding(title="Left")]
        right_records = [finding(id=2, title="Right")]
        matches, remaining_left, remaining_right = ghostmerge._maybe_create_cli_manual_match(
            [], left_records, right_records, []
        )

        self.assertEqual(matches, [])
        self.assertIs(remaining_left, left_records)
        self.assertIs(remaining_right, right_records)

    def test_orphan_reprocessing_creates_new_matches(self):
        left_record = finding(title="SQL injection")
        right_record = finding(id=2, title="SQL injection in login")

        matches, unmatched_left, unmatched_right = reprocess_orphan_matches(
            [left_record],
            [right_record],
            [70],
            set(),
        )

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["left"], left_record)
        self.assertEqual(matches[0]["right"], right_record)
        self.assertEqual(unmatched_left, [])
        self.assertEqual(unmatched_right, [])

    def test_orphan_reprocessing_does_not_recreate_rejected_pairs(self):
        left_record = finding(title="SQL injection")
        right_record = finding(id=2, title="SQL injection")
        rejected_key = reject_matched_record(
            {"left": left_record, "right": right_record, "score": 100.0},
            [],
            [],
        )

        matches, unmatched_left, unmatched_right = reprocess_orphan_matches(
            [left_record],
            [right_record],
            [70],
            {rejected_key},
        )

        self.assertEqual(matches, [])
        self.assertEqual(unmatched_left, [left_record])
        self.assertEqual(unmatched_right, [right_record])

    def test_orphan_reprocessing_tries_alternatives_when_best_pair_was_rejected(self):
        left_record = finding(title="SQL injection", description="Login form issue")
        rejected_right = finding(id=2, title="SQL injection", description="Different issue")
        alternative_right = finding(id=3, title="SQL injection in login", description="Login form issue")
        rejected_key = reject_matched_record(
            {"left": left_record, "right": rejected_right, "score": 100.0},
            [],
            [],
        )

        matches, unmatched_left, unmatched_right = reprocess_orphan_matches(
            [left_record],
            [rejected_right, alternative_right],
            [70],
            {rejected_key},
        )

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["right"], alternative_right)
        self.assertEqual(unmatched_left, [])
        self.assertEqual(unmatched_right, [rejected_right])

    def test_cli_and_web_service_produce_equivalent_shared_finding_outputs(self):
        """Keep the common non-interactive Finding workflow equivalent across both interfaces."""
        python_bin = PROJECT_ROOT / ".venv" / "bin" / "python"
        self.skipTest("project virtualenv is not present") if not python_bin.exists() else None

        common_populated_fields = {
            "host_detection_techniques": "Inspect browser process telemetry.",
            "network_detection_techniques": "Inspect unexpected script responses.",
            "finding_guidance": "",
        }
        left_record = finding(
            id=1,
            title="Cross-site scripting",
            description="Left detail",
            **common_populated_fields,
        ).to_dict()
        right_record = finding(
            id=2,
            title="Cross site scripting",
            description="Right detail",
            **common_populated_fields,
        ).to_dict()

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

        # Import locally so the CLI-focused regression module does not make the
        # Flask service a prerequisite for unrelated model and merge tests.
        from web_service import (
            apply_conflict_decision,
            create_merge_job,
            finalise_job,
            get_next_conflict,
        )

        web_job = create_merge_job([left_record], [right_record], job_id="paritybaseline123")
        while (conflict := get_next_conflict(web_job)) is not None:
            # Non-interactive CLI mode accepts the offered value for this
            # controlled fixture, so apply the same decision to the Web job.
            apply_conflict_decision(
                web_job,
                {"field_name": conflict.field_name, "action": "offered"},
            )
        web_result = finalise_job(web_job)

        self.assertEqual(len(merged_left), 1)
        self.assertEqual(len(merged_right), 1)
        self.assertEqual(merged_left[0]["id"], "1")
        self.assertEqual(merged_right[0]["id"], "1")
        self.assertEqual(merged_left[0]["description"], merged_right[0]["description"])
        self.assertEqual(web_result.left_records, merged_left)
        self.assertEqual(web_result.right_records, merged_right)

    def test_cli_and_web_remain_equivalent_through_both_sensitivity_passes(self):
        """Exercise matching, unmatched copying, both sensitivity passes, and final serialisation."""
        python_bin = PROJECT_ROOT / ".venv" / "bin" / "python"
        self.skipTest("project virtualenv is not present") if not python_bin.exists() else None

        left_records = [
            finding(id=1, title="ACME-CORP portal", description="Short detail").to_dict(),
            finding(id=2, title="Left-only ACME-CORP record", description="Left-only detail").to_dict(),
        ]
        right_records = [
            finding(
                id=20,
                title="ACME-CORP portal",
                description="A substantially more complete right-side detail.",
            ).to_dict(),
            finding(id=21, title="Right-only ACME-CORP record", description="Right-only detail").to_dict(),
        ]
        terms = {
            "acme-corp": "confidential-client",
            "confidential-client": "[CLIENT]",
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            left_path = tmp_path / "left.json"
            right_path = tmp_path / "right.json"
            out_left = tmp_path / "left-out.json"
            out_right = tmp_path / "right-out.json"
            terms_path = tmp_path / "sensitive-terms.txt"
            config_path = tmp_path / "config.json"
            left_path.write_text(json.dumps(left_records), encoding="utf-8")
            right_path.write_text(json.dumps(right_records), encoding="utf-8")
            terms_path.write_text(
                "acme-corp => confidential-client\nconfidential-client => [CLIENT]\n",
                encoding="utf-8",
            )

            with (PROJECT_ROOT / "ghostmerge_config.example.json").open("r", encoding="utf-8") as handle:
                config = json.load(handle)
            config.update({
                "interactive_mode": False,
                "sensitivity_check_enabled": True,
                "sensitivity_check_before_matching": True,
                "sensitivity_check_terms_file": str(terms_path),
                "orphan_reprocessing_enabled": False,
                "fuzzy_match_threshold": [70],
                "log_file_enabled": False,
            })
            config_path.write_text(json.dumps(config), encoding="utf-8")

            cli = subprocess.run(
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

            self.assertEqual(cli.returncode, 0, cli.stderr)
            cli_left = json.loads(out_left.read_text(encoding="utf-8"))
            cli_right = json.loads(out_right.read_text(encoding="utf-8"))

        configure_for_tests(
            sensitivity_check_enabled=True,
            sensitivity_check_before_matching=True,
            orphan_reprocessing_enabled=False,
            fuzzy_match_threshold=[70],
        )
        from web_service import (
            acknowledge_sensitivity_review,
            approve_output_preview,
            apply_conflict_decision,
            apply_sensitivity_decision,
            create_merge_job,
            get_next_conflict,
            get_next_sensitivity_item,
            prepare_output_preview,
            save_outputs,
        )

        web_job = create_merge_job(
            left_records,
            right_records,
            job_id="sensitiveparity123",
            sensitivity_snapshot={
                "version": 1,
                "enabled": True,
                "pre_match_enabled": True,
                "terms": terms,
                "terms_digest": sensitive_terms_digest(terms),
                "terms_source": "sensitive-terms.txt",
                "configuration_error": None,
            },
        )
        while (conflict := get_next_conflict(web_job)) is not None:
            apply_conflict_decision(
                web_job,
                {"field_name": conflict.field_name, "action": "offered"},
            )
        while get_next_sensitivity_item(web_job, terms) is not None:
            apply_sensitivity_decision(
                web_job,
                {"action": "offered", "decision_token": web_job.sensitivity_decision_token},
                terms=terms,
            )
        acknowledge_sensitivity_review(web_job)
        prepare_output_preview(web_job)
        web_result = approve_output_preview(web_job, web_job.output_preview_token)

        with tempfile.TemporaryDirectory() as web_tmp_dir:
            web_jobs_dir = Path(web_tmp_dir)
            save_outputs(web_job, web_jobs_dir, web_result)
            durable_web_left = json.loads(
                (web_jobs_dir / web_job.job_id / "left.json").read_text(encoding="utf-8")
            )
            durable_web_right = json.loads(
                (web_jobs_dir / web_job.job_id / "right.json").read_text(encoding="utf-8")
            )

        self.assertEqual(web_result.left_records, cli_left)
        self.assertEqual(web_result.right_records, cli_right)
        self.assertEqual(durable_web_left, cli_left)
        self.assertEqual(durable_web_right, cli_right)
        serialised_output = json.dumps({"left": cli_left, "right": cli_right}).lower()
        self.assertNotIn("acme-corp", serialised_output)
        self.assertNotIn("confidential-client", serialised_output)
        self.assertIn("[client]", serialised_output)

    def test_cli_flag_only_sensitivity_failure_redacts_content_and_writes_no_output(self):
        python_bin = PROJECT_ROOT / ".venv" / "bin" / "python"
        self.skipTest("project virtualenv is not present") if not python_bin.exists() else None
        sensitive_value = "ultra-secret-customer-name"

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            left_path = tmp_path / "left.json"
            right_path = tmp_path / "right.json"
            out_left = tmp_path / "left-out.json"
            out_right = tmp_path / "right-out.json"
            terms_path = tmp_path / "sensitive-terms.txt"
            config_path = tmp_path / "config.json"
            left_path.write_text(
                json.dumps([finding(description=f"Contains {sensitive_value}").to_dict()]),
                encoding="utf-8",
            )
            right_path.write_text("[]", encoding="utf-8")
            terms_path.write_text(f"{sensitive_value}\n", encoding="utf-8")

            with (PROJECT_ROOT / "ghostmerge_config.example.json").open("r", encoding="utf-8") as handle:
                config = json.load(handle)
            config.update({
                "interactive_mode": False,
                "sensitivity_check_enabled": True,
                "sensitivity_check_before_matching": False,
                "sensitivity_check_terms_file": str(terms_path),
                "log_file_enabled": False,
            })
            config_path.write_text(json.dumps(config), encoding="utf-8")

            cli = subprocess.run(
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

            diagnostics = f"{cli.stdout}\n{cli.stderr}".lower()
            self.assertNotEqual(cli.returncode, 0)
            self.assertNotIn(sensitive_value, diagnostics)
            self.assertIn("cannot resolve flag-only term", diagnostics)
            self.assertFalse(out_left.exists())
            self.assertFalse(out_right.exists())


if __name__ == "__main__":
    unittest.main()

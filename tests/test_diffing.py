import unittest

from diffing import build_semantic_diff


def segment_text(diff, side, change=None):
    """Flatten one side's visible segment text for focused assertions."""
    values = []
    for block in diff.blocks:
        lines = block.left_lines if side == "left" else block.right_lines
        for line in lines:
            for segment in line.segments:
                if change is None or segment.change == change:
                    values.append(segment.text)
    return "".join(values)


class SemanticDiffTests(unittest.TestCase):
    def test_single_character_replacement_marks_only_changed_characters(self):
        diff = build_semantic_diff("The cat sat", "The cot sat")

        self.assertEqual(segment_text(diff, "left", "removed"), "a")
        self.assertEqual(segment_text(diff, "right", "added"), "o")
        self.assertEqual(diff.removed_characters, 1)
        self.assertEqual(diff.added_characters, 1)
        self.assertFalse(diff.approximate)

    def test_empty_and_populated_values_produce_one_sided_content(self):
        added = build_semantic_diff("", "populated", context_lines=None)
        removed = build_semantic_diff("populated", "", context_lines=None)

        self.assertEqual(segment_text(added, "right", "added"), "populated")
        self.assertEqual(added.added_characters, len("populated"))
        self.assertEqual(segment_text(removed, "left", "removed"), "populated")
        self.assertEqual(removed.removed_characters, len("populated"))

    def test_inserted_line_does_not_mark_following_lines_as_changed(self):
        diff = build_semantic_diff(
            "alpha\nbravo\ncharlie\ndelta",
            "alpha\ninserted\nbravo\ncharlie\ndelta",
            context_lines=None,
        )

        self.assertEqual([block.kind for block in diff.blocks], ["equal", "insert", "equal"])
        self.assertEqual(segment_text(diff, "right", "added"), "inserted↵")
        self.assertNotIn("bravo", segment_text(diff, "right", "added"))
        self.assertNotIn("charlie", segment_text(diff, "right", "added"))
        self.assertEqual(diff.added_line_breaks, 1)

    def test_split_line_reports_replaced_space_and_local_newline(self):
        diff = build_semantic_diff("alpha beta gamma", "alpha beta\ngamma", context_lines=None)

        self.assertEqual([block.kind for block in diff.blocks], ["replace"])
        self.assertEqual(segment_text(diff, "right", "added"), "↵")
        self.assertEqual(segment_text(diff, "left", "removed"), " ")
        self.assertEqual(diff.removed_characters, 1)
        self.assertEqual(diff.added_line_breaks, 1)

    def test_joined_lines_reports_local_newline_and_replacement_space(self):
        diff = build_semantic_diff("alpha beta\ngamma", "alpha beta gamma", context_lines=None)

        self.assertEqual(segment_text(diff, "left", "removed"), "↵")
        self.assertEqual(segment_text(diff, "right", "added"), " ")
        self.assertEqual(diff.added_characters, 1)
        self.assertEqual(diff.removed_line_breaks, 1)

    def test_newline_only_split_and_join_do_not_create_character_changes(self):
        split = build_semantic_diff("alpha beta gamma", "alpha beta \ngamma", context_lines=None)
        joined = build_semantic_diff("alpha beta \ngamma", "alpha beta gamma", context_lines=None)

        self.assertEqual(segment_text(split, "right", "added"), "↵")
        self.assertEqual(segment_text(split, "left", "removed"), "")
        self.assertEqual(split.added_characters, 0)
        self.assertEqual(split.added_line_breaks, 1)
        self.assertEqual(segment_text(joined, "left", "removed"), "↵")
        self.assertEqual(segment_text(joined, "right", "added"), "")
        self.assertEqual(joined.removed_characters, 0)
        self.assertEqual(joined.removed_line_breaks, 1)

    def test_changed_tabs_are_visible_but_not_counted_as_characters(self):
        diff = build_semantic_diff("alpha\tbeta", "alpha beta", context_lines=None)

        self.assertEqual(segment_text(diff, "left", "removed"), "→")
        self.assertEqual(segment_text(diff, "right", "added"), " ")
        self.assertEqual(diff.removed_characters, 0)
        self.assertEqual(diff.added_characters, 1)

    def test_repeated_content_uses_deterministic_alignment(self):
        left = "header\nrepeat\nrepeat\nfooter"
        right = "header\nrepeat\nchanged\nrepeat\nfooter"

        first = build_semantic_diff(left, right, context_lines=None)
        second = build_semantic_diff(left, right, context_lines=None)

        self.assertEqual(first, second)
        self.assertEqual(segment_text(first, "right", "added"), "changed↵")
        self.assertNotIn("footer", segment_text(first, "right", "added"))

    def test_unicode_content_is_preserved_around_a_change(self):
        diff = build_semantic_diff("café 🔒", "café 🔓", context_lines=None)

        self.assertEqual(segment_text(diff, "left", "removed"), "🔒")
        self.assertEqual(segment_text(diff, "right", "added"), "🔓")
        self.assertIn("café ", segment_text(diff, "left", "equal"))

    def test_long_equal_context_is_collapsed_with_source_line_numbers(self):
        left_lines = [f"line {number}" for number in range(1, 11)]
        right_lines = list(left_lines)
        right_lines[5] = "changed line"

        diff = build_semantic_diff("\n".join(left_lines), "\n".join(right_lines), context_lines=2)

        collapsed = [block for block in diff.blocks if block.kind == "context"]
        visible_left_numbers = [
            line.source_line
            for block in diff.blocks
            for line in block.left_lines
            if line.source_line is not None
        ]
        self.assertEqual([block.collapsed_line_count for block in collapsed], [3, 2])
        self.assertIn(6, visible_left_numbers)
        self.assertNotIn(1, visible_left_numbers)
        self.assertNotIn(10, visible_left_numbers)

    def test_large_replace_block_uses_bounded_prefix_suffix_fallback(self):
        left = "prefix-" + ("a" * 40) + "-suffix"
        right = "prefix-" + ("b" * 40) + "-suffix"

        diff = build_semantic_diff(
            left,
            right,
            context_lines=None,
            detailed_character_limit=20,
            detailed_character_product_limit=100,
        )

        self.assertTrue(diff.approximate)
        self.assertEqual(segment_text(diff, "left", "removed"), "a" * 40)
        self.assertEqual(segment_text(diff, "right", "added"), "b" * 40)
        self.assertIn("prefix-", segment_text(diff, "left", "equal"))
        self.assertIn("-suffix", segment_text(diff, "right", "equal"))

    def test_whole_field_limit_uses_fallback_without_losing_common_edges(self):
        left = "prefix-" + ("left" * 10) + "-suffix"
        right = "prefix-" + ("right" * 10) + "-suffix"

        diff = build_semantic_diff(left, right, total_character_limit=20)

        self.assertTrue(diff.approximate)
        self.assertIn("prefix-", segment_text(diff, "left", "equal"))
        self.assertIn("-suffix", segment_text(diff, "right", "equal"))
        self.assertIn("left", segment_text(diff, "left", "removed"))
        self.assertIn("right", segment_text(diff, "right", "added"))

    def test_line_pair_limit_bounds_repetitive_multiline_alignment(self):
        left = "repeat\n" * 30
        right = ("repeat\n" * 15) + "changed\n" + ("repeat\n" * 14)

        diff = build_semantic_diff(left, right, line_product_limit=100)

        self.assertTrue(diff.approximate)
        self.assertIn("changed", segment_text(diff, "right", "added"))

    def test_inputs_are_not_modified(self):
        left = "one\ntwo"
        right = "one\nthree"

        build_semantic_diff(left, right)

        self.assertEqual(left, "one\ntwo")
        self.assertEqual(right, "one\nthree")

    def test_display_splitting_preserves_semantics_and_prefers_readable_boundaries(self):
        from diffing import split_field_diff_for_display

        left = "<p>Alpha words remain here.</p><p>Old closing sentence for review.</p>"
        right = "<p>Alpha words remain here.</p><p>New closing sentence for review.</p>"
        semantic = build_semantic_diff(left, right, context_lines=None)

        displayed = split_field_diff_for_display(semantic, maximum_characters=32)

        self.assertEqual(segment_text(displayed, "left"), left)
        self.assertEqual(segment_text(displayed, "right"), right)
        self.assertEqual(displayed.added_characters, semantic.added_characters)
        self.assertEqual(displayed.removed_characters, semantic.removed_characters)
        self.assertEqual(displayed.added_line_breaks, semantic.added_line_breaks)
        self.assertEqual(displayed.removed_line_breaks, semantic.removed_line_breaks)
        visible_lines = [
            line
            for block in displayed.blocks
            for line in (*block.left_lines, *block.right_lines)
        ]
        self.assertTrue(any(line.source_line is None for line in visible_lines))
        self.assertTrue(
            all(
                len("".join(segment.text for segment in line.segments)) <= 32
                for line in visible_lines
            )
        )
        self.assertTrue(
            any(
                "</p>" in "".join(segment.text for segment in line.segments)
                for line in visible_lines
            )
        )


class CliDiffRenderingTests(unittest.TestCase):
    def test_cli_rendering_wraps_after_alignment_and_realigns_following_blocks(self):
        from rich.console import Console
        from tui import build_cli_diff_text

        diff = build_semantic_diff(
            "alpha\nbravo\ncharlie",
            "alpha\ninserted words here\nbravo\ncharlie",
            context_lines=None,
        )

        left, right = build_cli_diff_text(diff, Console(width=80), content_width=10)

        self.assertIn("bravo", left.plain)
        self.assertIn("bravo", right.plain)
        self.assertNotIn("inserted", left.plain)
        self.assertIn("inserted", right.plain)
        self.assertEqual(left.plain.count("bravo"), 1)
        self.assertEqual(right.plain.count("bravo"), 1)

    def test_cli_rendering_treats_rich_markup_as_literal_text(self):
        from rich.console import Console
        from tui import build_cli_diff_text

        diff = build_semantic_diff("[bold red]safe[/]", "[bold blue]safe[/]", context_lines=None)

        left, right = build_cli_diff_text(diff, Console(width=80), content_width=40)

        self.assertIn("[bold red]safe[/]", left.plain)
        self.assertIn("[bold blue]safe[/]", right.plain)

    def test_cli_rendering_hard_wraps_long_unbroken_values_without_losing_content(self):
        from rich.console import Console
        from tui import build_cli_diff_text

        left_value = "A" * 40
        right_value = "A" * 20 + "B" + "A" * 19
        diff = build_semantic_diff(left_value, right_value, context_lines=None)

        left, right = build_cli_diff_text(diff, Console(width=80), content_width=8)

        self.assertEqual(left.plain.count("A"), 40)
        self.assertEqual(right.plain.count("A"), 39)
        self.assertEqual(right.plain.count("B"), 1)


if __name__ == "__main__":
    unittest.main()

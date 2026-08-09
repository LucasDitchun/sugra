#!/usr/bin/env python3
"""Unit tests for the release-train policy."""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("release_train.py")
SPEC = importlib.util.spec_from_file_location("release_train", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release_train.py")
release_train = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_train
SPEC.loader.exec_module(release_train)


class VersionPolicyTests(unittest.TestCase):
    def test_pre_one_features_are_batched_into_one_patch(self) -> None:
        commits = [
            release_train.Commit("a" * 40, "feat: first feature"),
            release_train.Commit("b" * 40, "feat(cli): second feature"),
            release_train.Commit("c" * 40, "fix: correction"),
        ]
        current = release_train.Version.parse("0.1.0")

        bump = release_train.select_bump(current, commits, "auto")

        self.assertEqual(bump, "patch")
        self.assertEqual(str(current.bump(bump)), "0.1.1")

    def test_pre_one_breaking_change_advances_minor(self) -> None:
        commits = [release_train.Commit("a" * 40, "feat(api)!: replace report schema")]
        current = release_train.Version.parse("0.1.9")

        bump = release_train.select_bump(current, commits, "auto")

        self.assertEqual(bump, "minor")
        self.assertEqual(str(current.bump(bump)), "0.2.0")

    def test_stable_semver_uses_feature_fix_and_breaking_levels(self) -> None:
        current = release_train.Version.parse("1.4.2")
        cases = (
            ([release_train.Commit("a", "fix: correct output")], "1.4.3"),
            ([release_train.Commit("a", "feat: add preset")], "1.5.0"),
            ([release_train.Commit("a", "refactor!: change API")], "2.0.0"),
        )
        for commits, expected in cases:
            with self.subTest(expected=expected):
                bump = release_train.select_bump(current, commits, "auto")
                self.assertEqual(str(current.bump(bump)), expected)

    def test_breaking_change_footer_is_detected(self) -> None:
        commit = release_train.Commit(
            "a",
            "feat: change output",
            "Details\n\nBREAKING CHANGE: report format changed",
        )
        self.assertTrue(commit.breaking)

    def test_explicit_bump_overrides_automatic_policy(self) -> None:
        current = release_train.Version.parse("0.1.0")
        commits = [release_train.Commit("a", "feat: compatible feature")]
        self.assertEqual(release_train.select_bump(current, commits, "minor"), "minor")

    def test_empty_release_range_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "no releaseable commits"):
            release_train.select_bump(release_train.Version(0, 1, 0), [], "auto")


class FileUpdateTests(unittest.TestCase):
    def test_only_workspace_package_version_is_changed(self) -> None:
        cargo = """[workspace.package]
version = "0.1.0"

[workspace.dependencies]
example = "9.8.7"
"""
        updated = release_train.update_workspace_version(
            cargo, release_train.Version.parse("0.1.1")
        )
        self.assertIn('version = "0.1.1"', updated)
        self.assertIn('example = "9.8.7"', updated)

    def test_changelog_replaces_same_release_without_losing_history(self) -> None:
        existing = """# Changelog

Intro.

## [0.1.1] - 2026-08-01

### Fixes

- old text (`aaaaaaa`)

## [0.1.0] - 2026-07-01

### Features

- initial release (`bbbbbbb`)
"""
        commits = [release_train.Commit("c" * 40, "feat: batched feature")]

        updated = release_train.update_changelog(
            existing, release_train.Version(0, 1, 1), commits, "2026-08-09"
        )

        self.assertEqual(updated.count("## [0.1.1]"), 1)
        self.assertIn("- batched feature (`ccccccc`)", updated)
        self.assertIn("## [0.1.0] - 2026-07-01", updated)

    def test_changelog_inserts_new_release_before_history(self) -> None:
        existing = "# Changelog\n\n## [0.1.0] - 2026-07-01\n\nInitial.\n"
        commits = [release_train.Commit("d" * 40, "fix: safer output")]

        updated = release_train.update_changelog(
            existing, release_train.Version(0, 1, 1), commits, "2026-08-09"
        )

        self.assertLess(updated.index("## [0.1.1]"), updated.index("## [0.1.0]"))
        self.assertIn("### Fixes", updated)

    def test_prepare_script_is_loadable_outside_repository_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            self.assertTrue(Path(temporary_directory).is_dir())
            self.assertEqual(str(release_train.Version.parse("0.7.4")), "0.7.4")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Prepare and validate Sugra release-train versions and changelog entries."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
CONVENTIONAL_PATTERN = re.compile(
    r"^(?P<kind>[a-zA-Z][a-zA-Z0-9-]*)(?:\([^)]+\))?(?P<breaking>!)?: (?P<summary>.+)$"
)
WORKSPACE_PACKAGE_PATTERN = re.compile(
    r'(?ms)(^\[workspace\.package\]\s*.*?^version\s*=\s*")([^"]+)(")'
)
RELEASE_COMMIT_PATTERN = re.compile(r"^chore(?:\(release\))?: prepare v\d+\.\d+\.\d+$")


@dataclass(frozen=True, order=True)
class Version:
    """A strict three-component semantic version."""

    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, value: str) -> "Version":
        match = VERSION_PATTERN.fullmatch(value.strip())
        if match is None:
            raise ValueError(f"invalid semantic version: {value!r}")
        return cls(*(int(part) for part in match.groups()))

    def bump(self, kind: str) -> "Version":
        if kind == "patch":
            return Version(self.major, self.minor, self.patch + 1)
        if kind == "minor":
            return Version(self.major, self.minor + 1, 0)
        if kind == "major":
            return Version(self.major + 1, 0, 0)
        raise ValueError(f"unsupported version bump: {kind}")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class Commit:
    """The release-relevant fields of a Git commit."""

    sha: str
    subject: str
    body: str = ""

    @property
    def conventional(self) -> re.Match[str] | None:
        return CONVENTIONAL_PATTERN.fullmatch(self.subject)

    @property
    def breaking(self) -> bool:
        header = self.conventional
        return bool(header and header.group("breaking")) or bool(
            re.search(r"(?m)^BREAKING(?: |-)?CHANGE:\s*\S", self.body)
        )

    @property
    def kind(self) -> str:
        header = self.conventional
        return header.group("kind").lower() if header else "other"

    @property
    def summary(self) -> str:
        header = self.conventional
        return header.group("summary").strip() if header else self.subject.strip()


def select_bump(current: Version, commits: Sequence[Commit], requested: str) -> str:
    """Apply Sugra's ZeroVer policy or honor an explicit release decision."""

    if requested in {"patch", "minor", "major"}:
        return requested
    if requested != "auto":
        raise ValueError(f"unsupported release policy: {requested}")
    if not commits:
        raise ValueError("develop has no releaseable commits beyond main")

    if any(commit.breaking for commit in commits):
        return "minor" if current.major == 0 else "major"
    if current.major == 0:
        return "patch"
    if any(commit.kind == "feat" for commit in commits):
        return "minor"
    return "patch"


def releaseable_commits(commits: Iterable[Commit]) -> list[Commit]:
    """Remove merge noise and release preparation commits from release notes."""

    return [
        commit
        for commit in commits
        if not commit.subject.startswith("Merge ")
        and not RELEASE_COMMIT_PATTERN.fullmatch(commit.subject)
    ]


def read_workspace_version(contents: str) -> Version:
    match = WORKSPACE_PACKAGE_PATTERN.search(contents)
    if match is None:
        raise ValueError("Cargo.toml does not define workspace.package.version")
    return Version.parse(match.group(2))


def update_workspace_version(contents: str, version: Version) -> str:
    if WORKSPACE_PACKAGE_PATTERN.search(contents) is None:
        raise ValueError("Cargo.toml does not define workspace.package.version")
    return WORKSPACE_PACKAGE_PATTERN.sub(
        lambda match: f"{match.group(1)}{version}{match.group(3)}", contents, count=1
    )


def render_release_section(
    version: Version, commits: Sequence[Commit], date: str
) -> str:
    groups: dict[str, list[Commit]] = {
        "Breaking changes": [],
        "Features": [],
        "Fixes": [],
        "Performance": [],
        "Maintenance": [],
    }
    for commit in commits:
        if commit.breaking:
            group = "Breaking changes"
        elif commit.kind == "feat":
            group = "Features"
        elif commit.kind == "fix":
            group = "Fixes"
        elif commit.kind == "perf":
            group = "Performance"
        else:
            group = "Maintenance"
        groups[group].append(commit)

    lines = [f"## [{version}] - {date}", ""]
    for title, entries in groups.items():
        if not entries:
            continue
        lines.extend([f"### {title}", ""])
        lines.extend(f"- {entry.summary} (`{entry.sha[:7]}`)" for entry in entries)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def update_changelog(
    contents: str, version: Version, commits: Sequence[Commit], date: str
) -> str:
    header = (
        "# Changelog\n\n"
        "All notable changes to Sugra are documented in this file. Releases follow the "
        "project's ZeroVer policy until 1.0.0.\n\n"
    )
    if not contents.strip():
        contents = header
    elif not contents.startswith("# Changelog"):
        raise ValueError("CHANGELOG.md must begin with '# Changelog'")

    section = render_release_section(version, commits, date)
    section_pattern = re.compile(
        rf"(?ms)^## \[{re.escape(str(version))}\] - .*?(?=^## \[|\Z)"
    )
    if section_pattern.search(contents):
        return (
            section_pattern.sub(section.rstrip() + "\n\n", contents, count=1).rstrip()
            + "\n"
        )

    first_release = re.search(r"(?m)^## \[", contents)
    if first_release is None:
        return contents.rstrip() + "\n\n" + section
    return (
        contents[: first_release.start()]
        + section
        + "\n"
        + contents[first_release.start() :]
    )


def run_git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, text=True, stdout=subprocess.PIPE
    ).stdout


def commits_between(base_ref: str, head_ref: str) -> list[Commit]:
    raw = run_git(
        "log",
        "--no-merges",
        "-z",
        "--format=%H%x1f%s%x1f%b",
        f"{base_ref}..{head_ref}",
    )
    commits = []
    for record in raw.split("\0"):
        if not record:
            continue
        sha, subject, body = record.split("\x1f", maxsplit=2)
        commits.append(Commit(sha=sha, subject=subject, body=body))
    return releaseable_commits(commits)


def contents_at(ref: str, path: str) -> str:
    return run_git("show", f"{ref}:{path}")


def build_plan(base_ref: str, head_ref: str, requested: str) -> dict[str, object]:
    current = read_workspace_version(contents_at(base_ref, "Cargo.toml"))
    commits = commits_between(base_ref, head_ref)
    bump = select_bump(current, commits, requested)
    version = current.bump(bump)
    return {
        "previous_version": str(current),
        "version": str(version),
        "tag": f"v{version}",
        "bump": bump,
        "commit_count": len(commits),
        "commits": commits,
    }


def write_github_output(path: str | None, plan: dict[str, object]) -> None:
    if path is None:
        return
    with Path(path).open("a", encoding="utf-8") as output:
        for key in ("previous_version", "version", "tag", "bump", "commit_count"):
            output.write(f"{key}={plan[key]}\n")


def serializable_plan(plan: dict[str, object]) -> dict[str, object]:
    result = dict(plan)
    result["commits"] = [commit.__dict__ for commit in plan["commits"]]
    return result


def prepare(args: argparse.Namespace) -> None:
    plan = build_plan(args.base_ref, args.head_ref, args.bump)
    version = Version.parse(str(plan["version"]))
    cargo_path = Path(args.cargo_toml)
    cargo_path.write_text(
        update_workspace_version(cargo_path.read_text(encoding="utf-8"), version),
        encoding="utf-8",
    )

    changelog_path = Path(args.changelog)
    current_changelog = (
        changelog_path.read_text(encoding="utf-8") if changelog_path.exists() else ""
    )
    release_date = args.date or dt.date.today().isoformat()
    changelog_path.write_text(
        update_changelog(current_changelog, version, plan["commits"], release_date),
        encoding="utf-8",
    )
    write_github_output(args.github_output, plan)
    print(json.dumps(serializable_plan(plan), indent=2))


def verify(args: argparse.Namespace) -> None:
    base_version = read_workspace_version(contents_at(args.base_ref, "Cargo.toml"))
    head_version = read_workspace_version(
        Path(args.cargo_toml).read_text(encoding="utf-8")
    )
    if head_version <= base_version:
        raise ValueError(
            f"release version {head_version} must be newer than main version {base_version}"
        )
    changelog = Path(args.changelog).read_text(encoding="utf-8")
    release_heading = (
        rf"(?m)^## \[{re.escape(str(head_version))}\] - \d{{4}}-\d{{2}}-\d{{2}}$"
    )
    if not re.search(release_heading, changelog):
        raise ValueError(f"CHANGELOG.md has no release section for {head_version}")
    tag = f"v{head_version}"
    if (
        subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}"],
            check=False,
            stdout=subprocess.DEVNULL,
        ).returncode
        == 0
    ):
        raise ValueError(f"release tag {tag} already exists")
    plan = {
        "previous_version": str(base_version),
        "version": str(head_version),
        "tag": tag,
    }
    write_github_output(args.github_output, plan)
    print(json.dumps(plan, indent=2))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    prepare_parser = commands.add_parser(
        "prepare", help="bump the workspace and changelog"
    )
    prepare_parser.add_argument("--base-ref", default="origin/main")
    prepare_parser.add_argument("--head-ref", default="HEAD")
    prepare_parser.add_argument(
        "--bump", choices=("auto", "patch", "minor", "major"), default="auto"
    )
    prepare_parser.add_argument("--cargo-toml", default="Cargo.toml")
    prepare_parser.add_argument("--changelog", default="CHANGELOG.md")
    prepare_parser.add_argument("--date")
    prepare_parser.add_argument("--github-output")
    prepare_parser.set_defaults(handler=prepare)

    verify_parser = commands.add_parser("verify", help="validate a release PR")
    verify_parser.add_argument("--base-ref", default="origin/main")
    verify_parser.add_argument("--cargo-toml", default="Cargo.toml")
    verify_parser.add_argument("--changelog", default="CHANGELOG.md")
    verify_parser.add_argument("--github-output")
    verify_parser.set_defaults(handler=verify)
    return root


def main() -> None:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"release train error: {error}") from error


if __name__ == "__main__":
    main()

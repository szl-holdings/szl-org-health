from __future__ import annotations

import base64
import copy
import hashlib
import unittest

from autonomic import controller as base
from autonomic import payload_equivalence as pe


REPOSITORY = "szl-holdings/a11oy"
OBSERVED = "a" * 40
EXPECTED = "b" * 40
DOCKERFILE = b"FROM python:3.12\nWORKDIR /app\nCOPY app.py /app/\nCOPY package/ /app/package/\nCMD [\"python\", \"app.py\"]\n"


def git_object(kind: str, data: bytes) -> str:
    return hashlib.sha1(f"{kind} {len(data)}\0".encode() + data).hexdigest()


def git_tree(files: dict[str, tuple[str, bytes]]) -> tuple[str, dict, dict]:
    """Build synthetic Git objects, independently of the production verifier."""
    root: dict = {}
    blobs: dict = {}
    for path, (mode, content) in files.items():
        parts = path.split("/")
        parent = root
        for part in parts[:-1]:
            parent = parent.setdefault(part, {})
        oid = git_object("blob", content)
        kind = "commit" if mode == "160000" else "blob"
        parent[parts[-1]] = (mode, kind, oid)
        if kind == "blob":
            blobs[oid] = {"sha": oid, "encoding": "base64", "size": len(content),
                          "content": base64.b64encode(content).decode()}

    def emit(node: dict, prefix: str = "") -> tuple[str, list]:
        body = bytearray()
        entries = []
        ordered = sorted(node, key=lambda name: (name + ("/" if isinstance(node[name], dict) else "")).encode())
        for name in ordered:
            value = node[name]
            path = prefix + name
            if isinstance(value, dict):
                oid, children = emit(value, path + "/")
                mode, kind = "040000", "tree"
            else:
                mode, kind, oid = value
                children = []
            body.extend(f"{mode.lstrip('0')} {name}\0".encode() + bytes.fromhex(oid))
            entries.append({"path": path, "mode": mode, "type": kind, "sha": oid})
            entries.extend(children)
        return git_object("tree", bytes(body)), entries

    tree_sha, entries = emit(root)
    return tree_sha, {"sha": tree_sha, "truncated": False, "tree": entries}, blobs


def payload_files() -> dict[str, tuple[str, bytes]]:
    return {
        "Dockerfile": ("100644", DOCKERFILE),
        "README.md": ("100644", b"---\nsdk: docker\n---\n"),
        "app.py": ("100644", b"print('bounded fixture')\n"),
        "package/__init__.py": ("100644", b""),
        "package/service.py": ("100644", b"VALUE = 1\n"),
        "docs/notes.md": ("100644", b"old notes\n"),
        "tests/test_app.py": ("100644", b"# old test\n"),
        ".github/workflows/hf-sync.yml": ("100644", b"name: canonical publisher\n"),
        "scripts/build_gdw_installed_source_manifest.py": ("100644", b"# manifest generator\n"),
    }


class GitHubFixture:
    def __init__(self, before: dict | None = None, after: dict | None = None) -> None:
        before = payload_files() if before is None else before
        if after is None:
            after = copy.deepcopy(before)
            after["docs/notes.md"] = ("100644", b"new notes\n")
            after["tests/test_app.py"] = ("100644", b"# new test\n")
        self.responses: dict[str, dict] = {}
        self.requests: list[tuple] = []
        self.tree_paths: dict[str, str] = {}
        self.blob_paths: dict[str, str] = {}
        for revision, files in ((OBSERVED, before), (EXPECTED, after)):
            tree_sha, tree, blobs = git_tree(files)
            self.responses[f"/repos/{REPOSITORY}/commits/{revision}"] = {
                "sha": revision,
                "commit": {"verification": {"verified": True, "reason": "valid"},
                           "tree": {"sha": tree_sha}},
            }
            tree_path = f"/repos/{REPOSITORY}/git/trees/{tree_sha}?recursive=1"
            self.tree_paths[revision] = tree_path
            self.responses[tree_path] = tree
            for oid, blob in blobs.items():
                self.responses[f"/repos/{REPOSITORY}/git/blobs/{oid}"] = blob
            self.blob_paths[revision] = f"/repos/{REPOSITORY}/git/blobs/{git_object('blob', files['Dockerfile'][1])}"
        self.compare_path = f"/repos/{REPOSITORY}/compare/{OBSERVED}...{EXPECTED}?per_page=1"
        self.responses[self.compare_path] = {
            "status": "ahead", "ahead_by": 2, "behind_by": 0, "total_commits": 2,
            "base_commit": {"sha": OBSERVED}, "merge_base_commit": {"sha": OBSERVED},
            # Deliberately empty: a capped compare-file list cannot prove equivalence.
            "files": [],
        }

    def _request(self, method: str, path: str, payload=None, **kwargs):
        if method != "GET" or payload is not None:
            raise AssertionError("equivalence verification must be read-only")
        self.requests.append((method, path, kwargs))
        if path not in self.responses:
            raise AssertionError(f"unexpected fixture request: {path}")
        return copy.deepcopy(self.responses[path])


class DockerCopySourcesTests(unittest.TestCase):
    def test_shell_json_and_directory_copy_sources(self) -> None:
        data = b'''FROM python:3.12\nCOPY --chown=1000:1000 app.py /app/\nCOPY --chmod=0755 ["package/", "assets/", "/app/"]\n'''
        self.assertEqual(set(pe.docker_copy_sources(data)), {"app.py", "package", "assets"})

    def test_heredoc_does_not_turn_body_into_docker_instructions(self) -> None:
        data = b'''FROM python:3.12 AS build\nCOPY app.py /work/\nRUN <<'SCRIPT'\nCOPY imaginary /not-an-instruction\nADD imaginary /not-an-instruction\nSCRIPT\nFROM python:3.12\nRUN --mount=type=bind,from=build,source=/work,target=/work true\n'''
        self.assertEqual(pe.docker_copy_sources(data), ("app.py",))

    def test_dynamic_image_does_not_allow_dynamic_context(self) -> None:
        data = b"ARG IMAGE=python:3.12\nFROM ${IMAGE} AS build\nCOPY app.py /app/\n"
        self.assertEqual(pe.docker_copy_sources(data), ("app.py",))

    def test_ambiguous_or_unbounded_context_is_rejected(self) -> None:
        instructions = (
            "ADD app.py /app/", "ONBUILD COPY app.py /app/", "COPY . /app/",
            "COPY / /app/", "COPY *.py /app/", "COPY $SOURCE /app/",
            "COPY ../app.py /app/", "COPY package/../app.py /app/",
            "COPY --from=unknown /app.py /app/", "COPY --link app.py /app/",
            "FROM python:3.12 AS build\nCOPY --from=build /app.py /app/",
            "RUN --mount=type=bind,source=.,target=/src true",
            "RUN --mount=type=bind,from=unknown,target=/src true",
            "UNKNOWN app.py", "COPY app.py", "RUN <<EOF\nunterminated",
        )
        for instruction in instructions:
            with self.subTest(instruction=instruction), self.assertRaises(base.ContractError):
                pe.docker_copy_sources(("FROM python:3.12\n" + instruction + "\n").encode())

    def test_parser_escape_directive_is_rejected(self) -> None:
        with self.assertRaises(base.ContractError):
            pe.docker_copy_sources(b"# escape=`\nFROM python:3.12\nCOPY app.py /app/\n")


class PayloadEquivalenceTests(unittest.TestCase):
    def verify(self, github: GitHubFixture) -> dict:
        return pe.verified_payload_equivalence(github, REPOSITORY, OBSERVED, EXPECTED)

    def test_docs_and_tests_only_changes_have_bound_proof(self) -> None:
        github = GitHubFixture()
        proof = self.verify(github)
        self.assertEqual(proof["schema"], "szl.payload-equivalence/v1")
        self.assertEqual(proof["match"], "PAYLOAD_EQUIVALENT")
        self.assertEqual(proof["repository"], REPOSITORY)
        self.assertEqual(proof["observed_revision"], OBSERVED)
        self.assertEqual(proof["expected_revision"], EXPECTED)
        self.assertEqual(set(proof["changed_paths"]), {"docs/notes.md", "tests/test_app.py"})
        self.assertEqual(set(proof["copy_sources"]), {"app.py", "package"})
        self.assertEqual(proof["dockerfile_blob"], git_object("blob", DOCKERFILE))
        for revision, field in ((OBSERVED, "observed_tree"), (EXPECTED, "expected_tree")):
            self.assertEqual(proof[field], github.responses[github.tree_paths[revision]]["sha"])
        tree_requests = [kwargs for _, path, kwargs in github.requests if "/git/trees/" in path]
        self.assertTrue(tree_requests)
        self.assertTrue(all(row.get("max_response_bytes") == 8_388_608 for row in tree_requests))

    def test_changed_copied_file_is_denied_even_with_empty_compare_file_list(self) -> None:
        after = payload_files()
        after["app.py"] = ("100644", b"print('changed runtime')\n")
        with self.assertRaises(base.ContractError):
            self.verify(GitHubFixture(after=after))

    def test_copied_directory_add_delete_and_rename_are_denied(self) -> None:
        for change in ("add", "delete", "rename"):
            after = payload_files()
            if change == "add":
                after["package/new.py"] = ("100644", b"NEW = True\n")
            else:
                content = after.pop("package/service.py")
                if change == "rename":
                    after["package/renamed.py"] = content
            with self.subTest(change=change), self.assertRaises(base.ContractError):
                self.verify(GitHubFixture(after=after))

    def test_payload_mode_change_is_denied(self) -> None:
        after = payload_files()
        after["app.py"] = ("100755", after["app.py"][1])
        with self.assertRaises(base.ContractError):
            self.verify(GitHubFixture(after=after))

    def test_publisher_and_context_control_changes_are_denied(self) -> None:
        paths = ("Dockerfile", "README.md", ".dockerignore", "Dockerfile.dockerignore",
                 ".gitattributes", ".gitmodules", ".github/workflows/hf-sync.yml",
                 ".github/scripts/publisher.py", "scripts/build_gdw_installed_source_manifest.py",
                 "scripts/configure_hf_series_a_runtime.py", "scripts/configure_hf_gdw_runtime.py",
                 "docs/operations/evidence/gdw-capture-37223162231.json",
                 "docs/operations/evidence/gdw-recovery-historical-anchors.json")
        for path in paths:
            after = payload_files()
            after[path] = ("100644", after.get(path, ("100644", b""))[1] + b"# changed\n")
            with self.subTest(path=path), self.assertRaises(base.ContractError):
                self.verify(GitHubFixture(after=after))

    def test_symlink_and_submodule_in_payload_are_denied_even_if_unchanged(self) -> None:
        for mode in ("120000", "160000"):
            before = payload_files()
            before["package/reference"] = (mode, b"../outside")
            with self.subTest(mode=mode), self.assertRaises(base.ContractError):
                self.verify(GitHubFixture(before=before))

    def test_fixed_control_symlink_cannot_hide_changed_context(self) -> None:
        before = payload_files()
        before[".dockerignore"] = ("120000", b"docs/ignore")
        before["docs/ignore"] = ("100644", b"docs/\n")
        after = copy.deepcopy(before)
        after["docs/ignore"] = ("100644", b"docs/\napp.py\n")
        with self.assertRaises(base.ContractError):
            self.verify(GitHubFixture(before=before, after=after))

    def test_nested_checkout_attributes_cannot_change_copied_file_bytes(self) -> None:
        before = payload_files()
        before["Dockerfile"] = ("100644", b"FROM python:3.12\nCOPY package/service.py /app/\n")
        before["package/.gitattributes"] = ("100644", b"*.py text eol=lf\n")
        after = copy.deepcopy(before)
        after["package/.gitattributes"] = ("100644", b"*.py text eol=crlf\n")
        with self.assertRaises(base.ContractError):
            self.verify(GitHubFixture(before=before, after=after))

    def test_optional_fixed_input_cannot_hide_beneath_symlink_ancestor(self) -> None:
        before = payload_files()
        del before["docs/notes.md"]
        before["docs"] = ("120000", b"outside")
        before["outside/operations/evidence/gdw-capture-37223162231.json"] = ("100644", b"old")
        after = copy.deepcopy(before)
        after["outside/operations/evidence/gdw-capture-37223162231.json"] = ("100644", b"new")
        with self.assertRaises(base.ContractError):
            self.verify(GitHubFixture(before=before, after=after))

    def test_missing_copy_source_is_denied(self) -> None:
        before = payload_files()
        before["Dockerfile"] = ("100644", b"FROM python:3.12\nCOPY missing.py /app/\n")
        with self.assertRaises(base.ContractError):
            self.verify(GitHubFixture(before=before))

    def test_unsigned_or_wrong_revision_commit_is_denied(self) -> None:
        for revision in (OBSERVED, EXPECTED):
            for change in ("signature", "sha"):
                github = GitHubFixture()
                commit = github.responses[f"/repos/{REPOSITORY}/commits/{revision}"]
                if change == "signature":
                    commit["commit"]["verification"]["verified"] = False
                else:
                    commit["sha"] = "c" * 40
                with self.subTest(revision=revision, change=change), self.assertRaises(base.ContractError):
                    self.verify(github)

    def test_ancestor_relationship_must_be_complete_and_unambiguous(self) -> None:
        mutations = ({"status": "diverged"}, {"behind_by": 1}, {"ahead_by": 0},
                     {"base_commit": {"sha": "c" * 40}},
                     {"merge_base_commit": {"sha": "c" * 40}})
        for mutation in mutations:
            github = GitHubFixture()
            github.responses[github.compare_path].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(base.ContractError):
                self.verify(github)

    def test_truncated_tree_or_wrong_tree_binding_is_denied(self) -> None:
        for revision in (OBSERVED, EXPECTED):
            for field, value in (("truncated", True), ("sha", "c" * 40)):
                github = GitHubFixture()
                github.responses[github.tree_paths[revision]][field] = value
                with self.subTest(revision=revision, field=field), self.assertRaises(base.ContractError):
                    self.verify(github)

    def test_omitted_or_forged_tree_entry_fails_git_object_reconstruction(self) -> None:
        for change in ("omit", "blob", "directory"):
            github = GitHubFixture()
            entries = github.responses[github.tree_paths[EXPECTED]]["tree"]
            if change == "omit":
                entries[:] = [row for row in entries if row["path"] != "app.py"]
            elif change == "blob":
                next(row for row in entries if row["path"] == "app.py")["sha"] = "c" * 40
            else:
                next(row for row in entries if row["path"] == "package")["sha"] = "c" * 40
            with self.subTest(change=change), self.assertRaises(base.ContractError):
                self.verify(github)

    def test_duplicate_or_invalid_tree_paths_are_denied(self) -> None:
        for change in ("duplicate", "traversal", "absolute"):
            github = GitHubFixture()
            entries = github.responses[github.tree_paths[EXPECTED]]["tree"]
            entry = copy.deepcopy(next(row for row in entries if row["path"] == "app.py"))
            if change == "traversal":
                entry["path"] = "../app.py"
            elif change == "absolute":
                entry["path"] = "/app.py"
            entries.append(entry)
            with self.subTest(change=change), self.assertRaises(base.ContractError):
                self.verify(github)

    def test_dockerfile_blob_corruption_is_denied(self) -> None:
        mutations = ({"content": base64.b64encode(b"FROM scratch\n").decode()},
                     {"content": "not base64!"}, {"sha": "c" * 40}, {"encoding": "utf8"})
        for mutation in mutations:
            github = GitHubFixture()
            github.responses[github.blob_paths[OBSERVED]].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(base.ContractError):
                self.verify(github)

    def test_unapproved_repository_and_invalid_revisions_fail_before_requests(self) -> None:
        for repository, observed, expected in (
            ("szl-holdings/lyte", OBSERVED, EXPECTED),
            (REPOSITORY, "main", EXPECTED), (REPOSITORY, OBSERVED, "b" * 39),
        ):
            github = GitHubFixture()
            with self.subTest(repository=repository, observed=observed), self.assertRaises(base.ContractError):
                pe.verified_payload_equivalence(github, repository, observed, expected)
            self.assertEqual(github.requests, [])


if __name__ == "__main__":
    unittest.main()

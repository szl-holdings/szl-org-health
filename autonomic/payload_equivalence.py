"""Prove unchanged A11oy repository deployment inputs between signed commits.

This is source-input equivalence, not rebuilt-image or runtime certification.
The COPY/continuation/heredoc grammar follows the reviewed A11oy parser at
6db8b768cade188d5d14ec57efdd710701059e98, scripts/build_gdw_installed_source_manifest.py.
No remotely fetched code is executed. Complete, rehashed Git trees provide the
diff: GitHub compare's capped file list is used for neither coverage nor equality.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

from autonomic.controller import ContractError, SHA40, canonical_json, require, sha256_hex

POLICY = "payload-equivalent-default-branch"
REPOSITORY = "szl-holdings/a11oy"
MAX_TREE_ENTRIES = 16384
MAX_TREE_BYTES = 8 * 1024 * 1024
MAX_DOCKERFILE_BYTES = 128 * 1024
# Include publisher configuration and Dockerfile-specific ignore precedence.
FIXED_INPUTS = ("Dockerfile", "README.md", ".dockerignore", "Dockerfile.dockerignore",
                ".gitattributes", ".gitmodules", ".github", "scripts",
                "docs/operations/evidence/gdw-capture-37223162231.json",
                "docs/operations/evidence/gdw-recovery-historical-anchors.json")
HEREDOC = re.compile(r"<<(-?)(?:'([A-Za-z_][A-Za-z0-9_]*)'|\"([A-Za-z_][A-Za-z0-9_]*)\"|([A-Za-z_][A-Za-z0-9_]*))")
LITERAL = re.compile(r"[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)*\Z")


def _path(value: Any) -> str:
    require(isinstance(value, str) and 0 < len(value.encode("utf-8")) <= 1024,
            "invalid Git path")
    require(not any(ord(c) < 32 or ord(c) == 127 for c in value)
            and "\\" not in value
            and all(p not in ("", ".", "..") and p.casefold() != ".git"
                    for p in value.split("/")), "unsafe Git path")
    return value


def _oid(value: Any) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
            "invalid Git object identity")
    return value


def _object_hash(kind: str, data: bytes) -> str:
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def docker_copy_sources(data: bytes) -> tuple[str, ...]:
    """Accept a bounded literal COPY grammar, including real RUN heredocs."""
    require(0 < len(data) <= MAX_DOCKERFILE_BYTES, "Dockerfile size is invalid")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ContractError("invalid Dockerfile encoding") from exc
    require("\r" not in text and "\0" not in text
            and not re.search(r"(?im)^\s*#\s*escape\s*=", text), "unsupported Docker escape")
    syntax = re.findall(r"(?im)^\s*#\s*syntax\s*=\s*(\S+)", text)
    require(all(s == "docker/dockerfile:1" for s in syntax), "unsupported Docker frontend")
    lines, position, sources, stages = text.splitlines(), 0, set(), set()
    while position < len(lines):
        line = lines[position]
        position += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        while line.rstrip().endswith("\\"):
            require(position < len(lines) and lines[position].strip()
                    and not lines[position].lstrip().startswith("#"), "ambiguous Docker continuation")
            line = line.rstrip()[:-1] + " " + lines[position]
            position += 1
        parts = line.strip().split(None, 1)
        require(len(parts) == 2, "invalid Docker instruction")
        instruction, arguments = parts[0].upper(), parts[1]
        require(instruction in {"FROM", "WORKDIR", "COPY", "RUN", "ARG", "ENV", "LABEL",
                                "EXPOSE", "VOLUME", "CMD", "ENTRYPOINT", "USER", "HEALTHCHECK",
                                "STOPSIGNAL", "SHELL"}, "unsupported Docker instruction")
        if instruction == "FROM":
            stage = re.search(r"\s+AS\s+([A-Za-z0-9_-]+)\s*$", arguments, re.I)
            if stage:
                stages.add(stage.group(1))
        if instruction == "RUN":
            # A bind mount without an admitted build stage can read the context
            # without COPY. It cannot be omitted from the source closure.
            for mount in re.findall(r"--mount=(\S+)", arguments):
                options = dict(p.split("=", 1) for p in mount.split(",") if "=" in p)
                require(options.get("from") in stages, "unproven RUN mount source")
            require(not re.search(r"--mount(?:\s|$)", arguments), "ambiguous RUN mount")
            matches = list(HEREDOC.finditer(line))
            require(line.count("<<") == len(matches) and len(matches) <= 4,
                    "ambiguous Docker heredoc")
            for match in matches:
                dash, single, double, bare = match.groups()
                marker = single or double or bare
                while position < len(lines):
                    part = lines[position]
                    position += 1
                    if (part.lstrip("\t") if dash else part) == marker:
                        break
                else:
                    require(False, "unterminated Docker heredoc")
        else:
            require("<<" not in line, "unsupported Docker heredoc")
        if instruction != "COPY":
            continue
        while arguments.startswith("--"):
            flag, separator, arguments = arguments.partition(" ")
            require(bool(separator), "COPY flag has no arguments")
            arguments = arguments.lstrip()
            require(re.fullmatch(r"--(?:chown|chmod)=[A-Za-z0-9_:.-]+", flag) is not None,
                    "unsupported COPY flag")
        if arguments.startswith("["):
            try:
                values = json.loads(arguments)
            except ValueError as exc:
                raise ContractError("invalid COPY JSON") from exc
            require(isinstance(values, list) and all(isinstance(v, str) for v in values),
                    "invalid COPY JSON")
        else:
            require(not any(c in arguments for c in "\"'\\"), "ambiguous COPY quoting")
            values = arguments.split()
        require(len(values) >= 2, "incomplete COPY")
        destination = values[-1]
        require(bool(destination) and not any(c in destination for c in "$\\\0")
                and ".." not in destination.split("/"), "invalid COPY destination")
        for value in values[:-1]:
            while value.startswith("./"):
                value = value[2:]
            value = _path(value.rstrip("/"))
            require(LITERAL.fullmatch(value) is not None, "nonliteral COPY source")
            sources.add(value)
        require(len(sources) <= 1024, "COPY source limit exceeded")
    require(bool(sources), "Dockerfile has no provable COPY sources")
    return tuple(sorted(sources))


def _commit(github: Any, repository: str, revision: str) -> str:
    _oid(revision)
    payload = github._request("GET", f"/repos/{repository}/commits/{revision}")
    require(isinstance(payload, dict) and payload.get("sha") == revision,
            "commit response revision drift")
    commit = payload.get("commit")
    require(isinstance(commit, dict), "missing commit metadata")
    verification = commit.get("verification")
    require(isinstance(verification, dict) and verification.get("verified") is True,
            "payload commit is not cryptographically verified")
    tree = commit.get("tree")
    require(isinstance(tree, dict), "missing commit tree")
    return _oid(tree.get("sha"))


def _tree(github: Any, repository: str, oid: str) -> dict[str, dict[str, str]]:
    payload = github._request("GET", f"/repos/{repository}/git/trees/{oid}?recursive=1",
                              max_response_bytes=MAX_TREE_BYTES)
    require(isinstance(payload, dict) and payload.get("sha") == oid
            and payload.get("truncated") is False, "incomplete or mismatched Git tree")
    rows = payload.get("tree")
    require(isinstance(rows, list) and 0 < len(rows) <= MAX_TREE_ENTRIES,
            "Git tree entry limit exceeded")
    entries: dict[str, dict[str, str]] = {}
    children: dict[str, list[tuple[str, dict[str, str]]]] = {"": []}
    kinds = {"100644": "blob", "100755": "blob", "120000": "blob",
             "040000": "tree", "160000": "commit"}
    for row in rows:
        require(isinstance(row, dict), "malformed Git tree entry")
        path = _path(row.get("path"))
        require(path not in entries, "duplicate Git tree path")
        mode = row.get("mode")
        require(isinstance(mode, str) and mode in kinds and row.get("type") == kinds[mode],
                "unknown Git tree mode or type")
        entries[path] = {"mode": mode, "type": kinds[mode], "sha": _oid(row.get("sha"))}
        if mode == "040000":
            children[path] = []
    for path, entry in entries.items():
        parent, _, name = path.rpartition("/")
        require(parent in children, "Git tree parent is missing")
        children[parent].append((name, entry))
    # Reconstruct every directory, including the root signed by the commit.
    # This catches omitted entries even if a response claims truncated=false.
    for directory, members in children.items():
        members.sort(key=lambda pair: pair[0].encode("utf-8")
                     + (b"/" if pair[1]["type"] == "tree" else b""))
        data = b"".join(entry["mode"].lstrip("0").encode() + b" "
                        + name.encode("utf-8") + b"\0" + bytes.fromhex(entry["sha"])
                        for name, entry in members)
        expected = entries[directory]["sha"] if directory else oid
        require(_object_hash("tree", data) == expected, "Git tree object hash mismatch")
    return entries


def _blob(github: Any, repository: str, oid: str) -> bytes:
    payload = github._request("GET", f"/repos/{repository}/git/blobs/{oid}")
    require(isinstance(payload, dict) and payload.get("sha") == oid
            and payload.get("encoding") == "base64", "mismatched Dockerfile blob")
    content = payload.get("content")
    require(isinstance(content, str), "missing Dockerfile blob bytes")
    try:
        data = base64.b64decode("".join(content.split()), validate=True)
    except ValueError as exc:
        raise ContractError("invalid Dockerfile blob encoding") from exc
    require(type(payload.get("size")) is int and payload["size"] == len(data)
            and 0 < len(data) <= MAX_DOCKERFILE_BYTES
            and _object_hash("blob", data) == oid, "Dockerfile blob hash or size mismatch")
    return data


def _within(path: str, source: str) -> bool:
    return path == source or path.startswith(source + "/")


def failed_verification(observed: str | None, expected: str | None,
                        exc: BaseException) -> dict[str, Any]:
    """Retain immutable identities and trusted callsite, never exception text."""
    from autonomic.controller import safe_error_kind
    from autonomic.slo_controller import safe_error_origin
    return {
        "schema": "szl.payload-equivalence/v1", "match": "NONE", "repository": REPOSITORY,
        "observed_revision": observed if isinstance(observed, str) and SHA40.fullmatch(observed) else None,
        "expected_revision": expected if isinstance(expected, str) and SHA40.fullmatch(expected) else None,
        "error_kind": safe_error_kind(exc), "error_origin": safe_error_origin(exc),
    }


def state_verification(proof: Any) -> dict[str, Any] | None:
    """Keep durable issue state bounded; the cycle artifact retains full proof."""
    if proof is None:
        return None
    result = {key: proof[key] for key in (
        "schema", "match", "repository", "observed_revision", "expected_revision",
        "observed_tree", "expected_tree", "dockerfile_blob", "error_kind", "error_origin",
    ) if key in proof}
    result["proof_sha256"] = sha256_hex(canonical_json(proof))
    return result


def verified_payload_equivalence(github: Any, repository: str,
                                 observed: str, expected: str) -> dict[str, Any]:
    require(repository == REPOSITORY and observed != expected,
            "payload equivalence is restricted to unequal A11oy revisions")
    _oid(observed)
    _oid(expected)
    observed_tree = _commit(github, repository, observed)
    expected_tree = _commit(github, repository, expected)
    comparison = github._request("GET", f"/repos/{repository}/compare/{observed}...{expected}?per_page=1")
    require(isinstance(comparison, dict), "missing ancestry comparison")
    require(comparison.get("status") == "ahead"
            and type(comparison.get("behind_by")) is int and comparison["behind_by"] == 0
            and type(comparison.get("ahead_by")) is int and comparison["ahead_by"] > 0,
            "observed revision is not a strict ancestor of the verified tip")
    for name in ("base_commit", "merge_base_commit"):
        row = comparison.get(name)
        require(isinstance(row, dict) and row.get("sha") == observed,
                "ancestry comparison identity mismatch")
    before = _tree(github, repository, observed_tree)
    after = _tree(github, repository, expected_tree)
    changed = sorted(p for p in before.keys() | after.keys()
                     if before.get(p) != after.get(p)
                     and (before.get(p, {}).get("type") != "tree"
                          or after.get(p, {}).get("type") != "tree"))
    # Directory OIDs change whenever any descendant changes; leaves and type
    # transitions capture the actual changed paths without false prefix drift.
    require(not any(_within(p, fixed) or _within(fixed, p)
                    for p in changed for fixed in FIXED_INPUTS),
            "publisher or fixed deployment input changed")
    require(not any(p.rsplit("/", 1)[-1] in {".gitattributes", ".gitmodules"} for p in changed),
            "checkout transformation inputs changed")
    for tree in (before, after):
        require(all(entry["mode"] in {"100644", "100755", "040000"}
                    for path, entry in tree.items()
                    if any(_within(path, fixed) or _within(fixed, path) for fixed in FIXED_INPUTS)
                    or path.rsplit("/", 1)[-1] in {".gitattributes", ".gitmodules"}),
                "publisher or checkout inputs contain a symlink or submodule")
    docker = after.get("Dockerfile")
    require(docker is not None and docker["mode"] in {"100644", "100755"}
            and before.get("Dockerfile") == docker, "Dockerfile is not unchanged regular source")
    sources = docker_copy_sources(_blob(github, repository, docker["sha"]))
    for source in sources:
        for tree in (before, after):
            require(source in tree, "COPY source is absent from the immutable tree")
            selected = [entry for path, entry in tree.items() if _within(path, source)]
            require(all(entry["mode"] in {"100644", "100755", "040000"} for entry in selected),
                    "COPY source contains a symlink or submodule")
    require(not any(_within(path, source) for path in changed for source in sources),
            "deployed COPY input changed")
    return {
        "schema": "szl.payload-equivalence/v1",
        "repository": repository,
        "observed_revision": observed,
        "expected_revision": expected,
        "observed_tree": observed_tree,
        "expected_tree": expected_tree,
        "match": "PAYLOAD_EQUIVALENT",
        "scope": "REPOSITORY_DEPLOYMENT_INPUTS_ONLY",
        "dockerfile_blob": docker["sha"],
        "copy_sources": list(sources),
        "fixed_inputs": list(FIXED_INPUTS),
        "changed_paths": changed,
        "changed_paths_sha256": sha256_hex(canonical_json(changed)),
        "ancestry": {"status": "ahead", "ahead_by": comparison["ahead_by"], "behind_by": 0},
    }

#!/usr/bin/env python3
"""Build or verify a source-bound Series-A diligence artifact."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

ROOT = Path(__file__).resolve().parent


def _load_exact_module(
    name: str,
    path: Path,
    *,
    package: bool = False,
) -> object:
    """Load one repository module without adding the repository to sys.path."""

    expected = path.resolve()
    existing = sys.modules.get(name)
    if existing is not None:
        location = getattr(existing, "__file__", None)
        try:
            loaded = Path(location).resolve() if isinstance(location, str) else None
        except OSError:
            loaded = None
        if loaded != expected:
            raise ImportError(f"{name} is already loaded from an unexpected path")
        return existing

    search_locations = [str(expected.parent)] if package else None
    spec = importlib.util.spec_from_file_location(
        name,
        expected,
        submodule_search_locations=search_locations,
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load exact repository module: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


_census_package = _load_exact_module(
    "census",
    ROOT / "census" / "__init__.py",
    package=True,
)
_diligence_module = _load_exact_module(
    "census.diligence",
    ROOT / "census" / "diligence.py",
)
setattr(_census_package, "diligence", _diligence_module)

DiligenceError = _diligence_module.DiligenceError
canonical_bytes = _diligence_module.canonical_bytes
compile_diligence = _diligence_module.compile_diligence
render_markdown = _diligence_module.render_markdown
strict_load_json = _diligence_module.strict_load_json
strict_read_json = _diligence_module.strict_read_json
require_public_projection_input = _diligence_module.require_public_projection_input
MAX_RECEIPT_BYTES = _diligence_module.MAX_RECEIPT_BYTES
validate_artifact = _diligence_module.validate_artifact


DEFAULT_INPUT = ROOT / "static" / "data.json"
DEFAULT_POLICY = ROOT / "diligence" / "policy.json"
DEFAULT_OUTPUT = ROOT / "generated" / "series-a-diligence.json"
DEFAULT_MARKDOWN = ROOT / "generated" / "SERIES_A_DILIGENCE.generated.md"


def _stage_write(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary_path
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary = _stage_write(path, payload)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _atomic_write_pair(first: tuple[Path, bytes], second: tuple[Path, bytes]) -> None:
    """Stage both files, then publish with rollback on a caught failure."""

    pairs = (first, second)
    originals = {
        path: path.read_bytes() if path.exists() else None for path, _ in pairs
    }
    staged: dict[Path, Path] = {}
    replaced: list[Path] = []
    try:
        for path, payload in pairs:
            staged[path] = _stage_write(path, payload)
        for path, _payload in pairs:
            os.replace(staged[path], path)
            replaced.append(path)
        for parent in {path.parent for path, _payload in pairs}:
            _fsync_directory(parent)
    except BaseException:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
        for path in reversed(replaced):
            original = originals[path]
            if original is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_write(path, original)
        raise
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)


def _guard_distinct_paths(*paths: Path) -> None:
    resolved = [path.resolve(strict=False) for path in paths]
    lexical = [os.path.normcase(str(path)) for path in resolved]
    if len(lexical) != len(set(lexical)):
        raise DiligenceError(
            "input, optional receipt, policy, JSON output, and Markdown output paths must be distinct"
        )
    for index, left in enumerate(paths):
        if not left.exists():
            continue
        for right in paths[index + 1 :]:
            if not right.exists():
                continue
            try:
                if os.path.samefile(left, right):
                    raise DiligenceError(
                        "input, policy, JSON output, and Markdown output "
                        "paths must not alias the same file"
                    )
            except OSError as exc:
                raise DiligenceError("path identity could not be verified") from exc


def _lock_stream(paths: tuple[Path, ...]) -> BinaryIO:
    identities = sorted(
        os.path.normcase(str(path.resolve(strict=False))) for path in paths
    )
    lock_id = hashlib.sha256("\0".join(identities).encode("utf-8")).hexdigest()
    lock_root = Path(tempfile.gettempdir()) / "szl-series-a-diligence-locks"
    lock_root.mkdir(parents=True, exist_ok=True)
    stream = (lock_root / f"{lock_id}.lock").open("a+b")
    stream.seek(0, os.SEEK_END)
    if stream.tell() == 0:
        stream.write(b"\0")
        stream.flush()
        os.fsync(stream.fileno())
    stream.seek(0)
    return stream


@contextmanager
def _pair_lock(*paths: Path) -> Iterator[None]:
    stream = _lock_stream(tuple(paths))
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()


def _expected_bytes(
    input_path: Path,
    policy_path: Path,
    receipt_path: Path | None,
    source_revision: str,
    as_of: str | None,
) -> tuple[dict, bytes, bytes]:
    report, raw_public_bytes = strict_read_json(input_path)
    require_public_projection_input(report)
    policy = strict_load_json(policy_path)
    receipt = None
    if receipt_path is not None:
        try:
            receipt, _raw_receipt = strict_read_json(
                receipt_path, max_bytes=MAX_RECEIPT_BYTES
            )
        except DiligenceError:
            # A requested but unreadable or malformed receipt is divergent,
            # never equivalent to the optional receipt being absent.
            receipt = {}
    artifact = compile_diligence(
        report,
        compiler_source_revision=source_revision,
        policy=policy,
        as_of=as_of,
        raw_public_bytes=raw_public_bytes,
        public_snapshot_receipt=receipt,
    )
    errors = validate_artifact(artifact)
    if errors:
        raise DiligenceError(f"compiled artifact is invalid: {', '.join(errors)}")
    return (
        artifact,
        canonical_bytes(artifact) + b"\n",
        render_markdown(artifact).encode("utf-8"),
    )


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise DiligenceError("command-line arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument(
        "--receipt",
        type=Path,
        help="optional sanitized census-receipt.json for exact public-byte binding",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument(
        "--as-of", help="RFC3339 assessment time; defaults to current UTC time"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="recompute and byte-compare existing outputs",
    )
    parser.add_argument(
        "--historical-check",
        action="store_true",
        help=(
            "with --check, reproduce stored historical bytes without "
            "claiming current freshness"
        ),
    )
    parser.add_argument(
        "--require-measured",
        action="store_true",
        help="return nonzero unless the recomputed state is MEASURED",
    )
    parser.add_argument(
        "--require-source-bound",
        action="store_true",
        help="return nonzero unless compiler bytes are bound to the exact revision",
    )
    return parser


def _result(
    *,
    state: str,
    artifact: dict,
    output: Path,
    markdown: Path,
    current_artifact: dict | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "state": state,
        "verification_mode": state,
        "artifact_state": artifact["state"],
        "output": str(output),
        "markdown": str(markdown),
        "digest_sha256": artifact["digest_sha256"],
        "gap_count": len(artifact["gaps"]),
        "public_snapshot_binding_state": artifact["public_snapshot_binding"]["state"],
    }
    if current_artifact is not None:
        result.update(
            {
                "current_artifact_state": current_artifact["state"],
                "current_assessed_at": current_artifact["assessed_at"],
                "current_digest_sha256": current_artifact["digest_sha256"],
                "current_gap_count": len(current_artifact["gaps"]),
                "current_snapshot_freshness_state": current_artifact["requirements"][
                    "snapshot_freshness"
                ]["state"],
            }
        )
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        _guard_distinct_paths(
            args.input,
            args.policy,
            args.output,
            args.markdown,
            *((args.receipt,) if args.receipt is not None else ()),
        )
        if args.historical_check and not args.check:
            raise DiligenceError("--historical-check requires --check")
        if args.historical_check and args.require_measured:
            raise DiligenceError(
                "--require-measured cannot be combined with --historical-check"
            )
        with _pair_lock(args.output, args.markdown):
            _guard_distinct_paths(
                args.input,
                args.policy,
                args.output,
                args.markdown,
                *((args.receipt,) if args.receipt is not None else ()),
            )
            reproduction_as_of = args.as_of
            if args.check and reproduction_as_of is None:
                existing = strict_load_json(args.output)
                reproduction_as_of = existing.get("assessed_at")
                if not isinstance(reproduction_as_of, str):
                    raise DiligenceError(
                        "checked artifact has no assessed_at timestamp"
                    )
            artifact, json_payload, markdown_payload = _expected_bytes(
                args.input,
                args.policy,
                args.receipt,
                args.source_revision,
                reproduction_as_of,
            )
            current_artifact = None
            if args.check:
                if args.output.read_bytes() != json_payload:
                    raise DiligenceError(
                        f"JSON output differs from recomputation: {args.output}"
                    )
                if args.markdown.read_bytes() != markdown_payload:
                    raise DiligenceError(
                        f"Markdown output differs from recomputation: {args.markdown}"
                    )
                if args.historical_check:
                    mode = "HISTORICAL_BYTES_VERIFIED"
                elif args.as_of is not None:
                    mode = "EXPLICIT_AS_OF_BYTES_VERIFIED"
                else:
                    mode = "CURRENT_CHECK_COMPLETE"
                    current_artifact, _current_json, _current_markdown = (
                        _expected_bytes(
                            args.input,
                            args.policy,
                            args.receipt,
                            args.source_revision,
                            None,
                        )
                    )
            else:
                mode = "BUILD_COMPLETE"

            result = _result(
                state=mode,
                artifact=artifact,
                output=args.output,
                markdown=args.markdown,
                current_artifact=current_artifact,
            )
            gate_artifact = current_artifact or artifact
            failures: list[str] = []
            if (
                gate_artifact["requirements"]["public_snapshot_receipt"]["state"]
                == "DIVERGENT"
            ):
                failures.append("PUBLIC_RECEIPT_DIVERGENT")
            if (
                current_artifact is not None
                and current_artifact["requirements"]["snapshot_freshness"]["state"]
                != "MEASURED"
            ):
                failures.append("CURRENT_EVIDENCE_STALE")
            if (
                args.require_source_bound
                and gate_artifact["requirements"]["compiler_source"]["state"]
                != "MEASURED"
            ):
                failures.append("SOURCE_BINDING_NOT_MET")
            if args.require_measured and gate_artifact["state"] != "MEASURED":
                failures.append("REQUIREMENT_NOT_MET")
            if failures:
                primary = failures[0]
                result["state"] = primary
                result["verification_mode"] = primary
                result["failures"] = failures
                stream = (
                    sys.stderr if primary == "CURRENT_EVIDENCE_STALE" else sys.stdout
                )
                print(
                    json.dumps(result, sort_keys=True, separators=(",", ":")),
                    file=stream,
                )
                return {
                    "PUBLIC_RECEIPT_DIVERGENT": 6,
                    "CURRENT_EVIDENCE_STALE": 4,
                    "SOURCE_BINDING_NOT_MET": 5,
                    "REQUIREMENT_NOT_MET": 3,
                }[primary]
            if not args.check:
                _atomic_write_pair(
                    (args.output, json_payload),
                    (args.markdown, markdown_payload),
                )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
    except (
        DiligenceError,
        OSError,
        UnicodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {"state": "FAILED", "error": str(exc)[:400]},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

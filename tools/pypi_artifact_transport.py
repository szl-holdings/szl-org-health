#!/usr/bin/env python3
"""Inert artifact-transport probe for the canonical PyPI release pins.

Used by .github/workflows/pypi-artifact-transport.yml, which is rendered from the
same PINS table as the canonical publish-pypi.yml. Standard library only.

  stage       write two deterministic inert files (a dummy wheel and sdist,
              classified `Private :: Do Not Upload`, never published) and a
              SHA-256 manifest of them
  verify      require a directory to hold exactly the manifest's files with
              identical SHA-256; a missing, extra, altered or linked file fails
  self-check  prove that `verify` rejects a missing, an extra and an altered file
              (negative controls on scratch copies) and accepts the directory as is
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

SCHEMA = "szl.pypi-artifact-transport.v1"
NAME = "szl_transport_probe"
VERSION = "0.0.0"
WHEEL = f"{NAME}-{VERSION}-py3-none-any.whl"
SDIST = f"{NAME}-{VERSION}.tar.gz"
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

METADATA = (
    "Metadata-Version: 2.1\n"
    "Name: szl-transport-probe\n"
    f"Version: {VERSION}\n"
    "Summary: Inert artifact-transport probe for szl-org-health. Never published.\n"
    "Classifier: Private :: Do Not Upload\n"
)
MODULE = '"""Inert artifact-transport probe for szl-org-health. Never published."""\n'


class ManifestError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def wheel_bytes() -> bytes:
    dist_info = f"{NAME}-{VERSION}.dist-info"
    files = {
        f"{NAME}/__init__.py": MODULE,
        f"{dist_info}/METADATA": METADATA,
        f"{dist_info}/WHEEL": "Wheel-Version: 1.0\nGenerator: szl-transport-probe\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = []
    for path, text in files.items():
        data = text.encode("utf-8")
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        record.append(f"{path},sha256={digest},{len(data)}")
    record.append(f"{dist_info}/RECORD,,")
    files[f"{dist_info}/RECORD"] = "\n".join(record) + "\n"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, text in files.items():
            info = zipfile.ZipInfo(path, ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3  # same bytes on every host
            info.external_attr = 0o100644 << 16
            archive.writestr(info, text.encode("utf-8"))
    return buffer.getvalue()


def sdist_bytes() -> bytes:
    root = f"{NAME}-{VERSION}"
    files = {f"{root}/PKG-INFO": METADATA, f"{root}/{NAME}/__init__.py": MODULE}
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, text in files.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(path)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    gz_buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buffer, mtime=0, compresslevel=9) as stream:
        stream.write(tar_buffer.getvalue())
    return gz_buffer.getvalue()


def stage(outdir: Path) -> dict:
    if outdir.exists() and any(outdir.iterdir()):
        raise SystemExit(f"::error::{outdir} is not empty; the probe stages into an empty directory")
    outdir.mkdir(parents=True, exist_ok=True)
    files = {}
    for name, data in ((WHEEL, wheel_bytes()), (SDIST, sdist_bytes())):
        (outdir / name).write_bytes(data)
        files[name] = sha256_bytes(data)
    return {"schema": SCHEMA, "files": files}


def parse_manifest(text: str) -> dict[str, str]:
    try:
        manifest = json.loads(text)
    except (TypeError, ValueError) as error:
        raise ManifestError(f"manifest is not JSON: {error}") from None
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ManifestError(f"manifest schema is not {SCHEMA}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ManifestError("manifest names no files")
    for name, digest in files.items():
        if not isinstance(name, str) or not FILENAME.fullmatch(name):
            raise ManifestError(f"manifest file name is not a plain file name: {name!r}")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ManifestError(f"manifest digest for {name} is not 64 lowercase hex: {digest!r}")
    return dict(files)


def verify(directory: Path, expected: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    """Return (errors, observed digests); no errors means byte-identical transport."""
    errors: list[str] = []
    observed: dict[str, str] = {}
    if not directory.is_dir():
        return [f"download directory {directory} does not exist"], observed
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            errors.append(f"linked entry {relative} is not accepted")
        elif path.is_file():
            observed[relative] = sha256_bytes(path.read_bytes())
    for name in sorted(set(expected) - set(observed)):
        errors.append(f"missing expected file {name}")
    for name in sorted(set(observed) - set(expected)):
        errors.append(f"unexpected file {name}")
    for name in sorted(set(expected) & set(observed)):
        if observed[name] != expected[name]:
            errors.append(f"sha256 mismatch for {name}: expected {expected[name]}, downloaded {observed[name]}")
    return errors, observed


def self_check(directory: Path, expected: dict[str, str]) -> list[str]:
    """Negative controls: each altered copy must be rejected, the original accepted."""
    failures: list[str] = []
    errors, _ = verify(directory, expected)
    if errors:
        return ["untouched download does not verify: " + "; ".join(errors)]
    first = sorted(expected)[0]

    def remove(copy: Path) -> None:
        (copy / first).unlink()

    def add(copy: Path) -> None:
        (copy / "unexpected-extra.whl").write_bytes(b"not part of the manifest\n")

    def alter(copy: Path) -> None:
        target = copy / first
        data = bytearray(target.read_bytes())
        data[-1] ^= 0x01
        target.write_bytes(bytes(data))

    controls = (
        ("missing expected file", remove, f"missing expected file {first}"),
        ("extra file", add, "unexpected file unexpected-extra.whl"),
        ("altered byte", alter, f"sha256 mismatch for {first}"),
    )
    with tempfile.TemporaryDirectory() as scratch:
        for index, (label, mutate, needle) in enumerate(controls):
            copy = Path(scratch) / f"control-{index}"
            shutil.copytree(directory, copy)
            mutate(copy)
            rejected, _ = verify(copy, expected)
            if any(needle in error for error in rejected):
                print(f"negative control [{label}]: rejected ({'; '.join(rejected)})")
            else:
                failures.append(f"negative control [{label}] was not rejected: {rejected}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    staged = commands.add_parser("stage")
    staged.add_argument("--outdir", type=Path, required=True)
    staged.add_argument("--manifest", type=Path, required=True)
    for name in ("verify", "self-check"):
        command = commands.add_parser(name)
        command.add_argument("--dir", type=Path, required=True)
        command.add_argument("--manifest-json", required=True)
    args = parser.parse_args(argv)

    if args.command == "stage":
        manifest = stage(args.outdir)
        args.manifest.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        for name, digest in sorted(manifest["files"].items()):
            print(f"staged sha256={digest} {name}")
        return 0

    try:
        expected = parse_manifest(args.manifest_json)
    except ManifestError as error:
        print(f"::error::{error}")
        return 1
    if args.command == "verify":
        errors, observed = verify(args.dir, expected)
        for name, digest in sorted(observed.items()):
            state = "MATCH" if expected.get(name) == digest else "DIFFERS"
            print(f"downloaded sha256={digest} {name} {state}")
        for error in errors:
            print(f"::error::{error}")
        if errors:
            return 1
        print(f"pre/post SHA-256 equal for {len(expected)}/{len(expected)} files")
        return 0
    failures = self_check(args.dir, expected)
    for failure in failures:
        print(f"::error::{failure}")
    if failures:
        return 1
    print("all negative controls rejected; untouched download accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())

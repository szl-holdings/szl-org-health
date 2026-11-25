#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic, offline regression suite for the braid v2 Lake receipt wrap.

Lake-policy refusals, adapter identity over throwaway git repositories, assemble() over
made-up child outputs shaped like the receipt library's UNSIGNED-honest envelope, a
one-change-at-a-time validate_wrap tamper matrix in which the receipt digest is re-derived
from the payload bytes, the older-pins mode, real child runs of a stdlib stand-in adapter
from a fresh export under stand-in interpreters (venvs of this Python whose site-packages
hold a stand-in ``szl_receipt`` library, an older one, or none), and the create-exclusive
CLI. Some stand-ins are tampered on purpose: a pack or replace ref planted in the
checkout's ``.git``, an interpreter or ``.pth`` line that reaches into the checkout, an
envelope whose note or organ claims more, a body with an added field or a rewritten
honesty block. Every repository, adapter, library, report and output is made up here
inside temporary directories; nothing touches a network, a signing key, a live Lake or this
checkout's git state.
"""
import base64
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import py_compile
import struct
import subprocess
import sys
import tempfile
import time
from unittest import TestCase, main as unittest_main, mock
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_catalog_admission import InputError  # noqa: E402
from tools.database_braid_common import (  # noqa: E402
    NETNS_EMPTY, NETNS_NOT_REQUESTED, NETNS_UNAVAILABLE, network_namespace_state,
)
from tools.database_braid_source_census import export_tree, list_tree  # noqa: E402
from tools import database_braid_lake_receipt as lake  # noqa: E402
from tools.database_braid_lake_receipt import (  # noqa: E402
    BODY_SCHEMA, INTERPRETER_FLAGS, PROCESS_TREES, RECEIPT_PAYLOAD_TYPE, SCHEMA, UNSIGNED_NOTE,
    adapter_identity, assemble, child_limits, commit_tree, expected_body, export_matches,
    interpreter_layout, main, open_envelope, pid_namespace_prefix, run_child, tree_object_id,
    validate_policy, validate_wrap, verified_listing, wrap_report,
)

LAKE = json.loads(
    (ROOT / "governance/database_contracts/ouroboros_braid_v2.json").read_text())["lake"]
NOW = datetime(2026, 11, 19, 6, 30, tzinfo=timezone.utc)
COMMIT = "c" * 40
BLOB = "b" * 40
TURN = "braid-turn:" + "1" * 32
INPUT = "2" * 64
STORED = "3" * 64
FORGED = "1" * 64
FALSE_FLAGS = ("signature_present", "signer_identity_established", "appended_to_live_lake",
               "private_key_handled", "production_authorized")
ENVELOPE_FIELDS = ("payloadType", "payload", "signature", "signed", "organ", "keyid", "digest",
                   "algo", "note")
# The fixed text szl_lake_receipt.build_lake_receipt_body writes at szl-lake 7e19e7f.
ADAPTER_REASON = ("szl-lake stores and anchors receipts; it measures no joules -> reported "
                  "UNAVAILABLE, never fabricated.")
ADAPTER_HONESTY = {
    "asserts": "integrity/append-only provenance, NOT correctness",
    "receipt_is": "evidence trail binding this lake object (subject+input+stored-object+policy"
                  "+energy), NOT a proof the anchored content is correct",
    "chain": "the Khipu SHA3-256 hash-chain is Conjecture 2 (advisory BFT), never a proven "
             "theorem",
}
INTERPRETER = {"python": "3.12.3", "prefix": "/opt/braid-venv", "base_prefix": "/usr",
               "outside_checkout": True}


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def body(*, subject=TURN, input_digest=INPUT, stored=STORED, policy_id=None, organ=None):
    return {"schema": BODY_SCHEMA, "kind": "szl-lake-anchor", "organ": organ or LAKE["organ"],
            "subject": subject, "input_digest": "sha256:" + input_digest,
            "stored_object_digest": "sha256:" + stored,
            "policy": {"id": policy_id or LAKE["policy_id"]},
            "energy": {"status": "UNAVAILABLE", "joules": None, "reason": ADAPTER_REASON},
            "honesty": dict(ADAPTER_HONESTY)}


def envelope(value, *, raw=None):
    raw = canon(value) if raw is None else raw
    return {"payloadType": RECEIPT_PAYLOAD_TYPE,
            "payload": base64.b64encode(raw).decode("ascii"), "signature": "",
            "signed": False,
            "organ": value.get("organ") if type(value) is dict else LAKE["organ"],
            "keyid": "", "digest": hashlib.sha256(raw).hexdigest(), "algo": "UNSIGNED",
            "note": "UNSIGNED-honest: no cosign key present"}


def child_ok(value=None, *, version="0.3.1", raw=None):
    env = envelope(value if value is not None else body(), raw=raw)
    return {"python": "3.12.3", "library_version": version, "envelope": env,
            "rederived": env["digest"], "verify_ok": False, "verify_detail": "unsigned-honest",
            "state": "EMITTED", "library_origin": "INTERPRETER_PATH",
            "adapter_origin": "EXPORTED_TREE"}


def child_unavailable():
    return {"python": "3.12.3", "state": "UNAVAILABLE", "reason": "LakeReceiptUnavailable",
            "library_version": None, "library_origin": "NOT_IMPORTED"}


def observed(**changes):
    value = {"network_namespace": NETNS_UNAVAILABLE, "export_files": 3,
             "export_skipped_entries": 0, "export_rehashed_to_commit": True,
             "interpreter": dict(INTERPRETER), "process_tree": "PROCESS_GROUP_ONLY",
             "isolated_mode": True, "bytecode_writes_disabled": True,
             "pycache_prefix_fresh_and_unused": True, "adapter_loaded_from_export": True}
    value.update(changes)
    return value


def request(*, subject=TURN, input_digest=INPUT, stored=STORED, section=None):
    section = section or LAKE
    return {"subject": subject, "input_digest": input_digest, "stored_object_digest": stored,
            "policy_id": section["policy_id"], "organ": section["organ"],
            "distribution": "szl-receipt-dsse"}


def wrap_of(raw, *, section=None, req=None, obs=None):
    return assemble(deepcopy(section or LAKE), COMMIT, BLOB, req or request(), raw,
                    observed=observed() if obs is None else obs, at=NOW)


def rebody(wrap, **changes):
    """Re-encode the envelope body with ``changes``, keeping every digest self-consistent."""
    value = json.loads(base64.b64decode(wrap["envelope"]["payload"]))
    for key, item in changes.items():
        if item is KeyError:
            del value[key]
        else:
            value[key] = item
    raw = canon(value)
    wrap["envelope"]["payload"] = base64.b64encode(raw).decode("ascii")
    wrap["envelope"]["digest"] = hashlib.sha256(raw).hexdigest()
    wrap["digest_rederived_by_adapter_same_process"] = wrap["envelope"]["digest"]
    return wrap


def git(repo, *args, home):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_AUTHOR_NAME": "Synthetic Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "Synthetic Fixture",
           "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    proc = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main",
                           *args], cwd=str(repo), env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True)
    return proc.stdout


# A stand-in receipt library, installed in a stand-in interpreter's site-packages.
LIBRARY = '''import base64, hashlib, json

PAYLOAD_TYPE = "application/vnd.szl.receipt+json"


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class Receipt:
    def __init__(self, kind, body):
        self.kind, self.body = kind, body

    def digest(self):
        return hashlib.sha256(canonical_json(self.body)).hexdigest()


def sign_receipt(receipt, private_key_pem, organ="unknown", keyid=""):
    if private_key_pem:
        raise RuntimeError("the stand-in never signs")
    payload = canonical_json(receipt.body)
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode("ascii"),
            "signature": "", "signed": False, "organ": organ, "keyid": keyid,
            "digest": receipt.digest(), "algo": "UNSIGNED",
            "note": "UNSIGNED-honest: no cosign key present"}


def verify_receipt(envelope, public_key_pem=None):
    if not envelope.get("signed", False):
        return False, "unsigned-honest"
    return False, "no public key provided"
'''


def library_files(version):
    info = "szl_receipt_dsse-%s.dist-info/" % version
    return {"szl_receipt/__init__.py": LIBRARY,
            info + "METADATA": "Metadata-Version: 2.1\nName: szl-receipt-dsse\n"
                               "Version: %s\n" % version,
            info + "top_level.txt": "szl_receipt\n"}


STAND_IN = r'''"""Synthetic stand-in for the szl-lake adapter; delegates to szl_receipt."""
import base64
import hashlib
import json
import os
import sys

MODE = "@MODE@"
MARK = "@MARK@"
TEXT = @TEXT@
if MODE == "noise":
    print("import-time noise")
if MODE == "list":
    sys.stdout.write("[1, 2]")
    sys.stdout.flush()
    os._exit(0)
if MODE == "sleep":
    import time
    time.sleep(120)
if MODE == "flood":
    while True:
        sys.stdout.write("x" * 65536)
if MODE == "probe":
    import resource
    facts = {"isolated": sys.flags.isolated, "dont_write_bytecode": sys.flags.dont_write_bytecode,
             "pycache_prefix": sys.pycache_prefix, "path": list(sys.path), "cwd": os.getcwd(),
             "pid": os.getpid(),
             "file": os.path.realpath(__file__), "argv": list(sys.argv), "env": dict(os.environ),
             "limits": {name: list(resource.getrlimit(getattr(resource, name)))
                        for name in ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_FSIZE", "RLIMIT_CORE")}}
    try:
        with open(os.path.join(os.environ.get("TMPDIR", "/tmp"), "probe-write"), "wb") as stream:
            stream.write(b"x")
            stream.flush()
        facts["write_errno"] = None
    except OSError as exc:
        facts["write_errno"] = exc.errno
    with open("/proc/net/dev") as stream:
        facts["interfaces"] = sorted(line.split(":", 1)[0].strip()
                                     for line in stream.read().splitlines()[2:] if ":" in line)
    sys.stdout.write(json.dumps(facts))
    sys.stdout.flush()
    os._exit(0)


class LakeReceiptUnavailable(RuntimeError):
    pass


def _library():
    if MODE == "unavailable":
        raise LakeReceiptUnavailable("stand-in: receipt library absent")
    try:
        import szl_receipt
    except Exception as exc:
        raise LakeReceiptUnavailable("szl_receipt is not installed") from exc
    return szl_receipt


def _body(*, anchor_id, input_digest, stored_object_digest, policy_id, organ):
    value = {"schema": "szl.pcgi.receipt/szl-lake-anchor/v1", "kind": "szl-lake-anchor",
             "organ": organ, "subject": anchor_id, "input_digest": "sha256:" + input_digest,
             "stored_object_digest": "sha256:" + stored_object_digest,
             "policy": {"id": policy_id},
             "energy": {"status": "UNAVAILABLE", "joules": None, "reason": TEXT["reason"]},
             "honesty": dict(TEXT["honesty"])}
    if MODE == "extra_field":
        value["authority"] = "ALLOW"
    if MODE == "honesty":
        value["honesty"] = {"asserts": "correctness PROVEN"}
    return value


def _spaced(fields):
    return json.dumps(_body(**fields), indent=1).encode("utf-8")


def lake_receipt_body_digest(**fields):
    library = _library()
    if MODE == "drift":
        return "f" * 64
    if MODE == "forged_digest":
        return "1" * 64
    if MODE == "noncanonical":
        return hashlib.sha256(_spaced(fields)).hexdigest()
    return library.Receipt(kind="_digest", body=_body(**fields)).digest()


def emit_lake_receipt(*, private_key_pem=None, **fields):
    if private_key_pem is not None:
        os._exit(7)
    library = _library()
    if MODE == "crash":
        os._exit(1)
    if MODE == "silent":
        os._exit(0)
    envelope = library.sign_receipt(library.Receipt(kind="szl-lake-anchor", body=_body(**fields)),
                                    None, organ=fields["organ"])
    if MODE == "signed":
        envelope.update(signed=True, signature="c3ludGhldGlj", algo="ECDSA-P256-SHA256",
                        keyid="synthetic")
    if MODE == "forged_digest":
        envelope["digest"] = "1" * 64
    if MODE == "payload_type":
        envelope["payloadType"] = "application/json"
    if MODE == "note":
        envelope["note"] = "SIGNED by the estate signer; production authorized"
    if MODE == "organ":
        envelope["organ"] = "a11oy"
    if MODE == "noncanonical":
        raw = _spaced(fields)
        envelope.update(payload=base64.b64encode(raw).decode("ascii"),
                        digest=hashlib.sha256(raw).hexdigest())
    return envelope


def verify_lake_receipt(envelope):
    return _library().verify_receipt(envelope)
'''


def adapter(mode="ok", mark="COMMITTED"):
    text = repr({"reason": ADAPTER_REASON, "honesty": ADAPTER_HONESTY})
    return STAND_IN.replace("@MODE@", mode).replace("@MARK@", mark).replace("@TEXT@", text)


def make_lake(base, name, *, mode="ok", commit=True, extra=None):
    """A throwaway szl-lake checkout holding a stand-in adapter (and ``extra`` files)."""
    repo = Path(base) / name
    repo.mkdir(parents=True)
    git(repo, "init", "-q", home=base)
    (repo / "szl_lake_receipt.py").write_text(adapter(mode), encoding="utf-8")
    (repo / "README.md").write_text("synthetic lake fixture\n", encoding="utf-8")
    for path, text in (extra or {}).items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    if commit:
        git(repo, "add", "-A", home=base)
        git(repo, "commit", "-q", "-m", "synthetic fixture", home=base)
    return repo


def make_python(base, name, files=None):
    """A stand-in interpreter: a venv of this Python with ``files`` in its site-packages."""
    target = Path(base) / name
    subprocess.run([sys.executable, "-I", "-m", "venv", "--without-pip", str(target)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    site = next(target.glob("lib/python*/site-packages"))
    for path, text in (files or {}).items():
        destination = site / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    return str(target / "bin" / "python")


def git_input(repo, *args, home, stdin):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    return subprocess.run(["git", *args], cwd=str(repo), env=env, input=stdin,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout


def reachable_objects(repo, *, home, swap):
    """``(object id, type, body)`` for everything HEAD reaches, with ``swap`` bodies replaced."""
    found = []
    for line in git(repo, "rev-list", "--objects", "HEAD", home=home).decode().splitlines():
        oid = line.split(" ", 1)[0]
        kind = git(repo, "cat-file", "-t", oid, home=home).decode().strip()
        found.append((oid, kind, swap.get(oid) or git(repo, "cat-file", kind, oid, home=home)))
    return found


def plant_pack(repo, objects):
    """Write a pack of ``(object id, type, body)`` into ``repo``'s .git, newer than any other.

    Git searches its most recently used pack first and starts with the newest one, so when
    every object a listing touches is in the planted pack, an object stored there under
    another object's id is what ``git ls-tree -r`` lists, without re-hashing its content.
    """
    kinds = {"commit": 1, "tree": 2, "blob": 3}
    data, entries = b"PACK" + struct.pack(">II", 2, len(objects)), []
    for oid, kind, raw in objects:
        size, head = len(raw), bytearray()
        first = (kinds[kind] << 4) | (size & 15)
        size >>= 4
        while size:
            head.append(first | 0x80)
            first, size = size & 0x7F, size >> 7
        head.append(first)
        packed = bytes(head) + zlib.compress(raw)
        entries.append((bytes.fromhex(oid), len(data), zlib.crc32(packed) & 0xFFFFFFFF))
        data += packed
    data += hashlib.sha1(data, usedforsecurity=False).digest()
    entries.sort()
    index = b"\xfftOc" + struct.pack(">I", 2)
    index += b"".join(struct.pack(">I", sum(e[0][0] <= i for e in entries)) for i in range(256))
    index += b"".join(e[0] for e in entries) + b"".join(struct.pack(">I", e[2]) for e in entries)
    index += b"".join(struct.pack(">I", e[1]) for e in entries) + data[-20:]
    index += hashlib.sha1(index, usedforsecurity=False).digest()
    name = "pack-" + hashlib.sha1(data[:-20], usedforsecurity=False).hexdigest()
    folder = Path(repo) / ".git" / "objects" / "pack"
    (folder / (name + ".pack")).write_bytes(data)
    (folder / (name + ".idx")).write_bytes(index)
    later = time.time() + 10 ** 6
    os.utime(folder / (name + ".pack"), (later, later))


def unhardened(checkout, statement):
    """What an import straight from the checkout gives, the way the v1 child imported."""
    code = "import sys; sys.path.insert(0, %r); %s" % (str(checkout), statement)
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", code], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, cwd=str(Path(checkout).parent),
                          timeout=60, check=False)
    return proc.stdout.decode("utf-8", "replace").strip()


class Base(TestCase):
    def refuses(self, code, fn, *args, **kwargs):
        with self.assertRaises(InputError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def assert_no_authority(self, wrap):
        for flag in FALSE_FLAGS:
            self.assertIs(wrap[flag], False, flag)
        self.assertNotIn("network_used", wrap)
        self.assertNotIn("adapter_matches_commit", wrap)
        self.assertNotIn("body_digest_rederived", wrap)
        self.assertNotIn("digest_matches", wrap)
        self.assertEqual(wrap["source_tree"], "FRESH_EXPORT_OF_COMMIT")
        self.assertIs(wrap["export_rehashed_to_commit"], True)
        self.assertIs(wrap["interpreter"]["outside_checkout"], True)
        self.assertIn(wrap["child"]["process_tree"], PROCESS_TREES)
        if wrap["child"]["process_tree"] == "OWN_PID_NAMESPACE":
            self.assertEqual(wrap["network_namespace"], NETNS_EMPTY)
        self.assertIn(wrap["network_namespace"], (NETNS_EMPTY, NETNS_UNAVAILABLE))
        self.assertIs(wrap["direct_network_egress_blocked"],
                      wrap["network_namespace"] == NETNS_EMPTY)
        if wrap["envelope"] is not None:
            self.assertIs(wrap["envelope"]["signed"], False)
            self.assertEqual((wrap["envelope"]["signature"], wrap["envelope"]["keyid"]), ("", ""))
            self.assertEqual(wrap["envelope"]["note"], "UNSIGNED-honest: no cosign key present")
            self.assertEqual(wrap["envelope"]["organ"], wrap["organ"])


class ValidatePolicyTests(Base):
    def test_committed_policy_passes_and_never_appends(self):
        self.assertIs(validate_policy(LAKE), LAKE)
        self.assertIs(LAKE["append_to_live_lake"], False)

    def test_field_set_is_closed(self):
        for mutate in (lambda s: s.pop("organ"), lambda s: s.update(extra=1),
                       lambda s: s["receipt_library"].pop("version"),
                       lambda s: s["receipt_library"].update(sha256="0" * 64),
                       lambda s: s.update(receipt_library=["szl-receipt-dsse", "0.3.1"]),
                       lambda s: s.update(receipt_library=None)):
            section = deepcopy(LAKE)
            mutate(section)
            self.refuses("LAKE_POLICY_FIELDS_INVALID", validate_policy, section)
        for value in (None, [], "lake", 0):
            self.refuses("LAKE_POLICY_FIELDS_INVALID", validate_policy, value)

    def test_each_value_is_checked(self):
        cases = {
            "repository": ["other-org/szl-lake", "szl-holdings/", "szl-holdings/a b", 7, None],
            "adapter_path": ["lake.py", "sub/szl_lake_receipt.py", "szl_lake_receipt.py ", None],
            "policy_id": ["pcgi.policy/x", "szl.UPPER/case", "szl.", 1],
            "organ": ["Szl-org", "ab", "1organ", "organ_x", 3, None],
            "append_to_live_lake": [True, 0, None, "false"],
        }
        for key, values in cases.items():
            for value in values:
                section = deepcopy(LAKE)
                section[key] = value
                with self.subTest(key=key, value=value):
                    self.refuses("LAKE_POLICY_INVALID", validate_policy, section)
        for key, value in (("distribution", "szl-receipt"), ("distribution", None),
                           ("version", "0.3"), ("version", "0.3.1-rc1"), ("version", "1"),
                           ("version", 0.31), ("version", 31), ("version", "v0.3.1")):
            section = deepcopy(LAKE)
            section["receipt_library"][key] = value
            with self.subTest(key=key, value=value):
                if value == "0.3":
                    self.assertIs(validate_policy(section), section)
                else:
                    self.refuses("LAKE_POLICY_INVALID", validate_policy, section)


class AdapterIdentityTests(Base):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lake-identity-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_committed_adapter_binds_to_head(self):
        repo = make_lake(self.base, "lake")
        commit, blob = adapter_identity(repo, "szl_lake_receipt.py")
        self.assertEqual(commit, git(repo, "rev-parse", "HEAD", home=self.base).decode().strip())
        self.assertEqual(blob, git(repo, "hash-object", "szl_lake_receipt.py",
                                   home=self.base).decode().strip())

    def test_edited_adapter_is_refused(self):
        repo = make_lake(self.base, "lake")
        target = repo / "szl_lake_receipt.py"
        target.write_bytes(target.read_bytes() + b"# drift\n")
        self.refuses("LAKE_WORKTREE_DIFFERS_FROM_COMMIT", adapter_identity, repo,
                     "szl_lake_receipt.py")

    def test_deleted_or_symlinked_adapter_is_refused(self):
        repo = make_lake(self.base, "lake")
        target = repo / "szl_lake_receipt.py"
        raw = target.read_bytes()
        target.unlink()
        self.refuses("LAKE_WORKTREE_DIFFERS_FROM_COMMIT", adapter_identity, repo,
                     "szl_lake_receipt.py")
        (self.base / "copy.py").write_bytes(raw)
        os.symlink(self.base / "copy.py", target)
        self.refuses("LAKE_WORKTREE_DIFFERS_FROM_COMMIT", adapter_identity, repo,
                     "szl_lake_receipt.py")

    def test_uncommitted_or_misplaced_adapter_is_missing(self):
        repo = make_lake(self.base, "untracked", commit=False)
        git(repo, "add", "README.md", home=self.base)
        git(repo, "commit", "-q", "-m", "readme only", home=self.base)
        self.refuses("LAKE_ADAPTER_MISSING", adapter_identity, repo, "szl_lake_receipt.py")
        nested = self.base / "nested"
        nested.mkdir()
        git(nested, "init", "-q", home=self.base)
        (nested / "sub").mkdir()
        (nested / "sub/szl_lake_receipt.py").write_text("x = 1\n", encoding="utf-8")
        git(nested, "add", "-A", home=self.base)
        git(nested, "commit", "-q", "-m", "nested", home=self.base)
        self.refuses("LAKE_ADAPTER_MISSING", adapter_identity, nested, "szl_lake_receipt.py")

    def test_not_a_checkout_is_refused(self):
        plain = self.base / "plain"
        plain.mkdir()
        (plain / "szl_lake_receipt.py").write_text("x = 1\n", encoding="utf-8")
        with self.assertRaises(InputError) as caught:
            adapter_identity(plain, "szl_lake_receipt.py")
        self.assertIn(caught.exception.code, ("CENSUS_GIT_REFUSED", "CENSUS_CHECKOUT_UNAVAILABLE",
                                              "CENSUS_CHECKOUT_NOT_TOP_LEVEL"))
        self.refuses("CENSUS_CHECKOUT_UNAVAILABLE", adapter_identity, self.base / "absent",
                     "szl_lake_receipt.py")


class AssembleTests(Base):
    def test_canonical_only_when_every_check_agrees(self):
        wrap = wrap_of(child_ok())
        self.assertEqual(wrap["state"], "CANONICAL_RECEIPT_EMITTED_UNSIGNED")
        self.assertEqual(wrap["schema"], SCHEMA)
        self.assertEqual(SCHEMA, "szl.database-braid-lake-wrap/v2")
        self.assertIs(wrap["digest_rehashed_by_parent"], True)
        self.assertIs(wrap["payload_is_canonical_json_of_body"], True)
        self.assertIs(wrap["body_matches_expected_anchor_body"], True)
        self.assertIs(wrap["adapter_rederivation_matches"], True)
        self.assertEqual(wrap["digest_rederived_by_adapter_same_process"],
                         wrap["envelope"]["digest"])
        self.assertEqual(wrap["envelope"]["digest"], hashlib.sha256(canon(body())).hexdigest())
        self.assertIs(wrap["export_rehashed_to_commit"], True)
        self.assertEqual(wrap["interpreter"], INTERPRETER)
        self.assertEqual(wrap["receipt_library"], {
            "distribution": "szl-receipt-dsse", "version_required": "0.3.1",
            "version_observed": "0.3.1", "module_origin": "INTERPRETER_PATH"})
        self.assertEqual(wrap["observed_at"], NOW.isoformat())
        self.assertEqual((wrap["commit"], wrap["adapter_blob_sha1"]), (COMMIT, BLOB))
        self.assertEqual((wrap["subject"], wrap["input_digest"], wrap["stored_object_digest"]),
                         (TURN, INPUT, STORED))
        self.assertEqual((wrap["export_files"], wrap["export_skipped_entries"]), (3, 0))
        self.assertEqual((wrap["verify_ok"], wrap["verify_detail"]), (False, "unsigned-honest"))
        self.assertEqual(wrap["child"], {
            "flags": list(INTERPRETER_FLAGS), "isolated_mode": True,
            "bytecode_writes_disabled": True, "pycache_prefix_fresh_and_unused": True,
            "adapter_loaded_from_export": True, "process_tree": "PROCESS_GROUP_ONLY",
            "limits": child_limits()})
        self.assertEqual(wrap["envelope"]["algo"], "UNSIGNED")
        self.assert_no_authority(wrap)
        self.assertIs(validate_wrap(wrap, LAKE), True)

    def test_expected_body_is_the_pinned_adapter_text(self):
        made = expected_body(subject=TURN, input_digest=INPUT, stored_object_digest=STORED,
                             policy_id=LAKE["policy_id"], organ=LAKE["organ"])
        self.assertEqual(made, body())
        self.assertEqual(canon(made), lake.canonical(made))
        self.assertEqual(UNSIGNED_NOTE, "UNSIGNED-honest: no cosign key present")
        made["honesty"]["asserts"] = "edited"
        self.assertEqual(lake.ADAPTER_HONESTY, ADAPTER_HONESTY)

    def test_body_with_anything_beyond_the_adapter_body_holds(self):
        def honesty(value):
            value["honesty"] = {"asserts": "correctness PROVEN"}

        def reworded(value):
            value["honesty"]["receipt_is"] = "a proof the anchored content is correct"

        cases = {
            "authority": lambda v: v.update(authority="ALLOW"),
            "honesty_rewritten": honesty, "honesty_reworded": reworded,
            "honesty_missing": lambda v: v.pop("honesty"),
            "honesty_extra": lambda v: v["honesty"].update(signed="estate signer"),
            "energy_reason": lambda v: v["energy"].update(reason="0 J measured"),
            "energy_extra": lambda v: v["energy"].update(meter="governed-inference-meter"),
        }
        for name, mutate in cases.items():
            value = body()
            mutate(value)
            with self.subTest(name):
                wrap = wrap_of(child_ok(value))
                self.assertEqual(wrap["state"], "HOLD")
                self.assertIs(wrap["body_matches_expected_anchor_body"], False)
                self.assertIs(wrap["payload_is_canonical_json_of_body"], True)
                self.assertIs(wrap["digest_rehashed_by_parent"], True)
                self.assertIs(validate_wrap(wrap, LAKE), True)

    def test_envelope_note_and_organ_are_the_library_values(self):
        for value in ("SIGNED by the estate signer; production authorized",
                      {"signed": True, "authority": "ALLOW"}, None, "", KeyError):
            raw = child_ok()
            if value is KeyError:
                raw["envelope"].pop("note")
            else:
                raw["envelope"]["note"] = value
            with self.subTest(note=value):
                self.refuses("LAKE_ENVELOPE_NOTE_UNEXPECTED", wrap_of, raw)
        for value in ("a11oy", None, "", LAKE["organ"].upper()):
            raw = child_ok()
            raw["envelope"]["organ"] = value
            with self.subTest(organ=value):
                self.refuses("LAKE_ENVELOPE_ORGAN_MISMATCH", wrap_of, raw)

    def test_envelope_keeps_only_library_fields(self):
        raw = child_ok()
        raw["envelope"]["authorized"] = True
        raw["envelope"]["rekor_index"] = 1
        wrap = wrap_of(raw)
        self.assertEqual(set(wrap["envelope"]), set(ENVELOPE_FIELDS))
        self.assertEqual(wrap["state"], "CANONICAL_RECEIPT_EMITTED_UNSIGNED")

    def test_default_timestamp_is_utc(self):
        wrap = assemble(deepcopy(LAKE), COMMIT, BLOB, request(), child_ok(), observed=observed())
        self.assertEqual(datetime.fromisoformat(wrap["observed_at"]).utcoffset().total_seconds(),
                         0)

    def test_adapter_rederivation_difference_holds(self):
        for rederived in ("d" * 64, None, 5, "D" * 64, FORGED):
            raw = child_ok()
            raw["rederived"] = rederived
            with self.subTest(rederived=rederived):
                wrap = wrap_of(raw)
                self.assertEqual(wrap["state"], "HOLD")
                self.assertIs(wrap["adapter_rederivation_matches"], False)
                self.assertIs(wrap["digest_rehashed_by_parent"], True)
                self.assertIsNotNone(wrap["envelope"])
                self.assertIs(validate_wrap(wrap, LAKE), True)
        raw = child_ok()
        raw.pop("rederived")
        self.assertEqual(wrap_of(raw)["state"], "HOLD")

    def test_version_difference_holds(self):
        for version, recorded in (("0.3.0", "0.3.0"), ("0.3.1.post1", "0.3.1.post1"),
                                  ("", None), (31, None), (None, None), ("0.3.1 ", None)):
            raw = child_ok(version=version)
            with self.subTest(version=version):
                wrap = wrap_of(raw)
                self.assertEqual(wrap["state"], "HOLD")
                self.assertIs(wrap["adapter_rederivation_matches"], True)
                self.assertEqual(wrap["receipt_library"]["version_observed"], recorded)
        raw = child_ok()
        raw.pop("library_version")
        wrap = wrap_of(raw)
        self.assertEqual((wrap["state"], wrap["receipt_library"]["version_observed"]),
                         ("HOLD", None))

    def test_verify_result_must_be_unsigned_honest(self):
        for key, value, recorded in (("verify_detail", "signature-ok", "signature-ok"),
                                     ("verify_detail", None, None),
                                     ("verify_detail", "x" * 61, None),
                                     ("verify_detail", "<ok>", None),
                                     ("verify_ok", True, True), ("verify_ok", 0, None),
                                     ("verify_ok", None, None)):
            raw = child_ok()
            raw[key] = value
            with self.subTest(key=key, value=value):
                wrap = wrap_of(raw)
                self.assertEqual(wrap["state"], "HOLD")
                self.assertEqual(wrap[key], recorded)
                self.assertIs(validate_wrap(wrap, LAKE), True)

    def test_library_from_outside_the_interpreter_holds(self):
        for origin, recorded in (("EXPORTED_TREE", "EXPORTED_TREE"), ("UNLOCATED", "UNLOCATED"),
                                 ("NOT_IMPORTED", "NOT_IMPORTED"), ("SITE", "UNLOCATED"),
                                 (None, "UNLOCATED")):
            raw = child_ok()
            raw["library_origin"] = origin
            with self.subTest(origin=origin):
                wrap = wrap_of(raw)
                self.assertEqual(wrap["state"], "HOLD")
                self.assertEqual(wrap["receipt_library"]["module_origin"], recorded)

    def test_payload_that_is_not_canonical_json_holds(self):
        spaced = json.dumps(body(), indent=1).encode("utf-8")
        wrap = wrap_of(child_ok(raw=spaced))
        self.assertEqual(wrap["state"], "HOLD")
        self.assertIs(wrap["payload_is_canonical_json_of_body"], False)
        self.assertIs(wrap["adapter_rederivation_matches"], True)
        self.assertIs(validate_wrap(wrap, LAKE), True)

    def test_child_that_could_not_emit_is_unavailable_not_zero(self):
        for raw in (child_unavailable(), {}, {"state": "EMITTED"},
                    {"state": "EMITTED", "envelope": None}, {"state": "EMITTED", "envelope": [1]},
                    {**child_ok(), "state": "UNAVAILABLE"}, {**child_ok(), "state": "emitted"}):
            with self.subTest(raw=sorted(raw)):
                wrap = wrap_of(raw, obs=observed(adapter_loaded_from_export=None))
                self.assertEqual(wrap["state"], "UNAVAILABLE")
                self.assertIsNone(wrap["envelope"])
                self.assertIs(wrap["digest_rehashed_by_parent"], False)
                for field in ("payload_is_canonical_json_of_body",
                              "body_matches_expected_anchor_body",
                              "digest_rederived_by_adapter_same_process", "verify_ok",
                              "verify_detail"):
                    self.assertIsNone(wrap[field], field)
                self.assertIs(wrap["adapter_rederivation_matches"], False)
                self.assert_no_authority(wrap)
                self.assertIs(validate_wrap(wrap, LAKE), True)

    def test_unavailable_child_with_a_signed_envelope_is_still_unavailable(self):
        raw = child_ok()
        raw["state"] = "UNAVAILABLE"
        raw["envelope"].update(signed=True, signature="c2ln", algo="ECDSA-P256")
        wrap = wrap_of(raw)
        self.assertEqual(wrap["state"], "UNAVAILABLE")
        self.assertIsNone(wrap["envelope"])

    def test_child_output_must_be_an_object(self):
        for raw in (None, [], "EMITTED", 0):
            self.refuses("LAKE_CHILD_OUTPUT_INVALID", wrap_of, raw)

    def test_signature_claims_are_refused(self):
        for key, value in (("signed", True), ("signed", 0), ("signed", None), ("signed", "false"),
                           ("signature", "c2ln"), ("signature", None), ("algo", "ECDSA-P256"),
                           ("algo", "unsigned"), ("signed", KeyError), ("signature", KeyError),
                           ("algo", KeyError)):
            raw = child_ok()
            if value is KeyError:
                raw["envelope"].pop(key)
            else:
                raw["envelope"][key] = value
            with self.subTest(key=key, value=value):
                self.refuses("LAKE_UNEXPECTED_SIGNATURE_CLAIM", wrap_of, raw)

    def test_keyid_or_malformed_digest_is_refused(self):
        for key, value in (("keyid", "synthetic-key"), ("keyid", None), ("digest", "A" * 64),
                           ("digest", "sha256:" + "a" * 64), ("digest", None)):
            raw = child_ok()
            raw["envelope"][key] = value
            raw["rederived"] = raw["envelope"]["digest"]
            with self.subTest(key=key, value=value):
                self.refuses("LAKE_UNEXPECTED_SIGNATURE_CLAIM", wrap_of, raw)

    def test_parent_rehashes_the_payload_instead_of_trusting_the_child(self):
        # The v1 wrap compared two child-reported digests with each other and accepted this.
        raw = child_ok()
        raw["envelope"]["digest"] = raw["rederived"] = FORGED
        self.refuses("LAKE_ENVELOPE_DIGEST_MISMATCH", wrap_of, raw)
        raw = child_ok()
        other = hashlib.sha256(canon(body(subject="braid-turn:" + "9" * 32))).hexdigest()
        raw["envelope"]["digest"] = raw["rederived"] = other
        self.refuses("LAKE_ENVELOPE_DIGEST_MISMATCH", wrap_of, raw)

    def test_payload_type_must_be_the_library_value(self):
        for value in ("application/json", "application/vnd.in-toto+json", None, ""):
            raw = child_ok()
            raw["envelope"]["payloadType"] = value
            with self.subTest(value=value):
                self.refuses("LAKE_PAYLOAD_TYPE_UNEXPECTED", wrap_of, raw)

    def test_body_must_bind_the_request(self):
        cases = [
            body(subject="braid-turn:" + "9" * 32), body(input_digest="9" * 64),
            body(stored="9" * 64), body(policy_id="szl.pcgi.policy/other/v1"),
            body(organ="szl-lake"), {**body(), "schema": "szl.pcgi.receipt/other/v1"},
            {**body(), "kind": "szl-other-anchor"},
            {**body(), "input_digest": INPUT},
            {**body(), "stored_object_digest": "sha512:" + STORED},
            {**body(), "policy": {"id": LAKE["policy_id"], "version": 2}},
            {**body(), "energy": {"status": "UNAVAILABLE", "joules": 0}},
            {**body(), "energy": {"status": "MEASURED", "joules": 1}},
            {**body(), "energy": {"status": "UNAVAILABLE"}},
            {**body(), "energy": None}, [body()], "body",
        ]
        missing = body()
        missing.pop("energy")
        cases.append(missing)
        for value in cases:
            label = value if type(value) is not dict else sorted(value.items(), key=str)[:2]
            with self.subTest(value=label):
                self.refuses("LAKE_BODY_BINDING_MISMATCH", wrap_of, child_ok(value))

    def test_undecodable_payload_is_refused(self):
        for raw_payload in (b"not json", b'{"a": 1.5}', b'{"a": 1, "a": 2}', b'{"a": NaN}',
                            b"\xff\xfe"):
            raw = child_ok(raw=raw_payload)
            with self.subTest(payload=raw_payload):
                self.refuses("LAKE_ENVELOPE_PAYLOAD_INVALID", wrap_of, raw)
        for payload in ("not base64!", None, 7, ""):
            raw = child_ok()
            raw["envelope"]["payload"] = payload
            with self.subTest(payload=payload):
                self.refuses("LAKE_ENVELOPE_PAYLOAD_INVALID", wrap_of, raw)
        raw = child_ok()
        raw["envelope"]["payload"] = base64.b64encode(b"stale digest").decode("ascii")
        self.refuses("LAKE_ENVELOPE_DIGEST_MISMATCH", wrap_of, raw)

    def test_policy_and_request_are_checked(self):
        section = deepcopy(LAKE)
        section["append_to_live_lake"] = True
        self.refuses("LAKE_POLICY_INVALID", wrap_of, child_ok(), section=section)
        for req in (request(subject="Braid-Turn:" + "1" * 32),
                    request(input_digest="sha256:" + INPUT), request(stored="3" * 63)):
            self.refuses("LAKE_WRAP_FIELDS_INVALID", wrap_of, child_unavailable(), req=req,
                         obs=observed(adapter_loaded_from_export=None))
        self.refuses("LAKE_WRAP_BINDING_INVALID", assemble, deepcopy(LAKE), "c" * 39, BLOB,
                     request(), child_unavailable(), observed=observed(), at=NOW)
        self.refuses("LAKE_WRAP_BINDING_INVALID", assemble, deepcopy(LAKE), COMMIT, "B" * 40,
                     request(), child_unavailable(), observed=observed(), at=NOW)

    def test_observations_are_required_and_checked(self):
        for key in ("isolated_mode", "bytecode_writes_disabled",
                    "pycache_prefix_fresh_and_unused"):
            for value in (False, None, 1):
                with self.subTest(key=key, value=value):
                    self.refuses("LAKE_CHILD_NOT_ISOLATED", wrap_of, child_ok(),
                                 obs=observed(**{key: value}))
        for value in (False, None, 1, "EXPORTED_TREE"):
            with self.subTest(adapter_loaded_from_export=value):
                self.refuses("LAKE_ADAPTER_NOT_FROM_EXPORT", wrap_of, child_ok(),
                             obs=observed(adapter_loaded_from_export=value))
        self.refuses("LAKE_ADAPTER_NOT_FROM_EXPORT", wrap_of, child_unavailable(),
                     obs=observed(adapter_loaded_from_export=False))
        for value in (NETNS_NOT_REQUESTED, "ISOLATED", None):
            with self.subTest(network_namespace=value):
                self.refuses("LAKE_NETWORK_CLAIM_INVALID", wrap_of, child_ok(),
                             obs=observed(network_namespace=value))
        for obs in ([], {**observed(), "extra": 1}, observed(export_files=0),
                    observed(export_skipped_entries=-1), observed(interpreter=None),
                    observed(interpreter=dict(INTERPRETER, extra=1)),
                    observed(interpreter=dict(INTERPRETER, prefix="venv")),
                    observed(interpreter=dict(INTERPRETER, base_prefix=None)),
                    observed(interpreter=dict(INTERPRETER, python="3.12")),
                    observed(process_tree="CGROUP"),
                    # A PID namespace is only nested inside an observed empty namespace.
                    observed(process_tree="OWN_PID_NAMESPACE")):
            with self.subTest(obs=obs):
                self.refuses("LAKE_OBSERVATION_INVALID", wrap_of, child_ok(), obs=obs)
        for value in (False, None, 1):
            with self.subTest(outside_checkout=value):
                self.refuses("LAKE_INTERPRETER_INSIDE_CHECKOUT", wrap_of, child_ok(),
                             obs=observed(interpreter=dict(INTERPRETER, outside_checkout=value)))
            with self.subTest(export_rehashed_to_commit=value):
                self.refuses("LAKE_EXPORT_MISMATCH", wrap_of, child_ok(),
                             obs=observed(export_rehashed_to_commit=value))
        nested = wrap_of(child_ok(), obs=observed(network_namespace=NETNS_EMPTY,
                                                  process_tree="OWN_PID_NAMESPACE"))
        self.assertEqual(nested["child"]["process_tree"], "OWN_PID_NAMESPACE")
        self.assertIs(validate_wrap(nested, LAKE), True)

    def test_network_namespace_is_recorded_as_observed(self):
        empty = wrap_of(child_ok(), obs=observed(network_namespace=NETNS_EMPTY))
        self.assertEqual(empty["network_namespace"], NETNS_EMPTY)
        self.assertIs(empty["direct_network_egress_blocked"], True)
        open_host = wrap_of(child_ok())
        self.assertIs(open_host["direct_network_egress_blocked"], False)

    def test_open_envelope_returns_the_exact_payload_bytes(self):
        env = envelope(body())
        value, raw = open_envelope(env)
        self.assertEqual(value, body())
        self.assertEqual(raw, canon(body()))


class ValidateWrapTests(Base):
    def setUp(self):
        self.good = wrap_of(child_ok())
        self.hold = wrap_of(child_ok(version="0.3.0"))
        self.unavailable = wrap_of(child_unavailable(),
                                   obs=observed(adapter_loaded_from_export=None))

    def mutated(self, source, mutate):
        wrap = deepcopy(source)
        mutate(wrap)
        return wrap

    def test_baselines_pass(self):
        for wrap in (self.good, self.hold, self.unavailable):
            self.assertIs(validate_wrap(wrap, LAKE), True)
            self.assertIs(validate_wrap(wrap, LAKE, require_current_pins=False), True)

    def test_field_set_is_closed(self):
        for wrap in (self.good, self.unavailable):
            for mutate in (lambda w: w.pop("state"), lambda w: w.update(signed=False),
                           lambda w: w.update(network_used=False),
                           lambda w: w.pop("production_authorized"),
                           lambda w: w["receipt_library"].pop("distribution"),
                           lambda w: w["receipt_library"].update(sha256="0" * 64),
                           lambda w: w.update(receipt_library=None)):
                self.refuses("LAKE_WRAP_FIELDS_INVALID", validate_wrap,
                             self.mutated(wrap, mutate), LAKE)
        for value in (None, [], "wrap"):
            self.refuses("LAKE_WRAP_FIELDS_INVALID", validate_wrap, value, LAKE)

    def test_other_schemas_are_named_not_guessed(self):
        for value in ("szl.database-braid-lake-wrap/v1", "szl.database-braid-lake-wrap/v3",
                      None):
            for pins in (True, False):
                with self.subTest(schema=value, pins=pins):
                    self.refuses("LAKE_WRAP_SCHEMA_UNSUPPORTED", validate_wrap,
                                 self.mutated(self.good, lambda w: w.update(schema=value)),
                                 LAKE, require_current_pins=pins)
        self.refuses("LAKE_WRAP_SCHEMA_UNSUPPORTED", validate_wrap,
                     self.mutated(self.good, lambda w: w.pop("schema")), LAKE)

    def test_binding_field_shapes(self):
        for key, value in (("repository", "other-org/szl-lake"), ("commit", "C" * 40),
                           ("commit", "c" * 41), ("commit", None),
                           ("adapter_path", "other.py"), ("adapter_blob_sha1", "b" * 64),
                           ("adapter_blob_sha1", 1), ("source_tree", "WORKING_TREE"),
                           ("source_tree", True), ("policy_id", "pcgi/other"),
                           ("organ", "Szl_Lake")):
            for wrap in (self.good, self.unavailable):
                for pins in (True, False):
                    with self.subTest(key=key, value=value, state=wrap["state"], pins=pins):
                        self.refuses("LAKE_WRAP_BINDING_INVALID", validate_wrap,
                                     self.mutated(wrap, lambda w: w.update({key: value})), LAKE,
                                     require_current_pins=pins)
        for key, value in (("distribution", "szl-receipt"), ("version_required", "0.3.1-rc1"),
                           ("version_required", None)):
            with self.subTest(key=key, value=value):
                self.refuses("LAKE_WRAP_BINDING_INVALID", validate_wrap,
                             self.mutated(self.good, lambda w: w["receipt_library"].update(
                                 {key: value})), LAKE, require_current_pins=False)

    def test_current_pins_are_required_by_default(self):
        for key, value in (("repository", "szl-holdings/szl-lake-old"),
                           ("policy_id", "szl.pcgi.policy/other/v1"), ("organ", "szl-lake")):
            with self.subTest(key=key):
                self.refuses("LAKE_WRAP_PIN_MISMATCH", validate_wrap,
                             self.mutated(self.unavailable, lambda w: w.update({key: value})),
                             LAKE)
        self.refuses("LAKE_WRAP_PIN_MISMATCH", validate_wrap,
                     self.mutated(self.good, lambda w: w["receipt_library"].update(
                         version_required="0.3.0")), LAKE)

    def test_authority_flags_must_be_false(self):
        for flag in FALSE_FLAGS:
            for value in (True, 0, None, "false", 0.0):
                for wrap in (self.good, self.unavailable):
                    with self.subTest(flag=flag, value=value):
                        self.refuses("LAKE_FALSE_AUTHORITY_CLAIM", validate_wrap,
                                     self.mutated(wrap, lambda w: w.update({flag: value})), LAKE)

    def test_subject_digest_and_library_shapes(self):
        for key, value in (("subject", "short"), ("subject", "Braid-Turn:" + "1" * 32),
                           ("subject", 1), ("input_digest", "sha256:" + INPUT),
                           ("input_digest", "A" * 64), ("stored_object_digest", "3" * 63),
                           ("stored_object_digest", None), ("export_files", 0),
                           ("export_files", "3"), ("export_skipped_entries", -1)):
            with self.subTest(key=key, value=value):
                self.refuses("LAKE_WRAP_FIELDS_INVALID", validate_wrap,
                             self.mutated(self.unavailable, lambda w: w.update({key: value})),
                             LAKE)
        for key, value in (("version_observed", 0.31), ("version_observed", "0.3.1 "),
                           ("module_origin", "SITE_PACKAGES"), ("module_origin", None)):
            with self.subTest(key=key, value=value):
                self.refuses("LAKE_WRAP_FIELDS_INVALID", validate_wrap,
                             self.mutated(self.good, lambda w: w["receipt_library"].update(
                                 {key: value})), LAKE)

    def test_timestamp_is_checked(self):
        for value in ("2026-11-19T06:30:00", "later", None, 1):
            with self.subTest(value=value):
                self.refuses("LAKE_TIMESTAMP_INVALID", validate_wrap,
                             self.mutated(self.good, lambda w: w.update(observed_at=value)), LAKE)

    def test_isolation_is_never_claimed_without_an_empty_namespace(self):
        for changes in ({"direct_network_egress_blocked": True},
                        {"network_namespace": NETNS_NOT_REQUESTED},
                        {"network_namespace": NETNS_EMPTY}):
            with self.subTest(changes=changes):
                self.refuses("LAKE_NETWORK_CLAIM_INVALID", validate_wrap,
                             self.mutated(self.good, lambda w: w.update(changes)), LAKE)
        empty = wrap_of(child_ok(), obs=observed(network_namespace=NETNS_EMPTY))
        self.assertIs(validate_wrap(empty, LAKE), True)
        self.refuses("LAKE_NETWORK_CLAIM_INVALID", validate_wrap,
                     self.mutated(empty, lambda w: w.update(direct_network_egress_blocked=False)),
                     LAKE)

    def test_child_record_is_checked(self):
        for mutate in (lambda w: w["child"].update(isolated_mode=False),
                       lambda w: w["child"].update(bytecode_writes_disabled=None),
                       lambda w: w["child"].update(pycache_prefix_fresh_and_unused=1),
                       lambda w: w["child"].update(adapter_loaded_from_export=False),
                       lambda w: w["child"].update(adapter_loaded_from_export=None),
                       lambda w: w["child"].update(sandbox="MICROVM"),
                       lambda w: w["child"]["limits"].update(cpu_seconds=-1),
                       lambda w: w["child"]["limits"].pop("cpu_seconds"),
                       lambda w: w["child"].update(flags="-I -B")):
            for pins in (True, False):
                with self.subTest(pins=pins):
                    self.refuses("LAKE_CHILD_RECORD_INVALID", validate_wrap,
                                 self.mutated(self.good, mutate), LAKE,
                                 require_current_pins=pins)

    def test_state_vocabulary_is_closed(self):
        for value in ("PASS", "SIGNED", "ALLOW", "canonical_receipt_emitted_unsigned", None, 1):
            self.refuses("LAKE_STATE_INVALID", validate_wrap,
                         self.mutated(self.good, lambda w: w.update(state=value)), LAKE)

    def test_unavailable_carries_no_receipt_and_no_match(self):
        for key, value in (("envelope", deepcopy(self.good["envelope"])), ("envelope", {}),
                           ("digest_rederived_by_adapter_same_process", "a" * 64),
                           ("digest_rederived_by_adapter_same_process", ""),
                           ("digest_rehashed_by_parent", True),
                           ("payload_is_canonical_json_of_body", True),
                           ("body_matches_expected_anchor_body", True),
                           ("body_matches_expected_anchor_body", False),
                           ("adapter_rederivation_matches", True),
                           ("adapter_rederivation_matches", 0), ("verify_ok", False),
                           ("verify_detail", "unsigned-honest")):
            with self.subTest(key=key, value=value):
                self.refuses("LAKE_UNAVAILABLE_NOT_UNKNOWN", validate_wrap,
                             self.mutated(self.unavailable, lambda w: w.update({key: value})),
                             LAKE)

    def test_emitted_states_need_the_exact_envelope(self):
        for wrap in (self.good, self.hold):
            for mutate in (lambda w: w.update(envelope=None), lambda w: w["envelope"].pop("note"),
                           lambda w: w["envelope"].update(rekor_index=1),
                           lambda w: w.update(envelope=[])):
                self.refuses("LAKE_ENVELOPE_FIELDS_INVALID", validate_wrap,
                             self.mutated(wrap, mutate), LAKE)

    def test_envelope_signature_claims(self):
        for key, value in (("signed", True), ("signed", 0), ("signature", "c2ln"),
                           ("algo", "ECDSA-P256"), ("keyid", "k"), ("keyid", None),
                           ("digest", "A" * 64), ("digest", None)):
            for wrap in (self.good, self.hold):
                with self.subTest(key=key, value=value, state=wrap["state"]):
                    self.refuses("LAKE_UNEXPECTED_SIGNATURE_CLAIM", validate_wrap,
                                 self.mutated(wrap, lambda w: w["envelope"].update({key: value})),
                                 LAKE)

    def test_digest_is_rederived_from_the_payload_bytes(self):
        def forged(w):
            w["envelope"]["digest"] = FORGED
            w["digest_rederived_by_adapter_same_process"] = FORGED

        for wrap in (self.good, self.hold):
            for pins in (True, False):
                with self.subTest(state=wrap["state"], pins=pins):
                    self.refuses("LAKE_ENVELOPE_DIGEST_MISMATCH", validate_wrap,
                                 self.mutated(wrap, forged), LAKE, require_current_pins=pins)

        def payload_swapped(w):
            other = canon(body(subject="braid-turn:" + "9" * 32))
            w["envelope"]["payload"] = base64.b64encode(other).decode("ascii")

        self.refuses("LAKE_ENVELOPE_DIGEST_MISMATCH", validate_wrap,
                     self.mutated(self.good, payload_swapped), LAKE)

    def test_payload_type_is_checked(self):
        self.refuses("LAKE_PAYLOAD_TYPE_UNEXPECTED", validate_wrap,
                     self.mutated(self.good, lambda w: w["envelope"].update(
                         payloadType="application/json")), LAKE)

    def test_envelope_note_and_organ_are_bound(self):
        for wrap in (self.good, self.hold):
            for pins in (True, False):
                for note in ("SIGNED by the estate signer; production authorized",
                             {"signed": True, "authority": "ALLOW"}, None):
                    with self.subTest(note=note, state=wrap["state"], pins=pins):
                        self.refuses("LAKE_ENVELOPE_NOTE_UNEXPECTED", validate_wrap,
                                     self.mutated(wrap, lambda w: w["envelope"].update(
                                         note=note)), LAKE, require_current_pins=pins)
                for organ in ("a11oy", None):
                    with self.subTest(organ=organ, state=wrap["state"], pins=pins):
                        self.refuses("LAKE_ENVELOPE_ORGAN_MISMATCH", validate_wrap,
                                     self.mutated(wrap, lambda w: w["envelope"].update(
                                         organ=organ)), LAKE, require_current_pins=pins)

    def test_body_beyond_the_adapter_body_cannot_stay_canonical(self):
        # The reviewer's forgery: a self-consistent digest over an added authority field and
        # a rewritten honesty block was accepted as CANONICAL_RECEIPT_EMITTED_UNSIGNED.
        changes = {"authority": "ALLOW", "honesty": {"asserts": "correctness PROVEN"}}
        for pins in (True, False):
            with self.subTest(pins=pins):
                forged = rebody(deepcopy(self.good), **changes)
                self.refuses("LAKE_DERIVED_FIELD_MISMATCH", validate_wrap, forged, LAKE,
                             require_current_pins=pins)
                forged["body_matches_expected_anchor_body"] = False
                self.refuses("LAKE_STATE_DRIFT", validate_wrap, forged, LAKE,
                             require_current_pins=pins)
                forged["state"] = "HOLD"
                self.assertIs(validate_wrap(forged, LAKE, require_current_pins=pins), True)
        for key, value in (("honesty", KeyError), ("honesty", dict(ADAPTER_HONESTY, chain="x")),
                           ("energy", {"status": "UNAVAILABLE", "joules": None,
                                       "reason": "0 J"}), ("signed_by", "estate")):
            with self.subTest(key=key):
                self.refuses("LAKE_DERIVED_FIELD_MISMATCH", validate_wrap,
                             rebody(deepcopy(self.good), **{key: value}), LAKE)

    def test_body_is_decoded_independently(self):
        for key, value in (("subject", "braid-turn:" + "9" * 32),
                           ("input_digest", "sha256:" + "9" * 64), ("input_digest", INPUT),
                           ("stored_object_digest", "sha256:" + "9" * 64),
                           ("policy", {"id": "szl.pcgi.policy/other/v1"}),
                           ("policy", LAKE["policy_id"]), ("organ", "szl-lake"),
                           ("schema", "szl.pcgi.receipt/other/v1"), ("kind", "other"),
                           ("energy", {"status": "UNAVAILABLE", "joules": 0}),
                           ("energy", {"status": "MEASURED", "joules": None}),
                           ("energy", {"status": "UNAVAILABLE"}), ("energy", "UNAVAILABLE"),
                           ("energy", KeyError), ("subject", KeyError)):
            for source in (self.good, self.hold):
                for pins in (True, False):
                    with self.subTest(key=key, value=value, state=source["state"], pins=pins):
                        wrap = rebody(deepcopy(source), **{key: value})
                        self.refuses("LAKE_BODY_BINDING_MISMATCH", validate_wrap, wrap, LAKE,
                                     require_current_pins=pins)

    def test_wrap_fields_cannot_follow_a_substituted_body(self):
        wrap = rebody(deepcopy(self.good), subject="braid-turn:" + "9" * 32)
        wrap["subject"] = "braid-turn:" + "8" * 32
        self.refuses("LAKE_BODY_BINDING_MISMATCH", validate_wrap, wrap, LAKE)
        wrap = deepcopy(self.good)
        wrap["input_digest"] = "9" * 64
        self.refuses("LAKE_BODY_BINDING_MISMATCH", validate_wrap, wrap, LAKE)

    def test_payload_must_decode(self):
        for payload in ("@@", None, ""):
            self.refuses("LAKE_ENVELOPE_PAYLOAD_INVALID", validate_wrap,
                         self.mutated(self.good, lambda w: w["envelope"].update(payload=payload)),
                         LAKE)

        def float_body(w):
            raw = b"[1.5]"
            w["envelope"].update(payload=base64.b64encode(raw).decode("ascii"),
                                 digest=hashlib.sha256(raw).hexdigest())

        self.refuses("LAKE_ENVELOPE_PAYLOAD_INVALID", validate_wrap,
                     self.mutated(self.good, float_body), LAKE)

    def test_derived_fields_are_rederived(self):
        for mutate in (lambda w: w.update(digest_rehashed_by_parent=False),
                       lambda w: w.update(digest_rehashed_by_parent=1),
                       lambda w: w.update(payload_is_canonical_json_of_body=False),
                       lambda w: w.update(payload_is_canonical_json_of_body=None),
                       lambda w: w.update(body_matches_expected_anchor_body=False),
                       lambda w: w.update(body_matches_expected_anchor_body=None),
                       lambda w: w.update(body_matches_expected_anchor_body=1),
                       lambda w: w.update(adapter_rederivation_matches=False),
                       lambda w: w.update(adapter_rederivation_matches=1),
                       lambda w: w.update(digest_rederived_by_adapter_same_process="d" * 64),
                       lambda w: w.update(digest_rederived_by_adapter_same_process="D" * 64),
                       lambda w: w.update(digest_rederived_by_adapter_same_process=None),
                       lambda w: w.update(verify_ok=0),
                       lambda w: w.update(verify_detail="<unsigned>")):
            self.refuses("LAKE_DERIVED_FIELD_MISMATCH", validate_wrap,
                         self.mutated(self.good, mutate), LAKE)

    def test_canonical_state_cannot_drift(self):
        for mutate in (lambda w: w["receipt_library"].update(version_observed="0.3.0"),
                       lambda w: w["receipt_library"].update(version_observed=None),
                       lambda w: w["receipt_library"].update(module_origin="EXPORTED_TREE"),
                       lambda w: w["receipt_library"].update(module_origin="NOT_IMPORTED"),
                       lambda w: w.update(verify_detail="signature-ok"),
                       lambda w: w.update(verify_detail=None), lambda w: w.update(verify_ok=True),
                       lambda w: w.update(verify_ok=None),
                       lambda w: w.update(adapter_rederivation_matches=False,
                                          digest_rederived_by_adapter_same_process="d" * 64)):
            self.refuses("LAKE_STATE_DRIFT", validate_wrap, self.mutated(self.good, mutate), LAKE)

    def test_hold_cannot_hide_a_canonical_receipt(self):
        self.refuses("LAKE_STATE_DRIFT", validate_wrap,
                     self.mutated(self.good, lambda w: w.update(state="HOLD")), LAKE)
        promoted = self.mutated(self.hold,
                                lambda w: w.update(state="CANONICAL_RECEIPT_EMITTED_UNSIGNED"))
        self.refuses("LAKE_STATE_DRIFT", validate_wrap, promoted, LAKE)

    def test_unavailable_cannot_relabel_an_emitted_receipt(self):
        self.refuses("LAKE_UNAVAILABLE_NOT_UNKNOWN", validate_wrap,
                     self.mutated(self.good, lambda w: w.update(state="UNAVAILABLE")), LAKE)

    def test_policy_is_revalidated(self):
        section = deepcopy(LAKE)
        section["receipt_library"]["distribution"] = "other"
        self.refuses("LAKE_POLICY_INVALID", validate_wrap, self.good, section)
        self.refuses("LAKE_POLICY_INVALID", validate_wrap, self.good, section,
                     require_current_pins=False)
        other = deepcopy(LAKE)
        other["organ"] = "other-organ"
        self.refuses("LAKE_WRAP_PIN_MISMATCH", validate_wrap, self.good, other)


class OlderPinsTests(Base):
    """A previous turn's wrap made under the pins of its own time still validates structurally."""

    def setUp(self):
        self.older = deepcopy(LAKE)
        self.older.update(repository="szl-holdings/szl-lake-archive",
                          policy_id="szl.pcgi.policy/szl-lake-append-only-honest/v0",
                          organ="szl-org-health-braid-old")
        self.older["receipt_library"]["version"] = "0.3.0"
        value = body(policy_id=self.older["policy_id"], organ=self.older["organ"])
        self.wrap = assemble(deepcopy(self.older), COMMIT, BLOB, request(section=self.older),
                             child_ok(value, version="0.3.0"), observed=observed(), at=NOW)

    def test_older_pins_validate_structurally_and_are_refused_as_current(self):
        self.assertEqual(self.wrap["state"], "CANONICAL_RECEIPT_EMITTED_UNSIGNED")
        self.assertIs(validate_wrap(self.wrap, LAKE, require_current_pins=False), True)
        self.refuses("LAKE_WRAP_PIN_MISMATCH", validate_wrap, self.wrap, LAKE)
        self.assertIs(validate_wrap(self.wrap, self.older), True)

    def test_older_tool_limits_are_accepted_only_without_current_pins(self):
        wrap = deepcopy(self.wrap)
        wrap["child"]["limits"]["address_space_bytes"] = 4294967296
        wrap["child"]["flags"] = ["-I", "-B"]
        self.assertIs(validate_wrap(wrap, LAKE, require_current_pins=False), True)
        self.refuses("LAKE_CHILD_RECORD_INVALID", validate_wrap, wrap, self.older)

    def test_older_pins_relax_no_digest_body_or_state_check(self):
        def forged(w):
            w["envelope"]["digest"] = w["digest_rederived_by_adapter_same_process"] = FORGED

        checks = (("LAKE_ENVELOPE_DIGEST_MISMATCH", forged),
                  ("LAKE_BODY_BINDING_MISMATCH",
                   lambda w: w.update(policy_id="szl.pcgi.policy/szl-lake-append-only-honest/v1")),
                  ("LAKE_BODY_BINDING_MISMATCH", lambda w: w.update(organ=LAKE["organ"])),
                  ("LAKE_STATE_DRIFT", lambda w: w["receipt_library"].update(
                      version_observed="0.3.1")),
                  ("LAKE_FALSE_AUTHORITY_CLAIM", lambda w: w.update(signature_present=True)),
                  ("LAKE_UNEXPECTED_SIGNATURE_CLAIM", lambda w: w["envelope"].update(
                      signed=True)))
        for code, mutate in checks:
            wrap = deepcopy(self.wrap)
            mutate(wrap)
            with self.subTest(code=code):
                self.refuses(code, validate_wrap, wrap, LAKE, require_current_pins=False)


class ChildRunTests(Base):
    """Real children over stand-in adapters exported from throwaway commits."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="lake-child-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name)
        cls.lib = make_python(cls.base, "lib-python", library_files("0.3.1"))
        cls.old = make_python(cls.base, "old-python", library_files("0.3.0"))
        cls.bare = make_python(cls.base, "bare-python")
        cls.repos = {mode: make_lake(cls.base, mode, mode=mode) for mode in (
            "ok", "drift", "unavailable", "signed", "crash", "silent", "noise", "list",
            "forged_digest", "payload_type", "noncanonical", "probe", "extra_field", "honesty",
            "note", "organ")}

    def wrap(self, name, *, python=None, **overrides):
        kwargs = {"subject": TURN, "input_digest": INPUT, "stored_object_digest": STORED,
                  "python": python or self.lib, "at": NOW, **overrides}
        return wrap_report(deepcopy(LAKE), self.repos[name], **kwargs)

    def test_canonical_unsigned_receipt_from_the_exported_adapter(self):
        wrap = self.wrap("ok")
        self.assertEqual(wrap["state"], "CANONICAL_RECEIPT_EMITTED_UNSIGNED")
        self.assertEqual(wrap["commit"], git(self.repos["ok"], "rev-parse", "HEAD",
                                             home=self.base).decode().strip())
        self.assertEqual(wrap["verify_detail"], "unsigned-honest")
        decoded = json.loads(base64.b64decode(wrap["envelope"]["payload"]))
        self.assertEqual(hashlib.sha256(canon(decoded)).hexdigest(), wrap["envelope"]["digest"])
        self.assertEqual(decoded["energy"]["joules"], None)
        self.assertEqual(wrap["receipt_library"]["module_origin"], "INTERPRETER_PATH")
        self.assertEqual(wrap["receipt_library"]["version_observed"], "0.3.1")
        self.assertEqual(wrap["export_files"], 2)
        self.assertEqual(wrap["network_namespace"], network_namespace_state())
        self.assert_no_authority(wrap)
        self.assertIs(validate_wrap(wrap, LAKE), True)

    def test_child_sees_only_a_fresh_export_with_isolating_flags_and_limits(self):
        env = {"PYTHONPATH": "/nonexistent", "HTTPS_PROXY": "http://proxy.invalid:3128",
               "SZL_COSIGN_PRIVATE_PEM": "sentinel", "GITHUB_TOKEN": "sentinel"}
        with mock.patch.dict(os.environ, env):
            raw, seen = run_child(self.repos["probe"], request(), python=self.lib)
        root = os.path.realpath(raw["argv"][1])
        checkout = str(self.repos["probe"].resolve())
        self.assertEqual((raw["isolated"], raw["dont_write_bytecode"]), (1, 1))
        self.assertEqual(raw["path"][-1], root)
        self.assertEqual(raw["file"], os.path.join(root, "szl_lake_receipt.py"))
        for entry in raw["path"] + [raw["cwd"], raw["pycache_prefix"], raw["env"]["HOME"]]:
            self.assertFalse(os.path.realpath(entry).startswith(checkout), entry)
        self.assertNotIn("/nonexistent", raw["path"])
        self.assertEqual(sorted(raw["env"]),
                         ["HOME", "LANG", "NO_PROXY", "PATH", "TMPDIR", "no_proxy"])
        self.assertEqual(raw["limits"]["RLIMIT_CPU"], [lake.CHILD_CPU_SECONDS] * 2)
        self.assertEqual(raw["limits"]["RLIMIT_AS"], [lake.CHILD_ADDRESS_BYTES] * 2)
        self.assertEqual(raw["limits"]["RLIMIT_FSIZE"], [0, 0])
        self.assertEqual(raw["write_errno"], 27)
        self.assertEqual(seen["network_namespace"], network_namespace_state())
        if seen["network_namespace"] == NETNS_EMPTY:
            self.assertEqual(raw["interfaces"], ["lo"])
        self.assertEqual(seen["process_tree"],
                         "OWN_PID_NAMESPACE" if pid_namespace_prefix() else "PROCESS_GROUP_ONLY")
        if seen["process_tree"] == "OWN_PID_NAMESPACE":
            self.assertEqual(raw["pid"], 1)
        self.assertEqual(seen["interpreter"], {
            "python": "%d.%d.%d" % sys.version_info[:3],
            "prefix": os.path.abspath(Path(self.lib).parent.parent),
            "base_prefix": sys.base_prefix, "outside_checkout": True})
        self.assertIs(seen["export_rehashed_to_commit"], True)
        with mock.patch.object(lake, "_PID_NAMESPACE", [None]):
            _raw, seen = run_child(self.repos["ok"], request(), python=self.lib)
        self.assertEqual(seen["process_tree"], "PROCESS_GROUP_ONLY")

    def test_body_beyond_the_adapter_body_holds(self):
        for name in ("extra_field", "honesty"):
            with self.subTest(name):
                wrap = self.wrap(name)
                self.assertEqual(wrap["state"], "HOLD")
                self.assertIs(wrap["body_matches_expected_anchor_body"], False)
                self.assertIs(wrap["adapter_rederivation_matches"], True)
                self.assertIs(validate_wrap(wrap, LAKE), True)

    def test_envelope_note_or_organ_beyond_the_library_is_refused(self):
        self.refuses("LAKE_ENVELOPE_NOTE_UNEXPECTED", self.wrap, "note")
        self.refuses("LAKE_ENVELOPE_ORGAN_MISMATCH", self.wrap, "organ")

    def test_version_or_rederivation_difference_holds(self):
        old = self.wrap("ok", python=self.old)
        self.assertEqual((old["state"], old["receipt_library"]["version_observed"]),
                         ("HOLD", "0.3.0"))
        drift = self.wrap("drift")
        self.assertEqual((drift["state"], drift["adapter_rederivation_matches"]), ("HOLD", False))
        self.assertIs(drift["digest_rehashed_by_parent"], True)

    def test_missing_library_is_unavailable(self):
        for name, python in (("ok", self.bare), ("unavailable", self.lib)):
            with self.subTest(name=name):
                wrap = self.wrap(name, python=python)
                self.assertEqual(wrap["state"], "UNAVAILABLE")
                self.assertIsNone(wrap["envelope"])
                self.assertIs(wrap["adapter_rederivation_matches"], False)
                self.assertIs(validate_wrap(wrap, LAKE), True)
        raw, _ = run_child(self.repos["ok"], request(), python=self.bare)
        self.assertEqual((raw["reason"], raw["library_version"]), ("LakeReceiptUnavailable", None))

    def test_forged_digest_from_the_child_is_refused_by_the_parent(self):
        raw, _ = run_child(self.repos["forged_digest"], request(), python=self.lib)
        self.assertEqual((raw["envelope"]["digest"], raw["rederived"]), (FORGED, FORGED))
        self.refuses("LAKE_ENVELOPE_DIGEST_MISMATCH", self.wrap, "forged_digest")

    def test_unexpected_payload_type_is_refused(self):
        self.refuses("LAKE_PAYLOAD_TYPE_UNEXPECTED", self.wrap, "payload_type")

    def test_non_canonical_payload_holds(self):
        wrap = self.wrap("noncanonical")
        self.assertEqual(wrap["state"], "HOLD")
        self.assertIs(wrap["payload_is_canonical_json_of_body"], False)
        self.assertIs(wrap["adapter_rederivation_matches"], True)

    def test_signed_envelope_from_child_is_refused(self):
        self.refuses("LAKE_UNEXPECTED_SIGNATURE_CLAIM", self.wrap, "signed")

    def test_child_failures_are_typed(self):
        self.refuses("LAKE_CHILD_FAILED", self.wrap, "crash")
        self.refuses("LAKE_CHILD_FAILED", self.wrap, "silent")
        self.refuses("LAKE_CHILD_OUTPUT_INVALID", self.wrap, "noise")
        self.refuses("LAKE_CHILD_OUTPUT_INVALID", self.wrap, "list")
        self.refuses("LAKE_CHILD_UNAVAILABLE", run_child, self.repos["ok"], request(),
                     python=str(self.base / "no-such-python"))
        self.refuses("LAKE_CHILD_UNAVAILABLE", run_child, self.repos["ok"], request(),
                     python="python3")
        # Each of these fails the -I -S interpreter probe, before the adapter is exported.
        for name, code in (("false", "LAKE_INTERPRETER_PROBE_FAILED"),
                           ("true", "LAKE_INTERPRETER_PROBE_FAILED"),
                           ("echo", "LAKE_INTERPRETER_LAYOUT_INVALID")):
            exe = next((p for p in ("/bin/" + name, "/usr/bin/" + name) if os.path.isfile(p)),
                       None)
            if exe is not None:
                with self.subTest(name):
                    self.refuses(code, run_child, self.repos["ok"], request(), python=exe)

    def test_deadline_and_output_cap_are_enforced(self):
        sleeper = make_lake(self.base, "sleep", mode="sleep")
        flood = make_lake(self.base, "flood", mode="flood")
        started = time.monotonic()
        with mock.patch.object(lake, "CHILD_TIMEOUT_SECONDS", 2):
            self.refuses("LAKE_CHILD_TIMEOUT", run_child, sleeper, request(), python=self.lib)
        self.refuses("LAKE_CHILD_OUTPUT_TOO_LARGE", run_child, flood, request(), python=self.lib)
        self.assertLess(time.monotonic() - started, 90)

    def test_untracked_shadow_package_never_runs(self):
        repo = make_lake(self.base, "shadow-package")
        shadow = repo / "szl_lake_receipt/__init__.py"
        shadow.parent.mkdir()
        shadow.write_text(adapter("forged_digest", "SHADOW"), encoding="utf-8")
        self.assertEqual(unhardened(repo, "import szl_lake_receipt as m; print(m.MARK)"),
                         "SHADOW")
        wrap = wrap_report(deepcopy(LAKE), repo, subject=TURN, input_digest=INPUT,
                           stored_object_digest=STORED, python=self.lib, at=NOW)
        self.assertEqual(wrap["state"], "CANONICAL_RECEIPT_EMITTED_UNSIGNED")

    def test_planted_bytecode_never_runs(self):
        repo = make_lake(self.base, "planted-pyc")
        source = repo / "szl_lake_receipt.py"
        evil = self.base / "evil_szl_lake_receipt.py"
        evil.write_text(adapter("forged_digest", "PLANTED"), encoding="utf-8")
        cache = Path(importlib.util.cache_from_source(str(source)))
        cache.parent.mkdir(exist_ok=True)
        py_compile.compile(str(evil), cfile=str(cache), doraise=True)
        data = bytearray(cache.read_bytes())
        stat = source.stat()
        # A timestamp pyc whose header copies the committed source's mtime and size.
        data[8:16] = struct.pack("<II", int(stat.st_mtime) & 0xFFFFFFFF,
                                 stat.st_size & 0xFFFFFFFF)
        cache.write_bytes(bytes(data))
        self.assertEqual(unhardened(repo, "import szl_lake_receipt as m; print(m.MARK)"),
                         "PLANTED")
        wrap = wrap_report(deepcopy(LAKE), repo, subject=TURN, input_digest=INPUT,
                           stored_object_digest=STORED, python=self.lib, at=NOW)
        self.assertEqual(wrap["state"], "CANONICAL_RECEIPT_EMITTED_UNSIGNED")

    def test_untracked_library_and_distribution_record_are_not_importable(self):
        repo = make_lake(self.base, "untracked-library")
        for path, text in library_files("0.3.1").items():
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        shown = unhardened(repo, "import szl_receipt; print(szl_receipt.PAYLOAD_TYPE)")
        self.assertEqual(shown, RECEIPT_PAYLOAD_TYPE)
        wrap = wrap_report(deepcopy(LAKE), repo, subject=TURN, input_digest=INPUT,
                           stored_object_digest=STORED, python=self.bare, at=NOW)
        self.assertEqual(wrap["state"], "UNAVAILABLE")
        self.assertIsNone(wrap["receipt_library"]["version_observed"])

    def test_committed_library_copy_is_not_the_interpreter_library(self):
        repo = make_lake(self.base, "committed-library", extra=library_files("0.3.1"))
        wrap = wrap_report(deepcopy(LAKE), repo, subject=TURN, input_digest=INPUT,
                           stored_object_digest=STORED, python=self.bare, at=NOW)
        self.assertEqual(wrap["state"], "HOLD")
        self.assertEqual(wrap["receipt_library"]["module_origin"], "EXPORTED_TREE")
        self.assertIsNone(wrap["receipt_library"]["version_observed"])
        self.assertIs(validate_wrap(wrap, LAKE), True)

    def test_adapter_installed_in_the_interpreter_is_refused(self):
        installed = make_python(self.base, "installed-python",
                                {**library_files("0.3.1"), "szl_lake_receipt.py": adapter()})
        self.refuses("LAKE_ADAPTER_NOT_FROM_EXPORT", self.wrap, "ok", python=installed)

    def test_request_is_checked_before_any_git_or_child(self):
        for overrides in ({"subject": "Braid-Turn:" + "1" * 32}, {"subject": None},
                          {"input_digest": "sha256:" + INPUT}, {"stored_object_digest": "3" * 65},
                          {"input_digest": True}):
            with self.subTest(overrides=overrides):
                self.refuses("LAKE_REQUEST_INVALID", wrap_report, deepcopy(LAKE),
                             self.base / "absent",
                             **{"subject": TURN, "input_digest": INPUT,
                                "stored_object_digest": STORED, "python": "/nonexistent",
                                **overrides})

    def test_edited_adapter_never_reaches_the_child(self):
        repo = make_lake(self.base, "edited")
        (repo / "szl_lake_receipt.py").write_text(adapter("signed"), encoding="utf-8")
        self.refuses("LAKE_WORKTREE_DIFFERS_FROM_COMMIT", wrap_report, deepcopy(LAKE), repo,
                     subject=TURN, input_digest=INPUT, stored_object_digest=STORED,
                     python=self.lib)

    def swapped_root(self, repo, evil):
        """The root tree body with the adapter entry pointing at ``evil``, and its blob id."""
        blob = git_input(repo, "hash-object", "-w", "--stdin", stdin=evil,
                         home=self.base).decode("ascii").strip()
        old = git(repo, "rev-parse", "HEAD:szl_lake_receipt.py", home=self.base).decode().strip()
        root = git(repo, "rev-parse", "HEAD^{tree}", home=self.base).decode().strip()
        listing = git(repo, "ls-tree", root, home=self.base).decode("ascii")
        return root, blob, listing.replace(old, blob)

    def test_planted_pack_cannot_swap_a_committed_subtree(self):
        repo = make_lake(self.base, "planted-pack", extra={"lib/helper.py": "SAFE = True\n"})
        git(repo, "gc", "-q", home=self.base)
        evil = b"SAFE = False\n"
        blob = git_input(repo, "hash-object", "-w", "--stdin", stdin=evil,
                         home=self.base).decode("ascii").strip()
        subtree = git(repo, "rev-parse", "HEAD:lib", home=self.base).decode().strip()
        listing = git(repo, "ls-tree", subtree, home=self.base).decode("ascii")
        old = git(repo, "rev-parse", "HEAD:lib/helper.py", home=self.base).decode().strip()
        swapped = git_input(repo, "mktree", stdin=listing.replace(old, blob).encode("ascii"),
                            home=self.base).decode().strip()
        body_of = git(repo, "cat-file", "tree", swapped, home=self.base)
        # Valid copies of every committed object, and a different tree under the subtree's id.
        plant_pack(repo, reachable_objects(repo, home=self.base, swap={subtree: body_of}))
        (repo / "lib/helper.py").write_bytes(evil)
        # Control: git itself now lists the planted bytes for the committed path, at the
        # same commit, and the work tree agrees with that listing.
        raw = git(repo, "ls-tree", "-r", "HEAD", home=self.base).decode("ascii")
        listed = {line.split("\t", 1)[1]: line.split()[2] for line in raw.splitlines()}
        self.assertEqual(listed["lib/helper.py"], blob)
        # The census itself now re-hashes trees, so it is the first layer to refuse.
        self.refuses("CENSUS_LISTING_NOT_COMMIT_TREE", list_tree, repo)
        self.refuses("CENSUS_LISTING_NOT_COMMIT_TREE", verified_listing, repo)
        self.refuses("CENSUS_LISTING_NOT_COMMIT_TREE", adapter_identity, repo,
                     "szl_lake_receipt.py")
        self.refuses("CENSUS_LISTING_NOT_COMMIT_TREE", wrap_report, deepcopy(LAKE), repo,
                     subject=TURN, input_digest=INPUT, stored_object_digest=STORED,
                     python=self.lib)

    def test_replace_ref_cannot_swap_the_committed_root_tree(self):
        repo = make_lake(self.base, "replace-ref")
        committed = git(repo, "rev-parse", "HEAD:szl_lake_receipt.py",
                        home=self.base).decode().strip()
        root, blob, listing = self.swapped_root(repo, adapter("forged_digest", "REPLACED")
                                                .encode("utf-8"))
        swapped = git_input(repo, "mktree", stdin=listing.encode("ascii"),
                            home=self.base).decode().strip()
        git(repo, "replace", root, swapped, home=self.base)
        # Control: by default git now shows the replacement for the committed path.
        self.assertIn(blob, git(repo, "ls-tree", "HEAD", "szl_lake_receipt.py",
                                home=self.base).decode())
        commit, rows = verified_listing(repo)
        self.assertEqual(tree_object_id(rows), commit_tree(repo, commit))
        wrap = self.wrap_of_repo(repo)
        self.assertEqual(wrap["state"], "CANONICAL_RECEIPT_EMITTED_UNSIGNED")
        self.assertEqual((wrap["commit"], wrap["adapter_blob_sha1"]), (commit, committed))

    def wrap_of_repo(self, repo, python=None):
        return wrap_report(deepcopy(LAKE), repo, subject=TURN, input_digest=INPUT,
                           stored_object_digest=STORED, python=python or self.lib, at=NOW)

    def test_venv_inside_the_checkout_is_refused_before_it_runs(self):
        repo = make_lake(self.base, "venv-inside")
        marker = self.base / "lake-venv-ran"
        line = "import pathlib; pathlib.Path(%r).write_text('ran')\n" % str(marker)
        python = make_python(repo, ".venv", {**library_files("0.3.1"), "zz_marker.pth": line})
        # Control: started normally, that interpreter runs code planted in the checkout.
        subprocess.run([python, "-I", "-c", "pass"], check=True, timeout=60)
        self.assertTrue(marker.exists())
        marker.unlink()
        self.refuses("LAKE_INTERPRETER_INSIDE_CHECKOUT", self.wrap_of_repo, repo, python)
        self.refuses("LAKE_INTERPRETER_INSIDE_CHECKOUT", interpreter_layout, python, repo)
        self.assertFalse(marker.exists())

    def test_pth_lines_into_the_checkout_are_refused(self):
        repo = make_lake(self.base, "pth-lines")
        planted = repo / ".planted"
        for path, text in library_files("0.3.1").items():
            (planted / path).parent.mkdir(parents=True, exist_ok=True)
            (planted / path).write_text(text, encoding="utf-8")
        by_path = make_python(self.base, "pth-path-python", {"planted.pth": "%s\n" % planted})
        self.refuses("LAKE_INTERPRETER_INSIDE_CHECKOUT", self.wrap_of_repo, repo, by_path)
        by_code = make_python(self.base, "pth-code-python", {
            "sneaky.pth": "import sys; sys.path.append(%r)\n" % str(planted)})
        # An import line is code; nothing but running it shows where it points.
        self.assertIs(interpreter_layout(by_code, repo)["outside_checkout"], True)
        self.refuses("LAKE_INTERPRETER_INSIDE_CHECKOUT", self.wrap_of_repo, repo, by_code)


class CommittedTreeTests(Base):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lake-tree-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_listing_and_export_are_rehashed_to_the_commit(self):
        repo = make_lake(self.base, "tree", extra={"a.txt": "a\n", "a-b/x": "x\n",
                                                   "a/b.py": "b = 1\n", "a0": "0\n"})
        os.symlink("a.txt", repo / "link")
        git(repo, "add", "-A", home=self.base)
        git(repo, "commit", "-q", "-m", "link", home=self.base)
        commit, rows = verified_listing(repo)
        tree = git(repo, "rev-parse", "HEAD^{tree}", home=self.base).decode().strip()
        self.assertEqual((tree_object_id(rows), commit_tree(repo, commit)), (tree, tree))
        for bad in ("0" * 40, tree, "C" * 40):
            with self.subTest(bad=bad):
                self.refuses("LAKE_COMMIT_OBJECT_INVALID", commit_tree, repo, bad)
        self.refuses("LAKE_LISTING_INVALID", tree_object_id, rows + [rows[0]])
        dest = self.base / "export"
        dest.mkdir()
        counts = export_tree(repo, commit, dest, max_blob_bytes=1 << 20, max_total_bytes=1 << 24)
        self.assertEqual((counts["files"], counts["skipped_entries"]), (6, 1))
        self.assertIs(export_matches(dest, rows), True)
        (dest / "planted.py").write_text("x\n", encoding="utf-8")
        self.assertIs(export_matches(dest, rows), False)


class CliTests(Base):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="lake-cli-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name)
        cls.lib = make_python(cls.base, "lib-python", library_files("0.3.1"))
        cls.old = make_python(cls.base, "old-python", library_files("0.3.0"))
        cls.bare = make_python(cls.base, "bare-python")
        cls.ok = make_lake(cls.base, "ok")
        cls.policy = cls.base / "policy.json"
        cls.policy.write_text(json.dumps({"lake": LAKE}), encoding="utf-8")
        cls.report = cls.base / "report.json"
        cls.report.write_text(json.dumps({"turn_id": TURN, "inputs_digest": INPUT, "ordinal": 1}),
                              encoding="utf-8")
        cls.counter = 0

    def write(self, name, value):
        path = self.base / name
        path.write_bytes(value if type(value) is bytes else json.dumps(value).encode("utf-8"))
        return path

    def out(self):
        type(self).counter += 1
        return self.base / ("out-%d.json" % type(self).counter)

    def run_cli(self, *, checkout=None, report=None, output=None, policy=None, python=None):
        args = ["--policy", str(policy or self.policy), "--lake-checkout", str(checkout or self.ok),
                "--braid-report", str(report or self.report), "--python", python or self.lib,
                "--output", str(output)]
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(args)
        lines = buffer.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 1)
        return code, json.loads(lines[0])

    def test_binds_report_bytes_and_never_overwrites(self):
        output = self.out()
        code, printed = self.run_cli(output=output)
        self.assertEqual(code, 0)
        self.assertEqual(printed["state"], "CANONICAL_RECEIPT_EMITTED_UNSIGNED")
        self.assertIs(printed["signed"], False)
        self.assertIs(printed["digest_rehashed_by_parent"], True)
        self.assertIs(printed["adapter_rederivation_matches"], True)
        self.assertEqual(printed["network_namespace"], network_namespace_state())
        self.assertIs(printed["production_authorized"], False)
        self.assertIs(printed["appended_to_live_lake"], False)
        wrap = json.loads(output.read_text())
        self.assertEqual(wrap["subject"], TURN)
        self.assertEqual(wrap["input_digest"], INPUT)
        self.assertEqual(wrap["stored_object_digest"],
                         hashlib.sha256(self.report.read_bytes()).hexdigest())
        self.assertIs(validate_wrap(wrap, LAKE), True)
        before = output.read_bytes()
        code, printed = self.run_cli(output=output)
        self.assertEqual((code, printed["state"], printed["code"]),
                         (3, "UNAVAILABLE", "OUTPUT_PATH_DENIED"))
        self.assertEqual(output.read_bytes(), before)

    def test_stored_object_is_the_exact_bytes(self):
        spaced = self.write("spaced.json", json.dumps(
            {"turn_id": TURN, "inputs_digest": INPUT, "ordinal": 1}, indent=2).encode("utf-8"))
        first, second = self.out(), self.out()
        self.assertEqual(self.run_cli(output=first)[0], 0)
        self.assertEqual(self.run_cli(report=spaced, output=second)[0], 0)
        one, two = json.loads(first.read_text()), json.loads(second.read_text())
        self.assertEqual(two["stored_object_digest"],
                         hashlib.sha256(spaced.read_bytes()).hexdigest())
        self.assertNotEqual(one["stored_object_digest"], two["stored_object_digest"])
        self.assertEqual(one["input_digest"], two["input_digest"])

    def test_report_is_read_once(self):
        report = self.write("swap.json", {"turn_id": TURN, "inputs_digest": INPUT, "ordinal": 1})
        original = report.read_bytes()
        real = lake.read_json

        def read_then_swap(path, *, max_bytes):
            value = real(path, max_bytes=max_bytes)
            if path == report:
                # The file changes after it was parsed; the stored digest must not follow it.
                report.write_bytes(json.dumps({"turn_id": TURN, "inputs_digest": INPUT,
                                               "ordinal": 2}).encode("utf-8"))
            return value

        output = self.out()
        with mock.patch.object(lake, "read_json", read_then_swap):
            code, printed = self.run_cli(report=report, output=output)
        self.assertEqual((code, printed["state"]), (0, "CANONICAL_RECEIPT_EMITTED_UNSIGNED"))
        wrap = json.loads(output.read_text())
        self.assertNotEqual(report.read_bytes(), original)
        self.assertEqual(wrap["stored_object_digest"], hashlib.sha256(original).hexdigest())

    def test_output_inside_the_repository_is_refused(self):
        inside = ROOT / "tests" / "lake-wrap-should-not-exist.json"
        self.assertFalse(inside.exists())
        try:
            code, printed = self.run_cli(output=inside)
            self.assertEqual((code, printed["code"]), (3, "OUTPUT_PATH_DENIED"))
            self.assertFalse(inside.exists())
        finally:
            if inside.exists():
                inside.unlink()

    def test_missing_output_parent_is_refused(self):
        code, printed = self.run_cli(output=self.base / "missing-dir" / "out.json")
        self.assertEqual((code, printed["code"]), (3, "OUTPUT_PATH_DENIED"))

    def test_hold_and_unavailable_exit_two_and_are_written(self):
        for python, state in ((self.old, "HOLD"), (self.bare, "UNAVAILABLE")):
            output = self.out()
            code, printed = self.run_cli(python=python, output=output)
            self.assertEqual((code, printed["state"]), (2, state))
            wrap = json.loads(output.read_text())
            self.assertEqual(wrap["state"], state)
            self.assertIs(validate_wrap(wrap, LAKE), True)
            if state == "UNAVAILABLE":
                self.assertIsNone(wrap["envelope"])
                self.assertIs(wrap["adapter_rederivation_matches"], False)

    def test_malformed_reports_are_refused(self):
        cases = {
            "LAKE_REPORT_FIELDS_INVALID": [{"inputs_digest": INPUT}, {"turn_id": TURN},
                                           {"turn_id": 1, "inputs_digest": INPUT},
                                           {"turn_id": TURN, "inputs_digest": None},
                                           [TURN, INPUT], "report"],
            "LAKE_REQUEST_INVALID": [{"turn_id": "Braid-Turn:" + "1" * 32, "inputs_digest": INPUT},
                                     {"turn_id": TURN, "inputs_digest": "sha256:" + INPUT},
                                     {"turn_id": TURN, "inputs_digest": "2" * 63}],
            "FLOAT_VALUE_REFUSED": [b'{"turn_id": "' + TURN.encode() + b'", "inputs_digest": "'
                                    + INPUT.encode() + b'", "ordinal": 1.0}'],
            "DUPLICATE_JSON_KEY": [b'{"turn_id": "a", "turn_id": "b", "inputs_digest": "c"}'],
            "INVALID_JSON": [b"{not json", b"\xff\xfe"],
        }
        for expected, values in cases.items():
            for index, value in enumerate(values):
                report = self.write("bad-%s-%d.json" % (expected, index), value)
                output = self.out()
                with self.subTest(expected=expected, value=value):
                    code, printed = self.run_cli(report=report, output=output)
                    self.assertEqual((code, printed["code"], printed["state"]),
                                     (3, expected, "UNAVAILABLE"))
                    self.assertIs(printed["signed"], False)
                    self.assertFalse(output.exists())
        empty = self.write("empty.json", b"")
        output = self.out()
        code, printed = self.run_cli(report=empty, output=output)
        self.assertEqual((code, printed["code"]), (3, "INPUT_SIZE_INVALID"))
        code, printed = self.run_cli(report=self.base / "absent.json", output=output)
        self.assertEqual((code, printed["code"]), (3, "SOURCE_FILE_UNAVAILABLE"))
        self.assertFalse(output.exists())

    def test_policy_and_interpreter_are_checked(self):
        no_lake = self.write("no-lake.json", {"census": {}})
        output = self.out()
        self.assertEqual(self.run_cli(policy=no_lake, output=output), (3, {
            "state": "UNAVAILABLE", "code": "LAKE_POLICY_FIELDS_INVALID", "signed": False,
            "appended_to_live_lake": False, "production_authorized": False}))
        bad = deepcopy(LAKE)
        bad["append_to_live_lake"] = True
        code, printed = self.run_cli(policy=self.write("append.json", {"lake": bad}),
                                     output=output)
        self.assertEqual((code, printed["code"]), (3, "LAKE_POLICY_INVALID"))
        for python in ("python3", str(self.base / "no-such-python"), str(self.base)):
            code, printed = self.run_cli(python=python, output=output)
            self.assertEqual((code, printed["code"]), (3, "LAKE_INTERPRETER_INVALID"))
        self.assertFalse(output.exists())

    def test_edited_adapter_is_refused_and_not_written(self):
        with tempfile.TemporaryDirectory(prefix="lake-cli-edit-") as temp:
            repo = make_lake(temp, "lake")
            with (repo / "szl_lake_receipt.py").open("a", encoding="utf-8") as stream:
                stream.write("# drift\n")
            output = Path(temp) / "out.json"
            code, printed = self.run_cli(checkout=repo, output=output)
            self.assertEqual((code, printed["code"]), (3, "LAKE_WORKTREE_DIFFERS_FROM_COMMIT"))
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest_main()

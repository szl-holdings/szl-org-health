#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Shared strict helpers for the SZL Ouroboros braid v2 tools.

Canonical JSON, float-free strict loading, create-exclusive output, exact
rational text, a Lean comment and literal stripper, and one bounded way to run
a child process. Nothing here signs anything or grants authority. A digest
computed here is an identifier for bytes, NOT a signature and NOT evidence of
who produced them.

Network isolation is reported, never assumed: when a child is asked to run
without network, it is started in a new network namespace only if the host
allows one, and the result says which happened. On a host that refuses user
namespaces the child runs normally and the result says NOT_AVAILABLE.
Process-group kills reach every descendant that stays in the child's group; a
descendant that starts its own session escapes them.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import time

try:
    import resource
except ImportError:
    resource = None

try:
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_catalog_admission import InputError

SHA64 = re.compile(r"[0-9a-f]{64}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"szl-holdings/[A-Za-z0-9_.-]{1,80}\Z")
REL_PATH = re.compile(r"[A-Za-z0-9_.+@-]+(?:/[A-Za-z0-9_.+@-]+)*\Z")
RATIONAL = re.compile(r"(0|[1-9][0-9]{0,400})/([1-9][0-9]{0,400})\Z")
FIXED_DOCTRINE = "bounded, terminating, receipt-closed"
GENESIS = "0" * 64
MAX_JSON_DEPTH = 64
NETNS_EMPTY = "EMPTY_NETWORK_NAMESPACE"
NETNS_UNAVAILABLE = "NOT_AVAILABLE_ON_THIS_HOST"
NETNS_NOT_REQUESTED = "NOT_REQUESTED"
NETNS_STATES = (NETNS_EMPTY, NETNS_UNAVAILABLE, NETNS_NOT_REQUESTED)
# A new PID namespace too: when the child exits or is killed, the kernel kills every process
# left in it, including a grandchild that escaped the process group with setsid().
_UNSHARE = ("unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
            "--kill-child", "--")
_UNSHARE_SEARCH = "/usr/bin:/bin:/usr/sbin:/sbin"
# Lean 4's isIdRest: ASCII letters and digits, _ ' ! ?, the letter-like and subscript blocks.
_IDENT = re.compile("[A-Za-z0-9_'!?.\u0370-\u03ff\u1d62-\u1d6a\u1f00-\u1fff\u2080-\u209c"
                    "\u2100-\u214f\U0001d49c-\U0001d59f]")
_CHAR = re.compile(r"'(?:\\(?:u[0-9A-Fa-f]{4}|u\{[0-9A-Fa-f]{1,6}\}|x[0-9A-Fa-f]{2}|.)|[^\\'\n])'")
_RAW = re.compile(r"r(#*)\"")


def require(condition, code):
    """Raise the typed refusal ``code`` unless ``condition`` holds."""
    if not condition:
        raise InputError(code)


def canonical(value) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, ASCII only.

    Byte-identical to the v1 braid's ``canonical`` so v1 and v2 digests of the
    same value agree. Floats are refused because their text form is not a
    stable identity; exact rationals travel as "p/q" strings instead.
    """
    _refuse_floats(value, 0)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _refuse_floats(value, depth):
    require(depth <= MAX_JSON_DEPTH, "JSON_DEPTH_EXCEEDED")
    kind = type(value)
    if kind is float:
        raise InputError("FLOAT_VALUE_REFUSED")
    if kind is dict:
        for key, item in value.items():
            require(type(key) is str, "JSON_KEY_NOT_TEXT")
            _refuse_floats(item, depth + 1)
    elif kind in (list, tuple):
        for item in value:
            _refuse_floats(item, depth + 1)
    else:
        require(value is None or kind in (str, int, bool), "JSON_VALUE_TYPE_REFUSED")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(value) -> str:
    """SHA-256 over the canonical JSON of ``value``."""
    return sha256_hex(canonical(value))


def git_blob_sha1(raw: bytes) -> str:
    """Git's blob object id. A source-object identifier, not a security digest."""
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw,
                        usedforsecurity=False).hexdigest()


def _unique(pairs):
    out = {}
    for key, item in pairs:
        if key in out:
            raise InputError("DUPLICATE_JSON_KEY")
        out[key] = item
    return out


def _no_constant(_):
    raise InputError("NONFINITE_JSON_VALUE")


def _no_float(_):
    raise InputError("FLOAT_VALUE_REFUSED")


def strict_json(raw: bytes, *, max_bytes: int):
    """Parse bounded JSON refusing duplicate keys, NaN/Infinity and floats."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= max_bytes, "INPUT_SIZE_INVALID")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique,
                           parse_constant=_no_constant, parse_float=_no_float)
    except InputError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise InputError("INVALID_JSON") from None
    _refuse_floats(value, 0)
    return value


def read_json(path: Path, *, max_bytes: int):
    """Read one regular, non-symlink JSON file. Returns ``(value, sha256_of_bytes)``."""
    require(isinstance(path, Path), "SOURCE_FILE_UNAVAILABLE")
    require(not path.is_symlink() and path.is_file(), "SOURCE_FILE_UNAVAILABLE")
    require(0 < path.stat().st_size <= max_bytes, "INPUT_SIZE_INVALID")
    raw = path.read_bytes()
    return strict_json(raw, max_bytes=max_bytes), sha256_hex(raw)


def write_exclusive(path: Path, value, *, max_bytes: int, checkout: Path | None = None) -> str:
    """Create ``path`` (never overwrite) holding canonical JSON plus a newline.

    Refuses an existing path, a symlink, a missing parent, and any location
    inside ``checkout`` so evidence is never written into a source tree.
    Returns the SHA-256 of the bytes written.
    """
    require(isinstance(path, Path), "OUTPUT_PATH_DENIED")
    require(not path.is_symlink() and not path.exists() and path.parent.is_dir(),
            "OUTPUT_PATH_DENIED")
    if checkout is not None:
        require(not path.resolve().is_relative_to(checkout.resolve()), "OUTPUT_PATH_DENIED")
    raw = canonical(value) + b"\n"
    require(len(raw) <= max_bytes, "OUTPUT_TOO_LARGE")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
    return sha256_hex(raw)


def write_new_bytes(path: Path, raw: bytes) -> None:
    """Create ``path`` with ``raw``; refuses to follow a symlink or replace a file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    # Owner-only: evidence and logs are read back by the same user, never by others.
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def checkout_root() -> Path:
    """The source tree this tool lives in; outputs must stay outside it."""
    return Path(__file__).resolve().parent.parent


def rational_text(value: Fraction) -> str:
    """Lowest-terms "p/q" text for a non-negative exact rational."""
    require(type(value) is Fraction and value >= 0, "RATIONAL_INVALID")
    try:
        return f"{value.numerator}/{value.denominator}"
    except ValueError:
        # Python refuses int-to-text above its digit limit; that is a typed refusal here.
        raise InputError("RATIONAL_TOO_LARGE") from None


def parse_rational(text) -> Fraction:
    """Parse lowest-terms "p/q" text. Rejects floats, signs, spaces and non-reduced forms."""
    require(type(text) is str and len(text) <= 810, "RATIONAL_INVALID")
    match = RATIONAL.fullmatch(text)
    require(match is not None, "RATIONAL_INVALID")
    value = Fraction(int(match.group(1)), int(match.group(2)))
    require(rational_text(value) == text, "RATIONAL_NOT_REDUCED")
    return value


def natural(value, code="NATURAL_INVALID", *, maximum=10 ** 15) -> int:
    """A non-negative ``int`` that is not a ``bool`` and is within ``maximum``."""
    require(type(value) is int and 0 <= value <= maximum, code)
    return value


def closed(value, fields, code):
    """Require a ``dict`` whose key set is exactly ``fields``."""
    require(type(value) is dict and set(value) == set(fields), code)
    return value


def lean_code_only(text: str) -> str:
    """Lean source with comments and string or character literals removed.

    Handles nested ``/- -/`` blocks, ``--`` line comments, ordinary strings with
    escapes, raw strings (``r"..."``, ``r#"..."#``) and character literals. Each
    literal is replaced by ``""`` so neighbouring tokens stay separate. Text
    inside an interpolated string's braces is dropped with the string, but a
    string literal nested inside those braces ends the scan early; this is a
    text-level filter, not a Lean parser.
    """
    out, depth, i, size = [], 0, 0, len(text)
    while i < size:
        pair = text[i:i + 2]
        if pair == "/-":
            depth += 1
            i += 2
            continue
        if depth:
            if pair == "-/":
                depth -= 1
                i += 2
            else:
                i += 1
            continue
        if pair == "--":
            end = text.find("\n", i)
            i = size if end < 0 else end
            continue
        previous = text[i - 1] if i else " "
        if text[i] == "r" and not _IDENT.match(previous):
            raw = _RAW.match(text, i)
            if raw:
                close = '"' + raw.group(1)
                end = text.find(close, raw.end())
                i = size if end < 0 else end + len(close)
                out.append('""')
                continue
        if text[i] == '"':
            j = i + 1
            while j < size and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            out.append('""')
            continue
        if text[i] == "'" and not _IDENT.match(previous):
            char = _CHAR.match(text, i)
            if char:
                i = char.end()
                out.append('""')
                continue
        out.append(text[i])
        i += 1
    return "".join(out)


_NETNS_STATE: list = []


def _unshare_prefix():
    """``unshare`` by absolute path, so the child's own PATH cannot hide or replace it."""
    binary = shutil.which("unshare", path=_UNSHARE_SEARCH)
    return None if binary is None else (binary, *_UNSHARE[1:])


def network_namespace_state() -> str:
    """Whether this host can start a child in a new, empty network namespace.

    Measured once per process by starting ``cat /proc/net/dev`` inside one and
    checking that loopback is the only interface it can see.
    """
    if not _NETNS_STATE:
        _NETNS_STATE.append(_probe_network_namespace())
    return _NETNS_STATE[0]


def _probe_network_namespace() -> str:
    prefix = _unshare_prefix()
    if prefix is None:
        return NETNS_UNAVAILABLE
    try:
        proc = subprocess.run([*prefix, "cat", "/proc/net/dev"], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=20,
                              check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError):
        return NETNS_UNAVAILABLE
    names = [line.split(":", 1)[0].strip()
             for line in proc.stdout.decode("ascii", "replace").splitlines()[2:] if ":" in line]
    return NETNS_EMPTY if proc.returncode == 0 and names == ["lo"] else NETNS_UNAVAILABLE


def _limits(cpu_seconds, file_bytes, address_bytes):
    def apply():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        for kind, value in ((resource.RLIMIT_CPU, cpu_seconds),
                            (resource.RLIMIT_FSIZE, file_bytes),
                            (resource.RLIMIT_AS, address_bytes)):
            if value is not None:
                # An unprivileged process may lower but never raise its hard limit.
                hard = resource.getrlimit(kind)[1]
                value = value if hard == resource.RLIM_INFINITY else min(value, hard)
                resource.setrlimit(kind, (value, value))
    return apply


def _feed(stream, raw: bytes) -> None:
    try:
        stream.write(raw)
    except OSError:
        # The child closed its stdin early (or was killed): what it read is all it gets.
        pass
    finally:
        try:
            stream.close()
        except OSError:
            # Closing a pipe whose reader is gone can fail; there is nothing left to release.
            pass


def _exited(proc) -> bool:
    """Whether the child has exited, WITHOUT reaping it while ``waitid`` allows that.

    An unreaped child keeps its process-group id allocated, so a later group kill
    cannot reach an unrelated process that was given the same number.
    """
    if hasattr(os, "waitid") and hasattr(os, "WNOWAIT"):
        try:
            return os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
        except ChildProcessError:
            return True
    return proc.poll() is not None


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        # The group is already gone, or no longer ours to signal: nothing left to kill.
        pass


def bounded_run(argv, *, cwd, env, timeout, max_output, stdin_bytes=None, isolate_network=False,
                cpu_seconds=None, file_bytes=None, address_bytes=None, merge_stderr=True) -> dict:
    """Run one child with a deadline, an output cap read as it arrives, and limits.

    The child leads a new session. Its whole process group is killed on a timeout,
    on an output overflow, and once the child itself has exited, so no grandchild
    left in that group outlives the call. ``stdin_bytes`` is written by a helper
    thread as the child reads it, so a child that never reads cannot stall the
    deadline. Returns ``exit_code`` (negative for a signal, 127 when the child
    could not be started), ``output`` (at most ``max_output`` bytes),
    ``timed_out``, ``truncated``, ``seconds`` and ``network_namespace``.
    """
    state = NETNS_NOT_REQUESTED
    command = list(argv)
    if isolate_network:
        state = network_namespace_state()
        prefix = _unshare_prefix() if state == NETNS_EMPTY else None
        if prefix is None:
            state = NETNS_UNAVAILABLE
        else:
            command = [*prefix, *command]
    started = time.monotonic()
    deadline = started + timeout
    try:
        proc = subprocess.Popen(
            command, cwd=str(cwd), env=env, stdin=subprocess.PIPE if stdin_bytes is not None
            else subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
            start_new_session=True,
            preexec_fn=_limits(cpu_seconds, file_bytes, address_bytes))
    except (OSError, subprocess.SubprocessError):
        return {"exit_code": 127, "output": b"", "timed_out": False, "truncated": False,
                "seconds": 0, "network_namespace": state}
    feeder = None
    if stdin_bytes is not None:
        feeder = threading.Thread(target=_feed, args=(proc.stdin, bytes(stdin_bytes)), daemon=True)
        feeder.start()
    chunks, total, timed_out, truncated = [], 0, False, False
    fd = proc.stdout.fileno()
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if not selector.select(min(remaining, 1.0)):
                # Nothing to read for a while and the child is gone: whatever still holds
                # the pipe is a leftover descendant, which the group kill below removes.
                if _exited(proc):
                    break
                continue
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > max_output:
                chunks.append(block[:max(0, max_output - (total - len(block)))])
                truncated = True
                break
            chunks.append(block)
    if not (timed_out or truncated):
        pause = 0.001
        while not _exited(proc):
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(pause)
            pause = min(pause * 2, 0.05)
    _kill_group(proc.pid)
    proc.wait()
    proc.stdout.close()
    if feeder is not None:
        feeder.join(timeout=5)
    return {"exit_code": proc.returncode, "output": b"".join(chunks), "timed_out": timed_out,
            "truncated": truncated, "seconds": int(time.monotonic() - started),
            "network_namespace": state}

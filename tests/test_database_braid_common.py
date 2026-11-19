#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the braid v2 shared helpers that run or shape untrusted work.

bounded_run is exercised with real throwaway shell and Python children: a timeout and an
output overflow must kill the child's whole process group (a grandchild included), stdin must
never stall the deadline, and network isolation must be reported exactly as this host provided
it. Nothing here opens a network connection; every file lives in a temporary directory.
"""
from fractions import Fraction
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from unittest import TestCase, main as unittest_main, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_catalog_admission import InputError  # noqa: E402
from tools import database_braid_common as common  # noqa: E402
from tools.database_braid_common import (  # noqa: E402
    NETNS_EMPTY, NETNS_NOT_REQUESTED, NETNS_STATES, NETNS_UNAVAILABLE, bounded_run,
    lean_code_only, network_namespace_state, rational_text, write_new_bytes,
)

ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
LISTING = "cat /proc/net/dev 2>/dev/null || echo NO_PROC_NET_DEV"


def gone(pid, wait=10.0):
    """True once ``pid`` no longer runs. A zombie waiting for init counts as gone."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        stat = Path(f"/proc/{pid}/stat")
        if Path("/proc").is_dir():
            try:
                state = stat.read_text().rsplit(")", 1)[1].split()[0]
            except (FileNotFoundError, ProcessLookupError):
                return True
            if state in ("Z", "X"):
                return True
        else:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
        time.sleep(0.05)
    return False


def interfaces(output: bytes) -> list:
    return [line.split(":", 1)[0].strip()
            for line in output.decode("ascii", "replace").splitlines()[2:] if ":" in line]


class _Scratch(TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)

    def run_child(self, argv, **kwargs):
        options = {"cwd": self.dir, "env": ENV, "timeout": 30, "max_output": 1 << 20}
        options.update(kwargs)
        return bounded_run(argv, **options)


class BoundedRunTests(_Scratch):
    def test_plain_run_reports_every_field(self):
        run = self.run_child(["sh", "-c", "printf out; printf err >&2; exit 3"])
        self.assertEqual(set(run), {"exit_code", "output", "timed_out", "truncated", "seconds",
                                    "network_namespace"})
        self.assertEqual((run["exit_code"], run["output"]), (3, b"outerr"))
        self.assertEqual((run["timed_out"], run["truncated"]), (False, False))
        self.assertIs(type(run["seconds"]), int)
        self.assertEqual(run["network_namespace"], NETNS_NOT_REQUESTED)
        quiet = self.run_child(["sh", "-c", "printf out; printf err >&2"], merge_stderr=False)
        self.assertEqual(quiet["output"], b"out")

    def test_timeout_kills_the_whole_group_including_a_grandchild(self):
        pidfile = self.dir / "grandchild.pid"
        started = time.monotonic()
        run = self.run_child(["sh", "-c", f"sleep 300 & echo $! > {pidfile}; wait"], timeout=2)
        self.assertLess(time.monotonic() - started, 20)
        self.assertIs(run["timed_out"], True)
        self.assertEqual(run["exit_code"], -signal.SIGKILL)
        self.assertTrue(gone(int(pidfile.read_text())), "the grandchild outlived the timeout")

    def test_a_grandchild_left_behind_after_a_normal_exit_is_killed(self):
        pidfile = self.dir / "leftover.pid"
        run = self.run_child(["sh", "-c", f"sleep 300 & echo $! > {pidfile}; exit 0"], timeout=60)
        self.assertEqual((run["exit_code"], run["timed_out"]), (0, False))
        self.assertTrue(gone(int(pidfile.read_text())), "a leftover grandchild survived")

    def test_output_cap_truncates_exactly_and_kills(self):
        writer = "import sys\nwhile True:\n    sys.stdout.write('x' * 4096)\n    sys.stdout.flush()\n"
        run = self.run_child([sys.executable, "-c", writer], max_output=10000, timeout=60)
        self.assertIs(run["truncated"], True)
        self.assertIs(run["timed_out"], False)
        self.assertEqual(run["output"], b"x" * 10000)
        self.assertEqual(run["exit_code"], -signal.SIGKILL)

    def test_output_cap_also_kills_a_writing_grandchild(self):
        pidfile = self.dir / "writer.pid"
        # The grandchild records its own pid before it writes a byte, then becomes the writer.
        script = f"sh -c 'echo $$ > {pidfile}; exec yes xxxxxxxxxxxxxxxx' & wait"
        run = self.run_child(["sh", "-c", script], max_output=5000, timeout=60)
        self.assertIs(run["truncated"], True)
        self.assertEqual(len(run["output"]), 5000)
        self.assertTrue(gone(int(pidfile.read_text())), "the writing grandchild survived")

    def test_output_at_the_cap_is_not_truncated(self):
        run = self.run_child(["sh", "-c", "printf 0123456789"], max_output=10)
        self.assertEqual((run["output"], run["truncated"], run["exit_code"]),
                         (b"0123456789", False, 0))

    def test_stdin_is_delivered_in_full(self):
        payload = bytes(range(256)) * 12289
        run = self.run_child(["cat"], stdin_bytes=payload, max_output=len(payload))
        self.assertEqual((run["exit_code"], run["output"]), (0, payload))
        empty = self.run_child(["cat"], stdin_bytes=b"")
        self.assertEqual((empty["exit_code"], empty["output"]), (0, b""))

    def test_a_child_that_never_reads_stdin_cannot_stall_the_deadline(self):
        started = time.monotonic()
        run = self.run_child(["sh", "-c", "sleep 300"], stdin_bytes=b"y" * (8 << 20), timeout=2)
        self.assertLess(time.monotonic() - started, 20)
        self.assertIs(run["timed_out"], True)
        self.assertEqual(run["exit_code"], -signal.SIGKILL)

    def test_a_child_that_cannot_start_is_exit_127(self):
        run = self.run_child([str(self.dir / "no-such-program")])
        self.assertEqual(run, {"exit_code": 127, "output": b"", "timed_out": False,
                               "truncated": False, "seconds": 0,
                               "network_namespace": NETNS_NOT_REQUESTED})

    def test_core_cpu_and_file_size_limits_reach_the_child(self):
        shown = self.run_child(["sh", "-c", "ulimit -c; ulimit -t; ulimit -f"], cpu_seconds=7,
                               file_bytes=4 << 20)
        self.assertEqual(shown["output"].split(), [b"0", b"7", b"8192"])
        spin = self.run_child([sys.executable, "-c", "while True: pass"], cpu_seconds=1, timeout=60)
        self.assertIs(spin["timed_out"], False)
        self.assertIn(spin["exit_code"], (-signal.SIGXCPU, -signal.SIGKILL))
        target = self.dir / "big.bin"
        self.run_child(["sh", "-c", f"head -c 100000 /dev/zero > {target}"], file_bytes=1000)
        self.assertLessEqual(target.stat().st_size, 1000)


class NetworkNamespaceTests(_Scratch):
    def test_isolation_is_reported_exactly_as_this_host_provided_it(self):
        state = network_namespace_state()
        self.assertIn(state, (NETNS_EMPTY, NETNS_UNAVAILABLE))
        run = self.run_child(["sh", "-c", LISTING], isolate_network=True)
        self.assertEqual(run["exit_code"], 0)
        self.assertEqual(run["network_namespace"], state)
        if state == NETNS_EMPTY:
            self.assertEqual(interfaces(run["output"]), ["lo"])
        else:
            # No isolation was available: the child still ran, and says it was not isolated.
            self.assertEqual(run["network_namespace"], NETNS_UNAVAILABLE)
            self.assertTrue(run["output"])

    def test_without_isolation_the_host_namespace_is_used_and_said(self):
        run = self.run_child(["sh", "-c", LISTING])
        self.assertEqual((run["exit_code"], run["network_namespace"]), (0, NETNS_NOT_REQUESTED))

    def test_a_host_without_namespaces_still_runs_the_child_and_says_so(self):
        # Simulates the refusing host (for example a runner that restricts user namespaces).
        with mock.patch.object(common, "_NETNS_STATE", [NETNS_UNAVAILABLE]):
            run = self.run_child(["sh", "-c", "echo ran"], isolate_network=True)
        self.assertEqual((run["exit_code"], run["output"]), (0, b"ran\n"))
        self.assertEqual(run["network_namespace"], NETNS_UNAVAILABLE)

    def test_probe_without_an_unshare_binary_is_unavailable(self):
        with mock.patch.object(common, "_UNSHARE_SEARCH", str(self.dir)):
            self.assertIsNone(common._unshare_prefix())
            self.assertEqual(common._probe_network_namespace(), NETNS_UNAVAILABLE)
            with mock.patch.object(common, "_NETNS_STATE", [NETNS_EMPTY]):
                # The binary vanished after the probe: the run is not isolated and says so.
                run = self.run_child(["sh", "-c", "echo ran"], isolate_network=True)
        self.assertEqual((run["exit_code"], run["network_namespace"]), (0, NETNS_UNAVAILABLE))

    def test_states_are_the_three_named_ones(self):
        self.assertEqual(NETNS_STATES, ("EMPTY_NETWORK_NAMESPACE", "NOT_AVAILABLE_ON_THIS_HOST",
                                        "NOT_REQUESTED"))
        self.assertEqual(network_namespace_state(), network_namespace_state())


class LeanCodeOnlyLiteralTests(TestCase):
    def test_strings_hide_comment_markers_but_not_code(self):
        self.assertEqual(lean_code_only('def s := "/- not a comment" ; theorem t := sorry'),
                         'def s := "" ; theorem t := sorry')
        self.assertEqual(lean_code_only('def s := "-- not a comment" sorry'), 'def s := "" sorry')
        self.assertEqual(lean_code_only('"a \\" -- still string" sorry'), '"" sorry')
        self.assertEqual(lean_code_only('"gap \\\n   continues" sorry'), '"" sorry')
        self.assertEqual(lean_code_only('"sorry"'), '""')

    def test_raw_strings(self):
        self.assertEqual(lean_code_only('r"raw /- -- \\" sorry'), '"" sorry')
        self.assertEqual(lean_code_only('r#"has "quotes" and -/ "# sorry'), '"" sorry')
        self.assertEqual(lean_code_only('r##"a "# b"## sorry'), '"" sorry')
        # An r that ends an identifier does not open a raw string.
        self.assertEqual(lean_code_only('xr"q" sorry'), 'xr"" sorry')

    def test_character_literals(self):
        for literal in ("'\"'", "'-'", "'/'", "'\\''", "'\\\\'", "'\\n'", "'\\x41'", "'\\u03bb'",
                        "'λ'"):
            with self.subTest(literal=literal):
                self.assertEqual(lean_code_only(f"c := {literal} -- x\nsorry"), 'c := "" \nsorry')

    def test_primes_are_names_not_characters(self):
        for source in ("theorem h' : x' = x'' := sorry", "h₀' sorry'", "f' 'a'"):
            with self.subTest(source=source):
                self.assertIn("sorry" if "sorry" in source else "f'", lean_code_only(source))
        self.assertEqual(lean_code_only("f' 'a'"), "f' \"\"")
        # Lean reads x₁' as one name, so the quote after it opens a string that hides the sorry.
        self.assertEqual(lean_code_only("x₁'\"' sorry \""), "x₁'\"\"")
        self.assertEqual(lean_code_only("α'\"' sorry \""), "α'\"\"")

    def test_nested_and_line_comments_ignore_literals_inside_them(self):
        self.assertEqual(lean_code_only("/- a /- b -/ c -/ sorry"), " sorry")
        self.assertEqual(lean_code_only("/- \"-/\" -/ sorry"), '""')
        self.assertEqual(lean_code_only("-- \"\nsorry"), "\nsorry")
        self.assertEqual(lean_code_only("-- /- \nsorry"), "\nsorry")
        self.assertEqual(lean_code_only("x/--doc-/ sorry"), "x sorry")


class WriteNewBytesTests(_Scratch):
    def test_creates_a_new_file(self):
        target = self.dir / "new.log"
        write_new_bytes(target, b"evidence")
        self.assertEqual(target.read_bytes(), b"evidence")

    def test_refuses_an_existing_file_and_leaves_it_unchanged(self):
        target = self.dir / "kept.log"
        target.write_bytes(b"original")
        with self.assertRaises(FileExistsError):
            write_new_bytes(target, b"replacement")
        self.assertEqual(target.read_bytes(), b"original")

    def test_refuses_a_symlink_and_never_writes_through_it(self):
        victim = self.dir / "victim.txt"
        victim.write_bytes(b"untouched")
        link = self.dir / "link.log"
        os.symlink(victim, link)
        with self.assertRaises(OSError):
            write_new_bytes(link, b"through the link")
        self.assertEqual(victim.read_bytes(), b"untouched")
        dangling = self.dir / "dangling.log"
        os.symlink(self.dir / "not-yet-there", dangling)
        with self.assertRaises(OSError):
            write_new_bytes(dangling, b"x")
        self.assertFalse((self.dir / "not-yet-there").exists())


class RationalTextTests(TestCase):
    def test_text_above_the_digit_limit_is_a_typed_refusal(self):
        if not hasattr(sys, "set_int_max_str_digits"):
            self.fail("this suite targets Python 3.11 or later")
        previous = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(4300)
        try:
            with self.assertRaises(InputError) as caught:
                rational_text(Fraction(10 ** 5000))
            self.assertEqual(caught.exception.code, "RATIONAL_TOO_LARGE")
            self.assertEqual(rational_text(Fraction(10 ** 4299, 3)), "1" + "0" * 4299 + "/3")
        finally:
            sys.set_int_max_str_digits(previous)


class EscapedGrandchildTests(_Scratch):
    """A grandchild that leaves the process group with setsid() must still die with the child."""

    def test_setsid_grandchild_dies_with_a_timed_out_isolated_child(self):
        marker = self.dir / "grandchild.pid"
        script = f"setsid sh -c 'echo $$ > {marker}; exec sleep 300' & sleep 60"
        run = self.run_child(["sh", "-c", script], isolate_network=True, timeout=2)
        self.assertTrue(run["timed_out"])
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        if run["network_namespace"] != NETNS_EMPTY:
            # Without a PID namespace only the process group is killed; that is what is claimed.
            self.assertEqual(run["network_namespace"], NETNS_UNAVAILABLE)
            if marker.exists():
                pid = int(marker.read_text().split()[0])
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    # Already gone: the cleanup this branch exists for has happened.
                    pass
            return
        self.assertTrue(marker.exists())
        # The pid written inside the namespace is not the host pid, so check by command line.
        self.assertTrue(gone_by_cmdline("sleep 300"), "a setsid grandchild survived")


def gone_by_cmdline(needle, wait=10.0):
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        alive = False
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                raw = (entry / "cmdline").read_bytes()
                state = (entry / "stat").read_text().rsplit(")", 1)[1].split()[0]
            except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
                continue
            if raw.replace(b"\0", b" ").strip() == needle.encode() and state not in ("Z", "X"):
                alive = True
                break
        if not alive:
            return True
        time.sleep(0.1)
    return False


if __name__ == "__main__":
    unittest_main()

"""Unit tests for tools/projector.py's pure-stdlib RFC 8785 JCS fallback (issue #53).

Runs under both:
  - `uv run --with rfc8785 python -m unittest discover -s tests/projector -v`
    (verifies byte-for-byte parity between `_stdlib_jcs_dumps` and `rfc8785.dumps`), and
  - `python3 -I -m unittest discover -s tests/projector -v`
    (verifies zero third-party dependency execution on bare target hosts).
"""

from __future__ import annotations

import importlib.util
import json
import math
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROJECTOR_PATH = REPO / "tools" / "projector.py"


def _load_projector():
    spec = importlib.util.spec_from_file_location("tendcf_projector_under_test", PROJECTOR_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


try:
    import rfc8785 as _ref_rfc8785
except ModuleNotFoundError:
    _ref_rfc8785 = None


class StdlibJcsFallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.proj = _load_projector()

    def assert_matches_reference(self, obj: object, expected: bytes | None = None) -> None:
        got = self.proj._stdlib_jcs_dumps(obj)
        if expected is not None:
            self.assertEqual(got, expected)
        if _ref_rfc8785 is not None:
            ref = _ref_rfc8785.dumps(obj)
            self.assertEqual(got, ref, f"mismatch vs rfc8785.dumps for {obj!r}")

    def test_primitives_and_containers(self) -> None:
        cases: list[tuple[object, bytes]] = [
            (None, b"null"),
            (True, b"true"),
            (False, b"false"),
            (0, b"0"),
            (-1, b"-1"),
            (42, b"42"),
            (2**53 - 1, b"9007199254740991"),
            (-(2**53) + 1, b"-9007199254740991"),
            ([], b"[]"),
            ({}, b"{}"),
            ([1, True, False, None, "a", [], {}], b'[1,true,false,null,"a",[],{}]'),
            ((1, 2, 3), b"[1,2,3]"),
        ]
        for obj, expected in cases:
            with self.subTest(obj=obj):
                self.assert_matches_reference(obj, expected)

    def test_string_control_escapes_and_unicode(self) -> None:
        # RFC 8785 §3.2.2.2: control chars U+0000..U+001F, quote, backslash,
        # raw UTF-8 for everything else (BMP + astral).
        self.assert_matches_reference(
            '\x00\x01\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x1f"\\/',
            rb'"\u0000\u0001\u0007\b\t\n\u000b\f\r\u000e\u000f\u001f\"\\/"',
        )
        for cp in range(0x20):
            with self.subTest(cp=cp):
                self.assert_matches_reference(chr(cp))

        # RFC 8785 §3.2.2 example string + U+007F (DEL, unescaped) + BMP/astral Unicode
        self.assert_matches_reference(
            "\u20ac$\u000f\nA'B\"\\\\\"/",
            '"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"'.encode("utf-8"),
        )
        self.assert_matches_reference("\x7f", b'"\x7f"')
        self.assert_matches_reference("日本語 😀 € café", '"日本語 😀 € café"'.encode("utf-8"))

    def test_utf16be_key_sorting_traps(self) -> None:
        # UTF-16BE vs UTF-8 trap:
        #   U+E000 encodes in UTF-8 as EE 80 80, in UTF-16BE as E0 00.
        #   U+10000 encodes in UTF-8 as F0 90 80 80, in UTF-16BE as D8 00 DC 00.
        # In UTF-8: U+E000 < U+10000. In UTF-16BE (RFC 8785): U+10000 < U+E000!
        trap = {"\uE000": 1, "\U00010000": 2, "\uD7FF": 3}
        expected = '{"\uD7FF":3,"\U00010000":2,"\uE000":1}'.encode("utf-8")
        self.assert_matches_reference(trap, expected)

        # RFC 8785 §3.2.3 official sorting example
        rfc_sort = {
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "1": "One",
            "\u0080": "Control",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "\U0001f600": "Emoji: Grinning Face",
            "\u00f6": "Latin Small Letter O With Diaeresis",
        }
        got = self.proj._stdlib_jcs_dumps(rfc_sort)
        self.assert_matches_reference(rfc_sort)
        # Verify exact key order per RFC 8785 §3.2.3
        keys_in_order = list(json.loads(got).keys())
        self.assertEqual(
            keys_in_order,
            ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001f600", "\ufb33"],
        )

    def test_float_serialization_rfc8785_vectors(self) -> None:
        float_cases: list[tuple[float, bytes]] = [
            (0.0, b"0"),
            (-0.0, b"0"),
            (1.0, b"1"),
            (-1.0, b"-1"),
            (0.1 + 0.2, b"0.30000000000000004"),
            (4.50, b"4.5"),
            (2e-3, b"0.002"),
            (1e-4, b"0.0001"),
            (1e-5, b"0.00001"),
            (1.5e-5, b"0.000015"),
            (1e-6, b"0.000001"),
            (1e-7, b"1e-7"),
            (1e-27, b"1e-27"),
            (333333333.33333329, b"333333333.3333333"),
            (1e15, b"1000000000000000"),
            (1e16, b"10000000000000000"),
            (1.23e16, b"12300000000000000"),
            (1e20, b"100000000000000000000"),
            (1e21, b"1e+21"),
            (1e30, b"1e+30"),
            (-1e-7, b"-1e-7"),
            (-1e21, b"-1e+21"),
            (5e-324, b"5e-324"),
            (sys.float_info.max, b"1.7976931348623157e+308"),
            (sys.float_info.min, b"2.2250738585072014e-308"),
        ]
        for val, expected in float_cases:
            with self.subTest(val=val):
                self.assert_matches_reference(val, expected)

    def test_all_repo_projections_and_fixtures_match_reference(self) -> None:
        paths = sorted(
            list((REPO / "deploy").glob("**/host_specific*.json"))
            + [REPO / "examples" / "host_specific.json", REPO / "examples" / "goal-file.json"]
            + list((REPO / "tests" / "policy" / "fixtures").glob("*.json"))
        )
        self.assertGreater(len(paths), 10)
        for p in paths:
            raw = p.read_bytes()
            try:
                doc = json.loads(raw)
            except json.JSONDecodeError:
                continue
            with self.subTest(path=str(p.relative_to(REPO))):
                self.assert_matches_reference(doc)

        # Golden projection check using stdlib fallback directly
        goal = json.loads((REPO / "examples" / "goal-file.json").read_bytes())
        expected_golden = (REPO / "examples" / "host_specific.json").read_bytes()
        orig = self.proj._rfc8785
        try:
            self.proj._rfc8785 = None
            self.assertEqual(self.proj.project(goal), expected_golden)
            self.assertEqual(self.proj.validate_projection(expected_golden), [])
        finally:
            self.proj._rfc8785 = orig

    def test_negative_cases_rejected(self) -> None:
        bad_values: list[object] = [
            float("nan"),
            float("inf"),
            float("-inf"),
            2**53,
            -(2**53),
            10**30,
            "\ud800",
            "\udfff",
            {"\ud800": "v"},
            {1: "non-string-key"},
            {1, 2},
            object(),
        ]
        for val in bad_values:
            with self.subTest(val=repr(val)):
                with self.assertRaises((ValueError, TypeError)):
                    self.proj._stdlib_jcs_dumps(val)
                if _ref_rfc8785 is not None:
                    with self.assertRaises((ValueError, TypeError)):
                        _ref_rfc8785.dumps(val)

        # check_projection catches un-canonicalizable / non-canonical inputs without crashing
        orig = self.proj._rfc8785
        try:
            self.proj._rfc8785 = None
            for raw in (
                b'{"vars":{}}\n',
                b'{"vars": {}}',
                b'{"vars":{"b":1,"a":2}}',
                b'{"vars":{"x":NaN}}',
                b'{"vars":{"x":Infinity}}',
                b'{"vars":{"x":1e999}}',
                b'{"vars":{"x":9007199254740992}}',
                b'{"vars":{"x":"\\ud800"}}',
                b'{"vars":{"tendcf_service":{"a":' + b"[" * 50000 + b"]" * 50000 + b"}}}",
            ):
                findings = self.proj.check_projection(raw)
                self.assertTrue(
                    any(f.rule == self.proj.RULE_PROJECTION_BYTES for f in findings),
                    f"expected RULE_PROJECTION_BYTES for {raw[:60]!r}, got {findings!r}",
                )
        finally:
            self.proj._rfc8785 = orig

    def test_nul_escape_rejected_in_key_and_value_positions(self) -> None:
        """Issue #67/#69: tools/projector.py rejects \\u0000 in both key and value positions."""
        # 1. Key position (in both check_projection and project)
        nul_key_raw = (
            b'{"vars":{"tendcf_service":{"demo\\u0000svc":{"bundle":"demo",'
            b'"command":["/usr/bin/sleep","1"],"run_as":"nobody","state":"present",'
            b'"unit":{"runit":{"enabled":true}},"working_dir":"/"}}}}'
        )
        key_findings = self.proj.check_projection(nul_key_raw)
        self.assertTrue(
            any(
                f.rule == self.proj.RULE_PROJECTION
                and "(key)" in f.msg
                and "forbidden control character" in f.msg
                for f in key_findings
            ),
            f"expected key-position control-char finding, got {key_findings!r}",
        )

        # 2. Value position (in check_projection)
        nul_val_raw = (
            b'{"vars":{"tendcf_service":{"demo-svc":{"bundle":"demo",'
            b'"command":["/usr/bin/sleep","1"],"run_as":"nobody","state":"present",'
            b'"unit":{"runit":{"enabled":true}},"working_dir":"/srv\\u0000bad"}}}}'
        )
        val_findings = self.proj.check_projection(nul_val_raw)
        self.assertTrue(
            any(
                f.rule == self.proj.RULE_PROJECTION
                and "working_dir" in f.msg
                and "forbidden control character" in f.msg
                for f in val_findings
            ),
            f"expected value-position control-char finding, got {val_findings!r}",
        )

        # 3. project() refuses goal files carrying NUL in either key or value
        for label, svc_id, wdir in (
            ("key", "demo\x00svc", "/"),
            ("value", "demo-svc", "/srv\x00bad"),
        ):
            with self.subTest(position=label):
                goal = {
                    "domains": {
                        "supervision": {
                            "entries": {
                                "service": {
                                    svc_id: {
                                        "bundle": "demo",
                                        "command": ["/usr/bin/sleep", "1"],
                                        "run_as": "nobody",
                                        "state": "present",
                                        "unit": {"runit": {"enabled": True}},
                                        "working_dir": wdir,
                                    }
                                }
                            }
                        }
                    }
                }
                with self.assertRaises(self.proj.ProjectionRefused) as ctx:
                    self.proj.project(goal)
                self.assertIn("forbidden control character", str(ctx.exception))

    def test_iterative_walk_and_oversized_early_return(self) -> None:
        # 1. Exact pre-order traversal parity with a reference recursive walk
        def _ref_walk(node: object, path: str = ""):
            yield path or "<root>", node
            if isinstance(node, dict):
                for key, value in node.items():
                    here = f"{path}/{key}" if path else str(key)
                    yield f"{here} (key)", key
                    yield from _ref_walk(value, here)
            elif isinstance(node, list):
                for idx, value in enumerate(node):
                    here = f"{path}/{idx}" if path else str(idx)
                    yield from _ref_walk(value, here)

        nested = {
            "vars": {
                "a": [1, {"b": [2, 3], "c": {}}, []],
                "d": {"e": "x", "f": None},
            },
            "empty": {},
        }
        self.assertEqual(list(self.proj._walk(nested)), list(_ref_walk(nested)))
        self.assertEqual(list(self.proj._walk(nested, "top")), list(_ref_walk(nested, "top")))

        # 2. Lazy first-child visit + O(depth) bounded memory on a wide array under a long key
        long_key = "k" * 2048
        width = 10000
        wide = {"vars": {long_key: list(range(width))}}
        # Eager materialization of all child pointers would require > width * len(long_key) (~20 MB).
        tracemalloc.start()
        try:
            it = self.proj._walk(wide)
            first_ten = [next(it) for _ in range(10)]
            _cur_10, peak_10 = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(len(first_ten), 10)
        self.assertEqual(first_ten[0], ("<root>", wide))
        self.assertEqual(first_ten[5], (f"vars/{long_key}/0", 0))
        self.assertEqual(first_ten[9], (f"vars/{long_key}/4", 4))
        self.assertLess(
            peak_10,
            512 * 1024,
            f"lazy first-10 _walk allocated {peak_10} bytes (expected O(1), not O(width * key_len))",
        )

        tracemalloc.start()
        try:
            walked_count = sum(1 for _ in self.proj._walk(wide))
            _cur_full, peak_full = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(walked_count, width + 5)
        self.assertLess(
            peak_full,
            2 * 1024 * 1024,
            f"full _walk peak memory {peak_full} bytes exceeded O(depth) bound",
        )

        # 3. Oversized payload (> MAX_PROJECTION_BYTES) returns immediately with RULE_PROJECTION_BYTES
        oversized = b'{"vars":{"a":"' + b"x" * (self.proj.MAX_PROJECTION_BYTES + 16) + b'"}}'
        findings = self.proj.check_projection(oversized)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, self.proj.RULE_PROJECTION_BYTES)

    def test_isolated_python_subprocess_cli(self) -> None:
        """Prove `python3 -I -S tools/projector.py` works hermetically with stdlib only."""
        valid_files = [
            REPO / "examples" / "host_specific.json",
            REPO / "deploy" / "linux" / "canary" / "host_specific.json",
            REPO / "deploy" / "linux" / "canary" / "host_specific-absent.json",
            REPO / "deploy" / "darwin" / "canary" / "host_specific.json",
            REPO / "deploy" / "darwin" / "canary" / "host_specific-absent.json",
        ]
        for vf in valid_files:
            with self.subTest(valid=str(vf.relative_to(REPO))):
                r = subprocess.run(
                    [sys.executable, "-I", "-S", str(PROJECTOR_PATH), "--check", str(vf)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("projector: OK", r.stdout)

        with tempfile.TemporaryDirectory() as td:
            # 1. Trailing newline (non-canonical JCS)
            bad_nl = Path(td) / "trailing-nl.json"
            bad_nl.write_bytes((REPO / "deploy" / "linux" / "canary" / "host_specific.json").read_bytes() + b"\n")
            r = subprocess.run(
                [sys.executable, "-I", "-S", str(PROJECTOR_PATH), "--check", str(bad_nl)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("projector: FAIL:", r.stdout)

            # 2. Forbidden pre_action argv space
            bad_argv = Path(td) / "bad-argv.json"
            bad_argv.write_bytes(
                b'{"vars":{"tendcf_interlock":{"bad-check":{"blocks":"enclosing-bundle",'
                b'"bundle":"demo","defines_class":"demo_ok","pre_action":{"command":'
                b'["/usr/bin/true","arg with space"],"expect_exit":0,"timeout_seconds":5},'
                b'"report":true,"state":"present"}}}}'
            )
            r = subprocess.run(
                [sys.executable, "-I", "-S", str(PROJECTOR_PATH), "--check", str(bad_argv)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("interlock_argv", r.stdout)

            # 3. Empty vars projection is valid
            empty_vars = Path(td) / "empty.json"
            empty_vars.write_bytes(b'{"vars":{}}')
            r = subprocess.run(
                [sys.executable, "-I", "-S", str(PROJECTOR_PATH), "--check", str(empty_vars)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

            # 4. Deeply nested JSON handled cleanly (no traceback) in BOTH --check and goal-file modes
            deep_proj = Path(td) / "deep-proj.json"
            deep_proj.write_bytes(b'{"vars":{"a":' + b"[" * 50000 + b"]" * 50000 + b"}}")
            r_check = subprocess.run(
                [sys.executable, "-I", "-S", str(PROJECTOR_PATH), "--check", str(deep_proj)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_check.returncode, 1, r_check.stdout + r_check.stderr)
            self.assertNotIn("Traceback", r_check.stderr)
            self.assertIn("projector: FAIL:", r_check.stdout)

            # In goal-file mode, Python <=3.14 hits RecursionError in json.loads (rc 2),
            # while Python 3.15+'s iterative JSON parser parses it and hits RecursionError
            # in copy.deepcopy / _jcs_dumps -> ProjectionRefused (rc 1). Neither leaks a traceback.
            deep_goal = Path(td) / "deep-goal.json"
            deep_goal.write_bytes(
                b'{"domains":{"supervision":{"entries":{"service":{"a":{"x":'
                + b"[" * 50000
                + b"]" * 50000
                + b"}}}}}}"
            )
            r_goal = subprocess.run(
                [sys.executable, "-I", "-S", str(PROJECTOR_PATH), str(deep_goal)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertIn(r_goal.returncode, (1, 2), r_goal.stdout + r_goal.stderr)
            self.assertNotIn("Traceback", r_goal.stderr)
            self.assertTrue(
                "projector: ERROR:" in r_goal.stderr or "projector: REFUSED:" in r_goal.stderr,
                r_goal.stderr,
            )


if __name__ == "__main__":
    unittest.main()

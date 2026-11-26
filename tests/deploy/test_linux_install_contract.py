"""Contract and hermetic behavioral tests for deploy/linux/tendcf-install.sh (#53, #57, #58)."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INSTALLER = REPO / "deploy" / "linux" / "tendcf-install.sh"
PROJECTOR = REPO / "bin" / "projector.py"
CANARY_PRESENT = REPO / "deploy" / "linux" / "canary" / "host_specific.json"
CANARY_ABSENT = REPO / "deploy" / "linux" / "canary" / "host_specific-absent.json"

OK_CF_SCRIPT = (
    "#!/bin/sh\n"
    "echo 'any   hardclass'\n"
    "echo 'tendcf_cmdb_evaluated   source=promise'\n"
    "exit 0\n"
)


def _extract_func(src: str, name: str) -> str:
    lines = src.splitlines(keepends=True)
    header_re = re.compile(rf"^{re.escape(name)}\(\) \{{")
    heredoc_re = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
    start = None
    for idx, line in enumerate(lines):
        if header_re.match(line):
            start = idx
            break
    if start is None:
        raise AssertionError(f"function {name}() not found in {INSTALLER}")
    out: list[str] = []
    heredoc_end: str | None = None
    for line in lines[start:]:
        out.append(line)
        if heredoc_end is not None:
            if line.rstrip("\r\n") == heredoc_end:
                heredoc_end = None
            continue
        if not line.lstrip().startswith("#"):
            hm = heredoc_re.search(line)
            if hm is not None:
                heredoc_end = hm.group(1)
                continue
        if line.rstrip("\r\n") == "}":
            return "".join(out)
    raise AssertionError(f"unterminated function {name}() in {INSTALLER}")


def _make_linux_shims(shim_dir: Path, *, real_uid: bool = False) -> None:
    """Provide non-root/macOS shims for Linux-only commands (chown, GNU stat, sha256sum, flock)."""
    chown_shim = shim_dir / "chown"
    chown_shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    chown_shim.chmod(0o755)

    stat_shim = shim_dir / "stat"
    if real_uid:
        stat_shim.write_text(
            f"#!{sys.executable}\n"
            "import os, stat, sys\n"
            "fmt = sys.argv[2]\n"
            "p = sys.argv[3]\n"
            "st = os.lstat(p)\n"
            "mode = stat.S_IMODE(st.st_mode)\n"
            "if fmt == '%U:%G %a':\n"
            "    print(f'{st.st_uid}:{st.st_gid} {mode:o}')\n"
            "elif fmt == '%u %g %a':\n"
            "    print(f'{st.st_uid} {st.st_gid} {mode:o}')\n"
            "elif fmt == '%u %a':\n"
            "    print(f'{st.st_uid} {mode:o}')\n"
            "elif fmt == '%u':\n"
            "    print(f'{st.st_uid}')\n"
            "else:\n"
            "    raise SystemExit(f'unexpected stat fmt: {fmt}')\n",
            encoding="utf-8",
        )
    else:
        stat_shim.write_text(
            f"#!{sys.executable}\n"
            "import os, stat, sys\n"
            "fmt = sys.argv[2]\n"
            "p = sys.argv[3]\n"
            "st = os.lstat(p)\n"
            "mode = stat.S_IMODE(st.st_mode)\n"
            "if fmt == '%U:%G %a':\n"
            "    print(f'root:root {mode:o}')\n"
            "elif fmt == '%u %g %a':\n"
            "    print(f'0 0 {mode:o}')\n"
            "elif fmt == '%u %a':\n"
            "    print(f'0 {mode:o}')\n"
            "elif fmt == '%u':\n"
            "    print('0')\n"
            "else:\n"
            "    raise SystemExit(f'unexpected stat fmt: {fmt}')\n",
            encoding="utf-8",
        )
    stat_shim.chmod(0o755)

    real_install = shutil.which("install") or "/usr/bin/install"
    install_shim = shim_dir / "install"
    install_shim.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"real = {real_install!r}\n"
        "args = [real]\n"
        "i = 1\n"
        "while i < len(sys.argv):\n"
        "    if sys.argv[i] in ('-o', '-g') and i + 1 < len(sys.argv):\n"
        "        i += 2\n"
        "    else:\n"
        "        args.append(sys.argv[i])\n"
        "        i += 1\n"
        "os.execv(real, args)\n",
        encoding="utf-8",
    )
    install_shim.chmod(0o755)

    if shutil.which("sha256sum") is None:
        sha_shim = shim_dir / "sha256sum"
        sha_shim.write_text(
            f"#!{sys.executable}\n"
            "import hashlib, pathlib, sys\n"
            "p = sys.argv[1]\n"
            "h = hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()\n"
            "print(f'{h}  {p}')\n",
            encoding="utf-8",
        )
        sha_shim.chmod(0o755)

    if shutil.which("flock") is None:
        flock_shim = shim_dir / "flock"
        flock_shim.write_text(
            f"#!{sys.executable}\n"
            "import fcntl, sys\n"
            "fd = int(sys.argv[-1])\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n",
            encoding="utf-8",
        )
        flock_shim.chmod(0o755)


class LinuxInstallerHardeningContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.src = INSTALLER.read_text(encoding="utf-8")

    def test_bash_syntax_passes(self) -> None:
        r = subprocess.run(
            ["/bin/bash", "-n", str(INSTALLER)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_privileged_shebang_env_sanitization_scoped_ld_library_path_and_no_tmpdir(self) -> None:
        self.assertTrue(self.src.startswith("#!/bin/bash -p\n"))
        non_comment = "\n".join(
            line for line in self.src.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIn("compgen -e", non_comment)
        self.assertIn(
            "/usr/bin/env -i TENDCF_CLEAN_ENV=1 PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /bin/bash -p",
            non_comment,
        )
        self.assertNotIn("export LD_LIBRARY_PATH", non_comment)
        self.assertNotIn("TMPDIR", non_comment)
        self.assertIn('LD_LIBRARY_PATH="$cf_lib_path" "$cf_promises"', non_comment)
        self.assertIn('LD_LIBRARY_PATH="$cf_lib_path" "$cf_agent"', non_comment)
        self.assertIn('LD_LIBRARY_PATH="$cf_lib_path" "$cf_key"', non_comment)
        self.assertIn('LD_LIBRARY_PATH="$cf_lib_path" ldd "$bin"', non_comment)

        find_py = _extract_func(self.src, "find_trusted_python")
        self.assertNotIn("command -v", find_py)
        self.assertIn("/usr/bin/python3 /bin/python3", find_py)

        init_fn = _extract_func(self.src, "init_paths")
        self.assertIn('check_ancestors_ok "$prefix"', init_fn)
        self.assertIn("mktemp /tmp/tendcf-probe.XXXXXX", init_fn)

        ct_fn = _extract_func(self.src, "check_tree")
        self.assertIn('check_ancestors_ok "$prefix"', ct_fn)

    def test_direct_invocation_ignores_bash_env_and_exported_bash_func(self) -> None:
        """Codex #2: #!/bin/bash -p suppresses BASH_ENV and BASH_FUNC_* before line 1."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "pwned.marker"
            bash_env = root / "evil.sh"
            bash_env.write_text(f'echo PWN_BASH_ENV > "{marker}"\n', encoding="utf-8")
            env = dict(os.environ)
            env["BASH_ENV"] = str(bash_env)
            env["BASH_FUNC_say%%"] = f'() {{ echo PWN_FUNC > "{marker}"; }}'
            env["BASH_FUNC_die%%"] = f'() {{ echo PWN_DIE > "{marker}"; exit 99; }}'
            r = subprocess.run(
                [str(INSTALLER)],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse(marker.exists(), "BASH_ENV or BASH_FUNC_* executed despite #!/bin/bash -p")

    def test_contract_gates_locking_fd9_rollback_and_unique_paths(self) -> None:
        cmd_fn = _extract_func(self.src, "cmd_install")
        self.assertIn("--projector-src)", cmd_fn)
        self.assertIn("--projector-sha256)", cmd_fn)
        self.assertIn('[ -n "$2" ]', cmd_fn)
        idx_preval = cmd_fn.find('prevalidate_install_inputs "$datafile"')
        idx_prep = cmd_fn.find("prepare_projector_source")
        idx_detach = cmd_fn.find("detach_unsafe_installed_projector")
        idx_tree = cmd_fn.find("check_tree")
        idx_policy = cmd_fn.find("place_policy")
        idx_proj = cmd_fn.find("place_projector")
        idx_data = cmd_fn.find('put_data "$datafile"')
        for lbl, idx in (
            ("prevalidate", idx_preval),
            ("prepare_projector_source", idx_prep),
            ("detach_unsafe_installed_projector", idx_detach),
            ("check_tree", idx_tree),
            ("place_policy", idx_policy),
            ("place_projector", idx_proj),
            ("put_data", idx_data),
        ):
            self.assertNotEqual(idx, -1, f"missing {lbl} in cmd_install")
        self.assertLess(idx_preval, idx_prep)
        self.assertLess(idx_prep, idx_detach)
        self.assertLess(idx_detach, idx_tree)
        self.assertLess(idx_policy, idx_proj)
        self.assertLess(idx_proj, idx_data)

        # Codex R4 #1 & R5 #2: place_projector operates exclusively from $prepared_projector_file and never re-calls prepare_projector_source
        proj_fn = _extract_func(self.src, "place_projector")
        proj_code = "\n".join(line for line in proj_fn.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("readlink", proj_code)
        self.assertNotIn("$projector_src", proj_code)
        self.assertNotIn("prepare_projector_source", proj_code)
        self.assertIn("$prepared_projector_file", proj_code)

        # Codex R7 #1: detach_unsafe_installed_projector NEVER mutates directory ownership/permissions
        detach_fn = _extract_func(self.src, "detach_unsafe_installed_projector")
        detach_code = "\n".join(line for line in detach_fn.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("chown", detach_code)
        self.assertNotIn("chmod", detach_code)
        self.assertLess(detach_code.find('check_dir_root_unwritable "$d"'), detach_code.find('rm -f "$installed_projector"'))

        put_fn = _extract_func(self.src, "put_data")
        put_code = "\n".join(line for line in put_fn.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("$data.new", put_code)
        self.assertNotIn("$data.previous", put_code)
        self.assertIn('mktemp -d "$workdir/.putdata.XXXXXX"', put_code)
        self.assertIn('[ -f "$lockfile" ] && [ ! -L "$lockfile" ]', put_code)
        self.assertIn("flock -x 9", put_code)
        self.assertIn(".host_specific.new.XXXXXX", put_code)
        self.assertIn(".host_specific.prev.XXXXXX", put_code)
        self.assertIn('"$py" -I -S "$installed_projector" --check "$staged_data" 9>&-', put_code)

        idx_gate1 = put_code.find('"$installed_projector" --check "$staged_data" 9>&-')
        idx_gate2 = put_code.find('validate_cmdb_workdir "$stage_wd"')
        idx_bytes = put_code.find('data_bytes="$(wc -c < "$staged_data"')
        idx_arm = put_code.find("put_data_rollback_armed=1")
        idx_mv = put_code.find('mv -f "$tmp" "$data"')
        idx_gate3 = put_code.find('validate_cmdb_workdir "$workdir" "$entry"', idx_mv)
        idx_cleanup = put_code.rfind("cleanup_put_data")
        self.assertLess(idx_gate1, idx_gate2)
        self.assertLess(idx_gate2, idx_bytes)
        self.assertLess(idx_bytes, idx_arm)
        self.assertLess(idx_arm, idx_mv)
        self.assertLess(idx_mv, idx_gate3)
        self.assertLess(idx_gate3, idx_cleanup)

        cleanup_fn = _extract_func(self.src, "cleanup_put_data")
        idx_rb = cleanup_fn.find('if [ "${put_data_rollback_armed:-0}" -eq 1 ]; then')
        idx_unlock = cleanup_fn.find("exec 9>&-")
        self.assertNotEqual(idx_rb, -1)
        self.assertNotEqual(idx_unlock, -1)
        self.assertNotIn("exec 9>&- 2>/dev/null", cleanup_fn)
        self.assertLess(idx_rb, idx_unlock, "cleanup_put_data must roll back BEFORE releasing FD 9")

        val_fn = _extract_func(self.src, "validate_cmdb_workdir")
        self.assertIn("--show-classes", val_fn)
        self.assertIn("9>&-", val_fn)
        self.assertIn("tendcf_cmdb_evaluated", val_fn)
        self.assertIn("source=promise", val_fn)
        self.assertIn("tendcf_cmdb_refused", val_fn)
        self.assertIn("tendcf_cmdb_problem_", val_fn)
        self.assertIn("awk_rc", val_fn)
        self.assertNotIn("| sort", val_fn)

    def _build_harness(
        self,
        root: Path,
        cf_promises_script: str,
        *,
        initial_data: bytes | None = None,
    ) -> dict[str, Path]:
        shim_dir = root / "shims"
        shim_dir.mkdir()
        _make_linux_shims(shim_dir)

        prefix = root / "opt" / "tendcf"
        workdir = prefix / "var" / "libntech"
        (prefix / "share" / "tendcf" / "bin").mkdir(parents=True)
        shutil.copy2(PROJECTOR, prefix / "share" / "tendcf" / "bin" / "projector.py")
        (prefix / "share" / "tendcf" / "bin" / "projector.py").chmod(0o644)

        (workdir / "inputs" / "tendcf").mkdir(parents=True)
        (workdir / "inputs" / "promises.cf").write_text("bundle agent main {}\n", encoding="utf-8")
        (workdir / "inputs" / "promises.cf").chmod(0o644)
        (workdir / "data").mkdir(parents=True, mode=0o700)
        (workdir / "ppkeys").mkdir(parents=True, mode=0o700)

        data_path = workdir / "data" / "host_specific.json"
        if initial_data is not None:
            data_path.write_bytes(initial_data)
            data_path.chmod(0o600)

        cf_promises = root / "fake-cf-promises"
        cf_promises.write_text(cf_promises_script, encoding="utf-8")
        cf_promises.chmod(0o755)

        return {
            "shim_dir": shim_dir,
            "prefix": prefix,
            "workdir": workdir,
            "entry": workdir / "inputs" / "promises.cf",
            "data": data_path,
            "cf_promises": cf_promises,
            "installed_projector": prefix / "share" / "tendcf" / "bin" / "projector.py",
        }

    def _put_data_script(
        self,
        env_paths: dict[str, Path],
        src_file: Path,
        *,
        extra_preamble: str = "",
    ) -> str:
        funcs = "\n".join(
            _extract_func(self.src, name)
            for name in (
                "cleanup_put_data",
                "check_dir_root_unwritable",
                "check_regular_file_root_unwritable",
                "check_dir_chain_strict_under_prefix",
                "verify_installed_projector",
                "validate_cmdb_workdir",
                "put_data",
            )
        )
        return (
            "set -euo pipefail\n"
            f'export PATH="{env_paths["shim_dir"]}:$PATH"\n'
            'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
            'say() { echo "tendcf-install: $*"; }\n'
            "check_ancestors_ok() { return 0; }\n"
            "check_policy_tree_root_unwritable() { return 0; }\n"
            f'prefix="{env_paths["prefix"]}"\n'
            f'cf_lib_path="{env_paths["prefix"]}/lib"\n'
            f'workdir="{env_paths["workdir"]}"\n'
            f'entry="{env_paths["entry"]}"\n'
            f'data="{env_paths["data"]}"\n'
            f'cf_promises="{env_paths["cf_promises"]}"\n'
            f'installed_projector="{env_paths["installed_projector"]}"\n'
            'put_data_stage_wd=""\n'
            'put_data_tmp=""\n'
            'put_data_backup=""\n'
            "put_data_rollback_armed=0\n"
            "put_data_had_prev=0\n"
            f'find_trusted_python() {{ echo "{sys.executable}"; }}\n'
            f"{extra_preamble}\n"
            f"{funcs}\n"
            "trap cleanup_put_data EXIT\n"
            "trap 'exit 130' INT\n"
            "trap 'exit 143' TERM\n"
            f'put_data "{src_file}"\n'
        )

    def _run_put_data(
        self,
        env_paths: dict[str, Path],
        src_file: Path,
        *,
        extra_env: dict[str, str] | None = None,
        extra_preamble: str = "",
    ) -> subprocess.CompletedProcess[str]:
        script = self._put_data_script(env_paths, src_file, extra_preamble=extra_preamble)
        env = dict(os.environ)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["/bin/bash", "-c", script],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_gate1_projector_refusal_leaves_live_data_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig_bytes = CANARY_PRESENT.read_bytes()
            paths = self._build_harness(root, OK_CF_SCRIPT, initial_data=orig_bytes)
            before_ino = paths["data"].stat().st_ino

            bad = root / "noncanonical.json"
            bad.write_bytes(orig_bytes + b"\n")
            r = self._run_put_data(paths, bad)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("projector rejected", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig_bytes)
            self.assertEqual(paths["data"].stat().st_ino, before_ino)
            leftovers = [p.name for p in (paths["workdir"] / "data").iterdir() if ".new." in p.name or ".prev." in p.name]
            self.assertEqual(leftovers, [])

    def test_gate2_prepublish_refusal_zero_live_exposure(self) -> None:
        """Issue #57: cf-promises exit 0 with tendcf_cmdb_refused refuses BEFORE touching live data."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig_bytes = CANARY_PRESENT.read_bytes()
            probe_log = root / "live-during-gate2.log"
            cf_script = (
                "#!/bin/sh\n"
                f'cat "{root / "opt/tendcf/var/libntech/data/host_specific.json"}" > "{probe_log}"\n'
                "echo 'any   hardclass'\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "echo 'tendcf_cmdb_problem_sections   source=policy'\n"
                "echo 'tendcf_cmdb_refused   source=policy'\n"
                "exit 0\n"
            )
            paths = self._build_harness(root, cf_script, initial_data=orig_bytes)
            before_ino = paths["data"].stat().st_ino

            r = self._run_put_data(paths, CANARY_ABSENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("tendcf_cmdb_refused", r.stderr)
            self.assertIn("tendcf_cmdb_problem_sections", r.stderr)
            self.assertIn("live", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig_bytes)
            self.assertEqual(paths["data"].stat().st_ino, before_ino)
            self.assertEqual(probe_log.read_bytes(), orig_bytes)

    def test_validate_cmdb_workdir_fail_closed_on_empty_unmarked_untagged_and_awk_error(self) -> None:
        """Codex #5: reject empty/diagnostic output, missing source=promise, and awk failure."""
        cases = (
            ("empty output", "#!/bin/sh\nexit 0\n", "missing positive tendcf_cmdb_evaluated"),
            (
                "diagnostic header only",
                "#!/bin/sh\necho 'Class name   Meta tags'\necho 'any   hardclass'\nexit 0\n",
                "missing positive tendcf_cmdb_evaluated",
            ),
            (
                "marker without source=promise",
                "#!/bin/sh\necho 'tendcf_cmdb_evaluated   source=cmdb'\nexit 0\n",
                "missing positive tendcf_cmdb_evaluated",
            ),
        )
        for name, cf_script, expect_msg in cases:
            with self.subTest(name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                orig_bytes = CANARY_PRESENT.read_bytes()
                paths = self._build_harness(root, cf_script, initial_data=orig_bytes)
                r = self._run_put_data(paths, CANARY_ABSENT)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(expect_msg, r.stderr)
                self.assertEqual(paths["data"].read_bytes(), orig_bytes)

        # awk exits non-zero with empty stdout -> fail closed
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig_bytes = CANARY_PRESENT.read_bytes()
            paths = self._build_harness(root, OK_CF_SCRIPT, initial_data=orig_bytes)
            awk_fail = paths["shim_dir"] / "awk"
            awk_fail.write_text("#!/bin/sh\nexit 17\n", encoding="utf-8")
            awk_fail.chmod(0o755)
            r = self._run_put_data(paths, CANARY_ABSENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("awk exit 17", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig_bytes)

    def test_gate3_postpublish_failure_rolls_back_and_preserves_backup_on_mv_error(self) -> None:
        # Case A: had previous data -> restored atomically
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig_bytes = CANARY_PRESENT.read_bytes()
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" = "{live_wd}" ]; then\n'
                "  echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "  echo 'tendcf_cmdb_problem_foreign_class   source=policy'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_harness(root, cf_script, initial_data=orig_bytes)
            r = self._run_put_data(paths, CANARY_ABSENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("previous data restored", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig_bytes)
            leftovers = [p.name for p in (paths["workdir"] / "data").iterdir() if ".new." in p.name or ".prev." in p.name]
            self.assertEqual(leftovers, [])

        # Case B: no previous data -> newly published file removed
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" = "{live_wd}" ]; then\n'
                "  echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_harness(root, cf_script, initial_data=None)
            r = self._run_put_data(paths, CANARY_PRESENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("new data removed", r.stderr)
            self.assertFalse(paths["data"].exists())

        # Case C: rollback mv fails -> backup file is preserved (not deleted by EXIT trap)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig_bytes = CANARY_PRESENT.read_bytes()
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" = "{live_wd}" ]; then\n'
                "  echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_harness(root, cf_script, initial_data=orig_bytes)
            real_mv = shutil.which("mv") or "/bin/mv"
            mv_shim = paths["shim_dir"] / "mv"
            mv_shim.write_text(
                f"#!/bin/sh\ncase \"$2\" in *.prev.*) exit 1 ;; esac\nexec {real_mv} \"$@\"\n",
                encoding="utf-8",
            )
            mv_shim.chmod(0o755)
            r = self._run_put_data(paths, CANARY_ABSENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("rollback failed; backup preserved at", r.stderr)
            backups = [p for p in (paths["workdir"] / "data").iterdir() if ".host_specific.prev." in p.name]
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), orig_bytes)

    def test_sigterm_during_gate3_rolls_back_previous_or_removes_first_time(self) -> None:
        """Codex #4: catchable SIGTERM during Gate 3 rolls back instead of deleting backup."""
        for label, init_bytes in (("with_prev", CANARY_PRESENT.read_bytes()), ("first_time", None)):
            with self.subTest(label), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                live_wd = root / "opt" / "tendcf" / "var" / "libntech"
                gate3_ready = root / "gate3.ready"
                cf_script = (
                    "#!/bin/sh\n"
                    'wd=""\n'
                    'while [ $# -gt 0 ]; do\n'
                    '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                    'done\n'
                    f'if [ "$wd" = "{live_wd}" ]; then\n'
                    f'  echo ready > "{gate3_ready}"\n'
                    "  sleep 10\n"
                    "fi\n"
                    "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                    "exit 0\n"
                )
                paths = self._build_harness(root, cf_script, initial_data=init_bytes)
                script = self._put_data_script(paths, CANARY_ABSENT)
                proc = subprocess.Popen(
                    ["/bin/bash", "-c", script],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                deadline = time.monotonic() + 10.0
                while not gate3_ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(gate3_ready.exists(), "Gate 3 cf-promises never started")
                os.killpg(proc.pid, signal.SIGTERM)
                _out, err = proc.communicate(timeout=10)
                self.assertNotEqual(proc.returncode, 0)
                if init_bytes is not None:
                    self.assertEqual(paths["data"].read_bytes(), init_bytes)
                    self.assertIn("previous data restored", err)
                else:
                    self.assertFalse(paths["data"].exists())
                    self.assertIn("removed unverified first-time data", err)
                leftovers = [
                    p.name
                    for p in (paths["workdir"] / "data").iterdir()
                    if ".new." in p.name or ".prev." in p.name
                ]
                self.assertEqual(leftovers, [])

    def test_fifo_lockfile_refused_before_opening_fd9(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            paths = self._build_harness(root, OK_CF_SCRIPT, initial_data=CANARY_PRESENT.read_bytes())
            os.mkfifo(paths["workdir"] / "data" / ".publish.lock")
            r = self._run_put_data(paths, CANARY_ABSENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("not a regular file", r.stderr)

    def test_concurrent_publishers_serialize_with_flock_and_leave_no_temp_files(self) -> None:
        """Issue #58: 6 parallel publishers serialize cleanly with zero overlap and zero leftovers."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            trace = root / "cs.log"
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" != "{live_wd}" ]; then\n'
                f'  echo "ENTER $WORKER_ID" >> "{trace}"\n'
                "  sleep 0.08\n"
                f'  echo "LEAVE $WORKER_ID" >> "{trace}"\n'
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_harness(root, cf_script, initial_data=CANARY_PRESENT.read_bytes())
            procs: list[subprocess.Popen[str]] = []
            for i in range(6):
                src = CANARY_ABSENT if i % 2 == 0 else CANARY_PRESENT
                script = self._put_data_script(paths, src, extra_preamble=f'export WORKER_ID="{i}"')
                procs.append(
                    subprocess.Popen(
                        ["/bin/bash", "-c", script],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                )

            for i, p in enumerate(procs):
                out, err = p.communicate(timeout=30)
                self.assertEqual(p.returncode, 0, f"worker {i} failed: {out}\n{err}")

            final = paths["data"].read_bytes()
            self.assertIn(final, (CANARY_PRESENT.read_bytes(), CANARY_ABSENT.read_bytes()))
            lines = trace.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 12)
            for idx in range(0, len(lines), 2):
                enter_tok = lines[idx].split()
                leave_tok = lines[idx + 1].split()
                self.assertEqual(enter_tok[0], "ENTER")
                self.assertEqual(leave_tok[0], "LEAVE")
                self.assertEqual(enter_tok[1], leave_tok[1], f"interleaved lock trace: {lines}")

            leftovers = [
                p.name
                for p in (paths["workdir"] / "data").iterdir()
                if p.name not in ("host_specific.json", ".publish.lock")
            ]
            self.assertEqual(leftovers, [])
            wd_leftovers = [p.name for p in paths["workdir"].iterdir() if p.name.startswith(".putdata.")]
            self.assertEqual(wd_leftovers, [])

    def test_place_projector_integrity_gate_same_realpath_and_symlink_refusal(self) -> None:
        """Codex #3: require root-owned non-writable source OR matching --projector-sha256."""
        funcs = "\n".join(
            _extract_func(self.src, name)
            for name in (
                "cleanup_put_data",
                "cleanup_temp",
                "check_dir_root_unwritable",
                "check_regular_file_root_unwritable",
                "source_file_root_trusted_ok",
                "check_source_file_root_trusted",
                "check_dir_chain_strict_under_prefix",
                "resolve_projector_src",
                "verify_installed_projector",
                "installed_projector_clean_ok",
                "prepare_projector_source",
                "detach_unsafe_installed_projector",
                "place_projector",
            )
        )
        proj_sha = hashlib.sha256(PROJECTOR.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            shim_dir = root / "shims"
            shim_dir.mkdir()
            _make_linux_shims(shim_dir)
            prefix = root / "opt" / "tendcf"
            prefix.mkdir(parents=True)
            dst = prefix / "share" / "tendcf" / "bin" / "projector.py"

            def run_place(
                proj_src: Path,
                *,
                sha: str = "",
                src_trusted: bool = True,
            ) -> subprocess.CompletedProcess[str]:
                anc_fn = "check_ancestors_ok() { return 0; }" if src_trusted else 'check_ancestors_ok() { [ "$1" = "'"$prefix"'" ] && return 0; return 1; }'
                script = (
                    "set -euo pipefail\n"
                    f'export PATH="{shim_dir}:$PATH"\n'
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    f'prefix="{prefix}"\n'
                    f"{anc_fn}\n"
                    f'here="{root}"\n'
                    f'projector_src="{proj_src}"\n'
                    f'projector_sha256="{sha}"\n'
                    f'installed_projector="{dst}"\n'
                    'probe_tmp=""\n'
                    'place_projector_stage=""\n'
                    'place_projector_tmp=""\n'
                    'prepared_projector_stage=""\n'
                    'prepared_projector_file=""\n'
                    "projector_prepared=0\n"
                    "installed_projector_originally_clean=0\n"
                    'put_data_stage_wd=""\n'
                    'put_data_tmp=""\n'
                    'put_data_backup=""\n'
                    "put_data_rollback_armed=0\n"
                    "put_data_had_prev=0\n"
                    f"{funcs}\n"
                    "trap cleanup_temp EXIT\n"
                    "prepare_projector_source\n"
                    "detach_unsafe_installed_projector\n"
                    "place_projector\n"
                )
                return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)

            # 1. Mutable/non-root source WITHOUT --projector-sha256 -> REFUSED
            r_unpinned = run_place(PROJECTOR, sha="", src_trusted=False)
            self.assertNotEqual(r_unpinned.returncode, 0)
            self.assertIn("--projector-sha256", r_unpinned.stderr)

            # 2. Wrong --projector-sha256 -> REFUSED
            r_bad_sha = run_place(PROJECTOR, sha="0" * 64, src_trusted=False)
            self.assertNotEqual(r_bad_sha.returncode, 0)
            self.assertIn("sha256 mismatch", r_bad_sha.stderr)

            # 3. Valid --projector-sha256 on non-root source -> ACCEPTED
            r_ok_sha = run_place(PROJECTOR, sha=proj_sha, src_trusted=False)
            self.assertEqual(r_ok_sha.returncode, 0, r_ok_sha.stderr)
            self.assertEqual(dst.read_bytes(), PROJECTOR.read_bytes())
            self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o644)

            # 4. Same-realpath invocation preserves bytes without self-truncation
            r_same = run_place(dst, sha="", src_trusted=True)
            self.assertEqual(r_same.returncode, 0, r_same.stderr)
            self.assertEqual(dst.read_bytes(), PROJECTOR.read_bytes())

            # 5. Symlink source is refused
            link_src = root / "proj-link.py"
            link_src.symlink_to(PROJECTOR)
            r_link = run_place(link_src, sha=proj_sha, src_trusted=True)
            self.assertNotEqual(r_link.returncode, 0)
            self.assertIn("regular non-symlink", r_link.stderr)

            # 6. R5 Fix #2 (Codex R5 #2): place_projector fails closed if $prepared_projector_file is missing (never reopens $projector_src)
            dst.unlink()
            missing_stage_script = (
                "set -euo pipefail\n"
                f'export PATH="{shim_dir}:$PATH"\n'
                'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                f'prefix="{prefix}"\n'
                "check_ancestors_ok() { return 0; }\n"
                f'here="{root}"\n'
                f'projector_src="{PROJECTOR}"\n'
                f'projector_sha256="{proj_sha}"\n'
                f'installed_projector="{dst}"\n'
                'probe_tmp=""\n'
                'place_projector_stage=""\n'
                'place_projector_tmp=""\n'
                'prepared_projector_stage=""\n'
                'prepared_projector_file=""\n'
                "projector_prepared=0\n"
                "installed_projector_originally_clean=0\n"
                'put_data_stage_wd=""\n'
                'put_data_tmp=""\n'
                'put_data_backup=""\n'
                "put_data_rollback_armed=0\n"
                "put_data_had_prev=0\n"
                f"{funcs}\n"
                "trap cleanup_temp EXIT\n"
                "prepare_projector_source\n"
                'rm -f "$prepared_projector_file"\n'
                "place_projector\n"
            )
            r_missing_stage = subprocess.run(
                ["/bin/bash", "-c", missing_stage_script], capture_output=True, text=True, check=False
            )
            self.assertNotEqual(r_missing_stage.returncode, 0)
            self.assertIn("staged copy is missing", r_missing_stage.stderr)
            self.assertFalse(dst.exists(), "place_projector must NOT reopen $projector_src when staged file disappeared")

    def test_trust_helpers_reject_nonroot_writable_symlink_hops_and_untrusted_python(self) -> None:
        funcs = "\n".join(
            _extract_func(self.src, name)
            for name in (
                "check_dir_chain_ok",
                "check_ancestor_dir_ok",
                "check_ancestors_ok",
                "resolve_safe_python_ok",
                "check_policy_tree_root_unwritable",
            )
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            shim_real = root / "shims-real"
            shim_real.mkdir()
            _make_linux_shims(shim_real, real_uid=True)

            wdir = root / "writable"
            wdir.mkdir(mode=0o777)
            os.chmod(wdir, 0o777)
            child = wdir / "sub"
            child.mkdir(mode=0o755)
            shim_root = root / "shims-root"
            shim_root.mkdir()
            _make_linux_shims(shim_root, real_uid=False)

            r_ww = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f'set -euo pipefail; export PATH="{shim_root}:$PATH"; {funcs}; check_dir_chain_ok "{child}"',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_ww.returncode, 0, "world-writable ancestor must fail check_dir_chain_ok")

            hop_dir = root / "safe_hop"
            hop_dir.mkdir(mode=0o755)
            sym = hop_dir / "link"
            sym.symlink_to(wdir)
            r_hop = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f'set -euo pipefail; export PATH="{shim_root}:$PATH"; {funcs}; check_dir_chain_ok "{sym}/sub"',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_hop.returncode, 0, "symlink hop through writable dir must fail")

            fake_py = root / "fake_python3"
            fake_py.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_py.chmod(0o755)
            if os.geteuid() != 0:
                r_nonroot = subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        f'set -euo pipefail; export PATH="{shim_real}:$PATH"; {funcs}; resolve_safe_python_ok "{fake_py}"',
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(r_nonroot.returncode, 0, "non-root python must be rejected")

            r_outside = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f'set -euo pipefail; export PATH="{shim_root}:$PATH"; check_ancestors_ok() {{ return 0; }}; {funcs}; resolve_safe_python_ok "{fake_py}"',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_outside.returncode, 0, "python outside trusted system dirs must be rejected")

            pol = root / "wd" / "inputs" / "tendcf"
            pol.mkdir(parents=True)
            (pol / "evil.cf").symlink_to("/etc/hosts")
            r_pol = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f'set -euo pipefail; die() {{ echo "$*" >&2; exit 1; }}; workdir="{root / "wd"}"; {funcs}; check_policy_tree_root_unwritable',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_pol.returncode, 0)
            self.assertIn("unsafe entry", r_pol.stderr)

    def test_cmd_install_checks_projector_trust_before_check_tree_and_replaces_inode(self) -> None:
        """R3 Fix #1 (Codex #3): check_tree must NOT launder a writable projector; pinned install replaces inode."""
        funcs = "\n".join(
            _extract_func(self.src, name)
            for name in (
                "cleanup_put_data",
                "cleanup_temp",
                "check_dir_root_unwritable",
                "check_regular_file_root_unwritable",
                "source_file_root_trusted_ok",
                "check_source_file_root_trusted",
                "check_dir_chain_strict_under_prefix",
                "resolve_projector_src",
                "verify_installed_projector",
                "installed_projector_clean_ok",
                "check_tree",
                "prepare_projector_source",
                "detach_unsafe_installed_projector",
                "place_projector",
                "prevalidate_install_inputs",
                "cmd_install",
            )
        )
        proj_sha = hashlib.sha256(PROJECTOR.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            shim_dir = root / "shims"
            shim_dir.mkdir()
            _make_linux_shims(shim_dir)

            prefix = root / "opt" / "tendcf"
            (prefix / "bin").mkdir(parents=True)
            for b in ("cf-agent", "cf-promises", "cf-key", "cf-execd"):
                bp = prefix / "bin" / b
                bp.write_text("#!/bin/sh\necho 'CFEngine Core 3.21.0'\n", encoding="utf-8")
                bp.chmod(0o755)
            (prefix / "share" / "tendcf" / "bin").mkdir(parents=True)
            dst = prefix / "share" / "tendcf" / "bin" / "projector.py"
            shutil.copy2(PROJECTOR, dst)
            os.chmod(dst, 0o666)  # group/world-writable BEFORE cmd_install!

            policy_dir = root / "policy"
            policy_dir.mkdir()
            (policy_dir / "tendcf_services.cf").write_text("# dummy\n", encoding="utf-8")

            def run_cmd_install(extra_args: str, *, fail_place_policy: bool = False) -> subprocess.CompletedProcess[str]:
                place_pol_body = 'die "injected place_policy failure"' if fail_place_policy else "return 0"
                script = (
                    "set -euo pipefail\n"
                    f'export PATH="{shim_dir}:$PATH"\n'
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    'say() { echo "tendcf-install: $*"; }\n'
                    "check_ancestors_ok() { return 0; }\n"
                    "verify_tree_binaries() { return 0; }\n"
                    "init_paths() { return 0; }\n"
                    "lay_out() { return 0; }\n"
                    f"place_policy() {{ {place_pol_body}; }}\n"
                    f'prefix="{prefix}"\n'
                    f'cf_lib_path="{prefix}/lib"\n'
                    f'cf_agent="{prefix}/bin/cf-agent"\n'
                    f'cf_promises="{prefix}/bin/cf-promises"\n'
                    f'cf_key="{prefix}/bin/cf-key"\n'
                    f'cf_execd="{prefix}/bin/cf-execd"\n'
                    f'here="{root}"\n'
                    f'policy_src="{policy_dir}"\n'
                    'projector_src=""\n'
                    'projector_sha256=""\n'
                    f'installed_projector="{dst}"\n'
                    'probe_tmp=""\n'
                    'place_projector_stage=""\n'
                    'place_projector_tmp=""\n'
                    'prepared_projector_stage=""\n'
                    'prepared_projector_file=""\n'
                    "projector_prepared=0\n"
                    "installed_projector_originally_clean=0\n"
                    'put_data_stage_wd=""\n'
                    'put_data_tmp=""\n'
                    'put_data_backup=""\n'
                    "put_data_rollback_armed=0\n"
                    "put_data_had_prev=0\n"
                    f"{funcs}\n"
                    "trap cleanup_temp EXIT\n"
                    f'cmd_install --policy-src "{policy_dir}" {extra_args}\n'
                )
                return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)

            # 1. Unpinned on writable packaged projector -> REFUSED BEFORE check_tree runs!
            r_unpinned = run_cmd_install(f'--projector-src "{dst}"')
            self.assertNotEqual(r_unpinned.returncode, 0)
            self.assertIn("--projector-sha256", r_unpinned.stderr)
            self.assertEqual(
                stat.S_IMODE(dst.stat().st_mode),
                0o666,
                "check_tree must NOT have run to launder writable projector before refusal",
            )

            # 2. R4 Fix #2 (Codex R4 #2): failure between check_tree and place_projector leaves unsafe dst DETACHED (absent)!
            ext_proj = root / "ext-projector.py"
            shutil.copy2(PROJECTOR, ext_proj)
            os.chmod(ext_proj, 0o644)
            for label, args in (
                ("external_src", f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}'),
                ("pinned_dst", f'--projector-src "{dst}" --projector-sha256 {proj_sha}'),
            ):
                with self.subTest(mid_fail=label):
                    shutil.copy2(PROJECTOR, dst)
                    os.chmod(dst, 0o666)
                    r_fail = run_cmd_install(args, fail_place_policy=True)
                    self.assertNotEqual(r_fail.returncode, 0)
                    self.assertIn("injected place_policy failure", r_fail.stderr)
                    self.assertFalse(
                        dst.exists() or dst.is_symlink(),
                        "unsafe installed_projector must be detached before check_tree, never laundered",
                    )
                    # Subsequent verify_installed_projector fails closed
                    r_ver = subprocess.run(
                        [
                            "/bin/bash",
                            "-c",
                            "set -euo pipefail\n"
                            f'export PATH="{shim_dir}:$PATH"\n'
                            'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                            "check_ancestors_ok() { return 0; }\n"
                            f'prefix="{prefix}"\n'
                            f'installed_projector="{dst}"\n'
                            f"{funcs}\n"
                            "verify_installed_projector\n",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(r_ver.returncode, 0)
                    # Subsequent unpinned cmd_install pointing at missing $dst fails closed
                    r_retry = run_cmd_install(f'--projector-src "{dst}"')
                    self.assertNotEqual(r_retry.returncode, 0)

            # 3. R6 Fix #1 (Codex R6 #1): unsafe writable parent ($prefix/share/tendcf/bin mode 0777) MUST fail closed
            #    BEFORE mutating any directory mode/owner/ACL, for BOTH existing 0644 leaf and absent leaf!
            proj_bin_dir = prefix / "share" / "tendcf" / "bin"
            # (a) Writable parent + existing 0644 leaf -> fails closed, parent stays 0777, verify_installed_projector still refuses!
            shutil.copy2(PROJECTOR, dst)
            os.chmod(dst, 0o644)
            os.chmod(proj_bin_dir, 0o777)
            r_wparent_leaf = run_cmd_install(
                f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}',
            )
            self.assertNotEqual(r_wparent_leaf.returncode, 0)
            self.assertEqual(
                stat.S_IMODE(proj_bin_dir.stat().st_mode),
                0o777,
                "unsafe existing projector parent chain must NOT be mutated before refusing",
            )
            r_ver_wp = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -euo pipefail\n"
                    f'export PATH="{shim_dir}:$PATH"\n'
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    "check_ancestors_ok() { return 0; }\n"
                    f'prefix="{prefix}"\n'
                    f'installed_projector="{dst}"\n'
                    f"{funcs}\n"
                    "verify_installed_projector\n",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_ver_wp.returncode, 0, "verify_installed_projector must still refuse exposed leaf")

            # (b) Writable parent + absent leaf -> fails closed, parent stays 0777
            dst.unlink()
            os.chmod(proj_bin_dir, 0o777)
            r_wparent_absent = run_cmd_install(
                f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}',
            )
            self.assertNotEqual(r_wparent_absent.returncode, 0)
            self.assertEqual(
                stat.S_IMODE(proj_bin_dir.stat().st_mode),
                0o777,
                "unsafe existing projector parent chain with absent leaf must NOT be mutated",
            )
            os.chmod(proj_bin_dir, 0o755)

            # (c) Codex R7 #1: writable $prefix/share (0777) MUST fail closed with ZERO mutations whether
            #     $prefix/share/tendcf is absent OR contains a 0644 projector subtree!
            shutil.rmtree(prefix / "share" / "tendcf")
            os.chmod(prefix / "share", 0o777)
            r_wshare_absent = run_cmd_install(f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}')
            self.assertNotEqual(r_wshare_absent.returncode, 0)
            self.assertEqual(
                stat.S_IMODE((prefix / "share").stat().st_mode),
                0o777,
                "writable $prefix/share must NOT be mutated before failing closed",
            )
            # With a 0644 projector subtree placed under writable $prefix/share, cmd_install still refuses
            # without hardening $prefix/share, and verify_installed_projector still refuses the projector!
            (prefix / "share" / "tendcf" / "bin").mkdir(parents=True)
            shutil.copy2(PROJECTOR, dst)
            os.chmod(dst, 0o644)
            r_wshare_leaf = run_cmd_install(f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}')
            self.assertNotEqual(r_wshare_leaf.returncode, 0)
            self.assertEqual(stat.S_IMODE((prefix / "share").stat().st_mode), 0o777)
            r_ver_ws = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -euo pipefail\n"
                    f'export PATH="{shim_dir}:$PATH"\n'
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    "check_ancestors_ok() { return 0; }\n"
                    f'prefix="{prefix}"\n'
                    f'installed_projector="{dst}"\n'
                    f"{funcs}\n"
                    "verify_installed_projector\n",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_ver_ws.returncode, 0)

            # (d) Fresh build with ALREADY-trusted $prefix/$prefix/share (0755) and absent $prefix/share/tendcf -> succeeds!
            shutil.rmtree(prefix / "share" / "tendcf")
            os.chmod(prefix / "share", 0o755)
            r_fresh = run_cmd_install(f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}')
            self.assertEqual(r_fresh.returncode, 0, r_fresh.stderr)
            self.assertEqual(dst.read_bytes(), PROJECTOR.read_bytes())
            self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o644)

            # 4. R5 Fix #3 (Codex R5 #3): hold open writable FD on dst across cmd_install (prevents ext4 inode reuse
            #    and proves the old writable descriptor cannot tamper with the newly installed projector)
            shutil.copy2(PROJECTOR, dst)
            os.chmod(dst, 0o666)
            with dst.open("r+b") as held_fd:
                old_ino = os.fstat(held_fd.fileno()).st_ino
                r_pinned = run_cmd_install(f'--projector-src "{dst}" --projector-sha256 {proj_sha}')
                self.assertEqual(r_pinned.returncode, 0, r_pinned.stderr)
                self.assertEqual(dst.read_bytes(), PROJECTOR.read_bytes())
                self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o644)
                self.assertNotEqual(
                    dst.stat().st_ino,
                    old_ino,
                    "pinned install over formerly writable projector must replace inode",
                )
                held_fd.seek(0)
                held_fd.write(b"# tampered-old-fd\n")
                held_fd.flush()
                self.assertEqual(
                    dst.read_bytes(),
                    PROJECTOR.read_bytes(),
                    "writes through previously opened writable FD must NOT affect newly installed projector",
                )

    def test_relative_projector_src_normalized_and_checked_through_ancestors(self) -> None:
        """R3 Fix #1 (Macroscope #4701728688): relative --projector-src normalized via pwd -L and ancestor-checked."""
        funcs = "\n".join(
            _extract_func(self.src, name)
            for name in (
                "cleanup_put_data",
                "cleanup_temp",
                "check_dir_chain_ok",
                "check_ancestor_dir_ok",
                "check_ancestors_ok",
                "check_dir_root_unwritable",
                "check_regular_file_root_unwritable",
                "source_file_root_trusted_ok",
                "check_source_file_root_trusted",
                "check_dir_chain_strict_under_prefix",
                "resolve_projector_src",
                "verify_installed_projector",
                "installed_projector_clean_ok",
                "prepare_projector_source",
                "detach_unsafe_installed_projector",
                "place_projector",
            )
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            shim_dir = root / "shims"
            shim_dir.mkdir()
            _make_linux_shims(shim_dir)

            # Override stat shim so ancestors ABOVE root look like trusted 0:0 755
            # (portable across macOS /var/folders and Linux /tmp 1777), while root
            # and everything underneath report their real filesystem modes.
            (shim_dir / "stat").write_text(
                f"#!{sys.executable}\n"
                "import os, stat, sys\n"
                f"root_s = {str(root)!r}\n"
                "fmt = sys.argv[2]\n"
                "p = sys.argv[3]\n"
                "rp = os.path.realpath(p) if not os.path.islink(p) else p\n"
                "if rp != root_s and not rp.startswith(root_s + '/'):\n"
                "    mode = 0o755\n"
                "else:\n"
                "    mode = stat.S_IMODE(os.lstat(p).st_mode)\n"
                "if fmt == '%U:%G %a':\n"
                "    print(f'root:root {mode:o}')\n"
                "elif fmt == '%u %g %a':\n"
                "    print(f'0 0 {mode:o}')\n"
                "elif fmt == '%u %a':\n"
                "    print(f'0 {mode:o}')\n"
                "elif fmt == '%u':\n"
                "    print('0')\n",
                encoding="utf-8",
            )
            (shim_dir / "stat").chmod(0o755)

            prefix = root / "opt" / "tendcf"
            prefix.mkdir(parents=True)
            os.chmod(root, 0o755)
            os.chmod(root / "opt", 0o755)
            os.chmod(prefix, 0o755)
            dst = prefix / "share" / "tendcf" / "bin" / "projector.py"

            trusted_pkg = root / "trusted_pkg"
            (trusted_pkg / "bin").mkdir(parents=True)
            os.chmod(trusted_pkg, 0o755)
            os.chmod(trusted_pkg / "bin", 0o755)
            shutil.copy2(PROJECTOR, trusted_pkg / "bin" / "projector.py")
            os.chmod(trusted_pkg / "bin" / "projector.py", 0o644)

            writable_pkg = root / "writable_pkg"
            (writable_pkg / "bin").mkdir(parents=True)
            os.chmod(writable_pkg, 0o777)
            os.chmod(writable_pkg / "bin", 0o755)
            shutil.copy2(PROJECTOR, writable_pkg / "bin" / "projector.py")
            os.chmod(writable_pkg / "bin" / "projector.py", 0o644)

            sym_proj = trusted_pkg / "bin" / "link.py"
            sym_proj.symlink_to(trusted_pkg / "bin" / "projector.py")

            def run_rel(cwd: Path, rel_src: str) -> subprocess.CompletedProcess[str]:
                script = (
                    "set -euo pipefail\n"
                    f'export PATH="{shim_dir}:$PATH"\n'
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    f'prefix="{prefix}"\n'
                    f'here="{root}"\n'
                    f'projector_src="{rel_src}"\n'
                    'projector_sha256=""\n'
                    f'installed_projector="{dst}"\n'
                    'probe_tmp=""\n'
                    'place_projector_stage=""\n'
                    'place_projector_tmp=""\n'
                    'prepared_projector_stage=""\n'
                    'prepared_projector_file=""\n'
                    "projector_prepared=0\n"
                    "installed_projector_originally_clean=0\n"
                    'put_data_stage_wd=""\n'
                    'put_data_tmp=""\n'
                    'put_data_backup=""\n'
                    "put_data_rollback_armed=0\n"
                    "put_data_had_prev=0\n"
                    f"{funcs}\n"
                    "trap cleanup_temp EXIT\n"
                    f'cd "{cwd}"\n'
                    "prepare_projector_source\n"
                    "detach_unsafe_installed_projector\n"
                    "place_projector\n"
                )
                return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)

            # 1. Trusted relative path -> ACCEPTED
            r_ok = run_rel(trusted_pkg, "bin/projector.py")
            self.assertEqual(r_ok.returncode, 0, r_ok.stderr)
            self.assertEqual(dst.read_bytes(), PROJECTOR.read_bytes())

            # 2. Relative symlink -> REFUSED
            r_sym = run_rel(trusted_pkg, "bin/link.py")
            self.assertNotEqual(r_sym.returncode, 0)
            self.assertIn("regular non-symlink", r_sym.stderr)

            # 3. Relative path inside world-writable dir -> REFUSED
            r_ww = run_rel(writable_pkg, "bin/projector.py")
            self.assertNotEqual(r_ww.returncode, 0)
            self.assertIn("--projector-sha256", r_ww.stderr)

    def test_first_publication_rollback_rm_failure_reports_error_and_live_path(self) -> None:
        """R3 Fix #3 (Codex #4): failed first-pub rm must report error naming $data, never claim removal."""
        real_rm = shutil.which("rm") or "/bin/rm"

        # Case A: Synchronous Gate 3 refusal with failing rm on $data
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" = "{live_wd}" ]; then\n'
                "  echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_harness(root, cf_script, initial_data=None)
            rm_shim = paths["shim_dir"] / "rm"
            rm_shim.write_text(
                f"#!/bin/sh\n"
                'for a in "$@"; do case "$a" in */host_specific.json) exit 1 ;; esac; done\n'
                f'exec {real_rm} "$@"\n',
                encoding="utf-8",
            )
            rm_shim.chmod(0o755)
            r = self._run_put_data(paths, CANARY_PRESENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("rollback could not remove unverified data at", r.stderr)
            self.assertIn(str(paths["data"]), r.stderr)
            self.assertNotIn("new data removed", r.stderr)
            self.assertTrue(paths["data"].exists())

        # Case B: EXIT-trap SIGTERM during Gate 3 with failing rm on $data
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            gate3_ready = root / "gate3.ready"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" = "{live_wd}" ]; then\n'
                f'  echo ready > "{gate3_ready}"\n'
                "  sleep 10\n"
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_harness(root, cf_script, initial_data=None)
            rm_shim = paths["shim_dir"] / "rm"
            rm_shim.write_text(
                f"#!/bin/sh\n"
                'for a in "$@"; do case "$a" in */host_specific.json) exit 1 ;; esac; done\n'
                f'exec {real_rm} "$@"\n',
                encoding="utf-8",
            )
            rm_shim.chmod(0o755)
            script = self._put_data_script(paths, CANARY_PRESENT)
            proc = subprocess.Popen(
                ["/bin/bash", "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            deadline = time.monotonic() + 10.0
            while not gate3_ready.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(gate3_ready.exists(), "Gate 3 cf-promises never started")
            os.killpg(proc.pid, signal.SIGTERM)
            _out, err = proc.communicate(timeout=10)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("ERROR: rollback could not remove unverified data at", err)
            self.assertIn(str(paths["data"]), err)
            self.assertNotIn("removed unverified first-time data", err)
            self.assertTrue(paths["data"].exists())

    def test_no_augments_on_cf_agent_entrypoints_only(self) -> None:
        """Issue #59: cf-agent invocations pass --no-augments; cf-promises does not."""
        place_fn = _extract_func(self.src, "place_policy")
        self.assertIn(
            'exec_command => "$(sys.cf_agent) --no-augments -f $(sys.inputdir)/promises.cf";',
            place_fn,
        )
        run_once_fn = _extract_func(self.src, "cmd_run_once")
        self.assertIn('"$cf_agent" --no-augments -K -I -f "$entry"', run_once_fn)

        # cf-promises does not support --no-augments; confirm none of its calls pass it.
        validate_fn = _extract_func(self.src, "validate_cmdb_workdir")
        self.assertNotIn("--no-augments", validate_fn)
        init_fn = _extract_func(self.src, "init_paths")
        self.assertNotIn("--no-augments", init_fn)

        # Hermetic behavioral check: cmd_run_once passes --no-augments to $cf_agent.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            args_log = root / "cf-agent.args"
            fake_agent = root / "cf-agent"
            fake_agent.write_text(
                f"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{args_log}\"\nexit 0\n",
                encoding="utf-8",
            )
            fake_agent.chmod(0o755)
            entry = root / "promises.cf"
            entry.write_text("bundle agent main {}\n", encoding="utf-8")
            data = root / "host_specific.json"
            data.write_text('{"vars":{}}\n', encoding="utf-8")
            script = (
                "set -euo pipefail\n"
                'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                f'cf_lib_path="{root}"\n'
                f'cf_agent="{fake_agent}"\n'
                f'entry="{entry}"\n'
                f'data="{data}"\n'
                f"{run_once_fn}\n"
                "cmd_run_once\n"
            )
            r = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, r.stderr)
            argv = args_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(argv, ["--no-augments", "-K", "-I", "-f", str(entry)])


if __name__ == "__main__":
    unittest.main()

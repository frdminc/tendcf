"""Contract and hermetic behavioral tests for deploy/linux/tendcf-install.sh (#53, #57, #58)."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INSTALLER = REPO / "deploy" / "linux" / "tendcf-install.sh"
PROJECTOR = REPO / "bin" / "projector.py"
CANARY_PRESENT = REPO / "deploy" / "linux" / "canary" / "host_specific.json"
CANARY_ABSENT = REPO / "deploy" / "linux" / "canary" / "host_specific-absent.json"


def _extract_func(src: str, name: str) -> str:
    m = re.search(rf"^{re.escape(name)}\(\) \{{[^\n]*\n(.*?)^\}}", src, re.MULTILINE | re.DOTALL)
    if m is None:
        raise AssertionError(f"function {name}() not found in {INSTALLER}")
    return m.group(0)


def _make_linux_shims(shim_dir: Path, *, real_uid: bool = False) -> None:
    """Provide non-root/macOS shims for Linux-only commands (chown, GNU stat, flock) when needed."""
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

    def test_env_sanitization_scoped_ld_library_path_and_no_tmpdir(self) -> None:
        non_comment = "\n".join(
            line for line in self.src.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIn("compgen -e", non_comment)
        self.assertIn("/usr/bin/env -i TENDCF_CLEAN_ENV=1 PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /bin/bash", non_comment)
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

    def test_contract_gates_locking_fd9_and_unique_paths(self) -> None:
        cmd_fn = _extract_func(self.src, "cmd_install")
        self.assertIn("--projector-src)", cmd_fn)
        self.assertIn('[ -n "$2" ]', cmd_fn)
        idx_preval = cmd_fn.find('prevalidate_install_inputs "$datafile"')
        idx_tree = cmd_fn.find("check_tree")
        idx_policy = cmd_fn.find("place_policy")
        idx_proj = cmd_fn.find("place_projector")
        idx_data = cmd_fn.find('put_data "$datafile"')
        for lbl, idx in (
            ("prevalidate", idx_preval),
            ("check_tree", idx_tree),
            ("place_policy", idx_policy),
            ("place_projector", idx_proj),
            ("put_data", idx_data),
        ):
            self.assertNotEqual(idx, -1, f"missing {lbl} in cmd_install")
        self.assertLess(idx_preval, idx_tree)
        self.assertLess(idx_policy, idx_proj)
        self.assertLess(idx_proj, idx_data)

        put_fn = _extract_func(self.src, "put_data")
        put_code = "\n".join(line for line in put_fn.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("$data.new", put_code)
        self.assertNotIn("$data.previous", put_code)
        self.assertIn('mktemp -d "$workdir/.putdata.XXXXXX"', put_code)
        self.assertIn('[ -f "$lockfile" ] && [ ! -L "$lockfile" ]', put_code)
        self.assertIn("flock -x 9", put_code)
        self.assertIn(".host_specific.new.XXXXXX", put_code)
        self.assertIn(".host_specific.prev.XXXXXX", put_code)
        self.assertIn('"$py" -I "$installed_projector" --check "$staged_data" 9>&-', put_code)

        idx_gate1 = put_code.find('"$installed_projector" --check "$staged_data" 9>&-')
        idx_gate2 = put_code.find('validate_cmdb_workdir "$stage_wd"')
        idx_bytes = put_code.find('data_bytes="$(wc -c < "$staged_data"')
        idx_mv = put_code.find('mv -f "$tmp" "$data"')
        idx_gate3 = put_code.find('validate_cmdb_workdir "$workdir" "$entry"', idx_mv)
        idx_cleanup = put_code.rfind("cleanup_put_data")
        self.assertLess(idx_gate1, idx_gate2)
        self.assertLess(idx_gate2, idx_bytes)
        self.assertLess(idx_bytes, idx_mv)
        self.assertLess(idx_mv, idx_gate3)
        self.assertLess(idx_gate3, idx_cleanup)

        cleanup_fn = _extract_func(self.src, "cleanup_put_data")
        self.assertIn("exec 9>&-", cleanup_fn)
        self.assertNotIn("exec 9>&- 2>/dev/null", cleanup_fn)

        val_fn = _extract_func(self.src, "validate_cmdb_workdir")
        self.assertIn("--show-classes", val_fn)
        self.assertIn("9>&-", val_fn)
        self.assertIn("tendcf_cmdb_refused", val_fn)
        self.assertIn("tendcf_cmdb_problem_", val_fn)
        self.assertNotIn("| awk", val_fn.split("--show-classes")[1].splitlines()[0])

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

    def _run_put_data(
        self,
        env_paths: dict[str, Path],
        src_file: Path,
        *,
        extra_env: dict[str, str] | None = None,
        extra_preamble: str = "",
    ) -> subprocess.CompletedProcess[str]:
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
        script = (
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
            f'find_trusted_python() {{ echo "{sys.executable}"; }}\n'
            f"{extra_preamble}\n"
            f"{funcs}\n"
            "trap cleanup_put_data EXIT\n"
            f'put_data "{src_file}"\n'
        )
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
            paths = self._build_harness(
                root,
                "#!/bin/sh\necho 'any   hardclass'\n",
                initial_data=orig_bytes,
            )
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

    def test_empty_show_classes_output_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig_bytes = CANARY_PRESENT.read_bytes()
            paths = self._build_harness(root, "#!/bin/sh\nexit 0\n", initial_data=orig_bytes)
            r = self._run_put_data(paths, CANARY_ABSENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("empty output", r.stderr)
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
                "  echo 'any   hardclass'\n"
                "  echo 'tendcf_cmdb_problem_foreign_class   source=policy'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'any   hardclass'\n"
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
                "  echo 'any   hardclass'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'any   hardclass'\n"
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
                "  echo 'any   hardclass'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'any   hardclass'\n"
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

    def test_fifo_lockfile_refused_before_opening_fd9(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            paths = self._build_harness(
                root,
                "#!/bin/sh\necho 'any   hardclass'\n",
                initial_data=CANARY_PRESENT.read_bytes(),
            )
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
                "echo 'any   hardclass'\n"
                "exit 0\n"
            )
            paths = self._build_harness(root, cf_script, initial_data=CANARY_PRESENT.read_bytes())

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
            procs: list[subprocess.Popen[str]] = []
            for i in range(6):
                src = CANARY_ABSENT if i % 2 == 0 else CANARY_PRESENT
                script = (
                    "set -euo pipefail\n"
                    f'export PATH="{paths["shim_dir"]}:$PATH"\n'
                    f'export WORKER_ID="{i}"\n'
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    'say() { echo "tendcf-install: $*"; }\n'
                    "check_ancestors_ok() { return 0; }\n"
                    "check_policy_tree_root_unwritable() { return 0; }\n"
                    f'prefix="{paths["prefix"]}"\n'
                    f'cf_lib_path="{paths["prefix"]}/lib"\n'
                    f'workdir="{paths["workdir"]}"\n'
                    f'entry="{paths["entry"]}"\n'
                    f'data="{paths["data"]}"\n'
                    f'cf_promises="{paths["cf_promises"]}"\n'
                    f'installed_projector="{paths["installed_projector"]}"\n'
                    'put_data_stage_wd=""\n'
                    'put_data_tmp=""\n'
                    'put_data_backup=""\n'
                    f'find_trusted_python() {{ echo "{sys.executable}"; }}\n'
                    f"{funcs}\n"
                    "trap cleanup_put_data EXIT\n"
                    f'put_data "{src}"\n'
                )
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

    def test_place_projector_installs_handles_same_realpath_and_refuses_symlink(self) -> None:
        funcs = "\n".join(
            _extract_func(self.src, name)
            for name in (
                "check_dir_root_unwritable",
                "check_regular_file_root_unwritable",
                "check_dir_chain_strict_under_prefix",
                "resolve_projector_src",
                "verify_installed_projector",
                "place_projector",
            )
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            shim_dir = root / "shims"
            shim_dir.mkdir()
            _make_linux_shims(shim_dir)
            prefix = root / "opt" / "tendcf"
            prefix.mkdir(parents=True)
            dst = prefix / "share" / "tendcf" / "bin" / "projector.py"

            def run_place(proj_src: Path) -> subprocess.CompletedProcess[str]:
                script = (
                    "set -euo pipefail\n"
                    f'export PATH="{shim_dir}:$PATH"\n'
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    "check_ancestors_ok() { return 0; }\n"
                    f'prefix="{prefix}"\n'
                    f'here="{root}"\n'
                    f'projector_src="{proj_src}"\n'
                    f'installed_projector="{dst}"\n'
                    'place_projector_tmp=""\n'
                    f"{funcs}\n"
                    "place_projector\n"
                )
                return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)

            r1 = run_place(PROJECTOR)
            self.assertEqual(r1.returncode, 0, r1.stderr)
            self.assertEqual(dst.read_bytes(), PROJECTOR.read_bytes())
            self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o644)

            r2 = run_place(dst)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertEqual(dst.read_bytes(), PROJECTOR.read_bytes())

            link_src = root / "proj-link.py"
            link_src.symlink_to(PROJECTOR)
            r3 = run_place(link_src)
            self.assertNotEqual(r3.returncode, 0)
            self.assertIn("regular non-symlink", r3.stderr)

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

            # 1. check_ancestors_ok rejects a world-writable ancestor (e.g., 0777 dir)
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

            # 2. Symlink hop leading into a writable dir must fail check_dir_chain_ok
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

            # 3. Non-root file rejected by resolve_safe_python_ok (when running as non-root)
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

            # 4. Even if root-owned, a python resolving outside /usr/bin|/bin|/usr/lib|/usr/lib64 is rejected
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

            # 5. Symlink inside $workdir/inputs/tendcf rejected by check_policy_tree_root_unwritable
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


if __name__ == "__main__":
    unittest.main()

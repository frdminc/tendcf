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


def _make_linux_shims(shim_dir: Path) -> None:
    """Provide non-root/macOS shims for Linux-only commands (chown, GNU stat, flock) when needed."""
    # Non-root tests cannot chown to root:root, so shim chown as no-op and
    # wrap stat -c '%U:%G %a' to report root:root when running as non-root.
    chown_shim = shim_dir / "chown"
    chown_shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    chown_shim.chmod(0o755)

    stat_shim = shim_dir / "stat"
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

    # Install -o root -g root fails for non-root; strip -o/-g args and call real install.
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

    # Use real flock on Linux; on macOS (where util-linux flock isn't shipped),
    # provide a real fcntl.flock(fd, LOCK_EX) shim operating on the inherited FD.
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

    def test_contract_gates_locking_and_unique_paths(self) -> None:
        cmd_fn = _extract_func(self.src, "cmd_install")
        self.assertIn("--projector-src)", cmd_fn)
        idx_policy = cmd_fn.find("place_policy")
        idx_proj = cmd_fn.find("place_projector")
        idx_data = cmd_fn.find('put_data "$datafile"')
        self.assertNotEqual(idx_policy, -1)
        self.assertNotEqual(idx_proj, -1)
        self.assertNotEqual(idx_data, -1)
        self.assertLess(idx_policy, idx_proj)
        self.assertLess(idx_proj, idx_data)

        put_fn = _extract_func(self.src, "put_data")
        self.assertNotIn("$data.new", put_fn)
        self.assertNotIn("$data.previous", put_fn)
        self.assertIn("flock -x 9", put_fn)
        self.assertIn('.host_specific.new.XXXXXX', put_fn)
        self.assertIn('.host_specific.prev.XXXXXX', put_fn)
        self.assertIn('"$py" -I "$installed_projector" --check "$staged_data"', put_fn)

        idx_gate1 = put_fn.find('"$installed_projector" --check "$staged_data"')
        idx_gate2 = put_fn.find('validate_cmdb_workdir "$stage_wd"')
        idx_mv = put_fn.find('mv -f "$tmp" "$data"')
        idx_gate3 = put_fn.find('validate_cmdb_workdir "$workdir" "$entry"', idx_mv)
        self.assertLess(idx_gate1, idx_gate2)
        self.assertLess(idx_gate2, idx_mv)
        self.assertLess(idx_mv, idx_gate3)

        val_fn = _extract_func(self.src, "validate_cmdb_workdir")
        self.assertIn("--show-classes", val_fn)
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
    ) -> subprocess.CompletedProcess[str]:
        funcs = "\n".join(
            _extract_func(self.src, name)
            for name in (
                "cleanup_put_data",
                "check_dir_root_unwritable",
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
            f'prefix="{env_paths["prefix"]}"\n'
            f'workdir="{env_paths["workdir"]}"\n'
            f'entry="{env_paths["entry"]}"\n'
            f'data="{env_paths["data"]}"\n'
            f'cf_promises="{env_paths["cf_promises"]}"\n'
            f'installed_projector="{env_paths["installed_projector"]}"\n'
            'put_data_stage_wd=""\n'
            'put_data_tmp=""\n'
            'put_data_backup=""\n'
            f'find_trusted_python() {{ echo "{sys.executable}"; }}\n'
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

    def test_gate3_postpublish_failure_rolls_back_previous_or_removes_new(self) -> None:
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
                    f'prefix="{paths["prefix"]}"\n'
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
            # Verify strict serialization: every ENTER is immediately followed by matching LEAVE.
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

    def test_place_projector_installs_handles_same_realpath_and_refuses_symlink(self) -> None:
        funcs = "\n".join(
            _extract_func(self.src, name)
            for name in (
                "check_dir_root_unwritable",
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

            # Same-realpath invocation preserves bytes without self-truncation
            r2 = run_place(dst)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertEqual(dst.read_bytes(), PROJECTOR.read_bytes())

            # Symlink source is refused
            link_src = root / "proj-link.py"
            link_src.symlink_to(PROJECTOR)
            r3 = run_place(link_src)
            self.assertNotEqual(r3.returncode, 0)
            self.assertIn("regular non-symlink", r3.stderr)


if __name__ == "__main__":
    unittest.main()

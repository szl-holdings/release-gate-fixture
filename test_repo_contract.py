"""Repository contract checks: packaging, the README example and test wiring.

Each test checks a claim that pyproject.toml, README.md or the CI workflow
makes about this checkout. Standard library only; child processes run with
-B so no bytecode is written into the checkout.
"""
import fnmatch
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

import release_gate as gate

ROOT = Path(__file__).resolve().parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
WORKFLOW = ROOT / ".github" / "workflows" / "offline-fixture.yml"
IMPORT_FROM = ("import importlib, sys; sys.path.insert(0, sys.argv[1]); "
               "importlib.import_module(sys.argv[2])")


def find_test_modules():
    """Dotted names of every test module in the checkout."""
    paths = {*ROOT.glob("test_*.py"), *ROOT.glob("*_tests.py"),
             *ROOT.glob("tests/**/test_*.py")}
    return sorted(".".join(path.relative_to(ROOT).with_suffix("").parts) for path in paths)


def run_python(*args):
    return subprocess.run([sys.executable, "-B", *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=60)


class PackagingTests(unittest.TestCase):
    shipped = PYPROJECT["tool"]["setuptools"]["py-modules"]

    def test_shipped_modules_import_without_the_checkout(self):
        # A wheel holds exactly these modules, so each must import from a copy
        # that holds nothing else (-I: no checkout on sys.path, -S: no site).
        self.assertTrue(self.shipped)
        with tempfile.TemporaryDirectory() as directory:
            for name in self.shipped:
                shutil.copy2(ROOT / f"{name}.py", directory)
            for name in self.shipped:
                with self.subTest(module=name):
                    proc = subprocess.run(
                        [sys.executable, "-I", "-S", "-B", "-c", IMPORT_FROM, directory, name],
                        capture_output=True, text=True, timeout=60)
                    self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_test_modules_are_not_shipped(self):
        self.assertEqual(sorted(set(self.shipped) & set(find_test_modules())), [])


class ReadmeTests(unittest.TestCase):
    def example(self):
        """The README's release_gate.py command and its quoted expected output."""
        commands = [block for block in re.findall(r"```bash\n(.*?)```", README, re.S)
                    if "release_gate.py" in block]
        self.assertEqual(len(commands), 1, commands)
        argv = shlex.split(commands[0].replace("\\\n", " "))
        self.assertEqual(argv[:2], ["python", "release_gate.py"])
        expected = re.search(r"Expected output:\s*```json\n(.*?)```", README, re.S)
        self.assertIsNotNone(expected, "README no longer quotes the expected output")
        return argv[1:], expected.group(1).strip()

    def test_example_prints_the_documented_output(self):
        argv, expected = self.example()
        proc = run_python(*argv)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), expected)

    def test_example_without_the_clock_override_is_stale(self):
        argv, _ = self.example()
        index = argv.index("--now")
        del argv[index:index + 2]
        proc = run_python(*argv)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["metadata_gate"], "blocked")
        self.assertIs(report["release_authorized"], False)
        records = ["checks.build", "checks.tests", "review", "rights", "rollback"]
        self.assertEqual(report["diagnostics"], [f"{name}.observed_at: stale" for name in records])

    def test_usage_errors_exit_two(self):
        proc = run_python("release_gate.py", "--manifest", "example-manifest.json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("the following arguments are required", proc.stderr)

    def test_documented_size_limit_matches_the_code(self):
        self.assertIn(f"files over {gate.MAX_INPUT_BYTES:,} bytes are rejected", README)

    def test_source_table_lists_every_root_module_and_example(self):
        names = sorted(path.name for path in ROOT.iterdir() if path.suffix in (".py", ".json"))
        self.assertEqual([name for name in names if f"[{name}](./{name})" not in README], [])


class WiringTests(unittest.TestCase):
    modules = find_test_modules()

    def test_ci_runs_every_test_module(self):
        self.assertIn("test_release_gate", self.modules)
        loop = re.search(r"for module in \(([^)]*)\)", WORKFLOW.read_text(encoding="utf-8"))
        self.assertIsNotNone(loop, "offline-fixture.yml no longer names its test modules")
        self.assertEqual(sorted(re.findall(r'"([^"]+)"', loop.group(1))), self.modules)

    def test_readme_command_runs_every_test_module(self):
        command = re.search(r"python -m unittest -v ([^\n`]+)", README)
        self.assertIsNotNone(command, "README no longer shows the unittest command")
        self.assertEqual(sorted(command.group(1).split()), self.modules)

    def test_pytest_collects_every_test_module(self):
        options = PYPROJECT.get("tool", {}).get("pytest", {}).get("ini_options", {})
        patterns = options.get("python_files", ["test_*.py", "*_test.py"])  # pytest's default
        if isinstance(patterns, str):
            patterns = patterns.split()
        for module in self.modules:
            filename = module.rpartition(".")[2] + ".py"
            with self.subTest(module=module):
                self.assertTrue(any(fnmatch.fnmatch(filename, p) for p in patterns), patterns)


if __name__ == "__main__":
    unittest.main()

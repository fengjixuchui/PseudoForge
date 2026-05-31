import json
import tempfile
import unittest
import zipfile
from pathlib import Path

import ida_pseudoforge
from ida_pseudoforge.version import PLUGIN_NAME, VERSION, plugin_title
from tools import release_pseudoforge


class ReleasePseudoForgeTests(unittest.TestCase):
    def test_plugin_version_matches_manifest(self):
        manifest_path = Path(__file__).resolve().parents[1] / "ida-plugin.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(VERSION, manifest["plugin"]["version"])
        self.assertEqual(VERSION, ida_pseudoforge.__version__)
        self.assertEqual("PseudoForge", PLUGIN_NAME)
        self.assertEqual("PseudoForge %s" % VERSION, plugin_title())

    def test_bump_version(self):
        self.assertEqual("1.2.4", release_pseudoforge.bump_version("1.2.3", "patch"))
        self.assertEqual("1.3.0", release_pseudoforge.bump_version("1.2.3", "minor"))
        self.assertEqual("2.0.0", release_pseudoforge.bump_version("1.2.3", "major"))

    def test_prepare_release_bumps_versions_and_writes_zip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = _write_minimal_repo(Path(temp_dir), "0.1.0")

            result = release_pseudoforge.prepare_release(repo_root, output_dir="release")

            self.assertEqual(result.old_version, "0.1.0")
            self.assertEqual(result.new_version, "0.1.1")
            self.assertEqual(result.archive_path.name, "PseudoForge-0.1.1.zip")
            self.assertTrue(result.archive_path.exists())
            self.assertEqual(64, len(result.sha256))
            self.assertIn('VERSION = "0.1.1"', (repo_root / "ida_pseudoforge" / "version.py").read_text())
            manifest = json.loads((repo_root / "ida-plugin.json").read_text(encoding="utf-8"))
            self.assertEqual("0.1.1", manifest["plugin"]["version"])
            self.assertIn("Current plugin version: `0.1.1`.", (repo_root / "README.md").read_text())
            self.assertIn(
                "Current plugin version: `0.1.1`.",
                (repo_root / "pseudoforge_implementation_status.md").read_text(),
            )
            with zipfile.ZipFile(result.archive_path) as archive:
                names = set(archive.namelist())
            self.assertIn("pseudoforge.py", names)
            self.assertIn("ida-plugin.json", names)
            self.assertIn("ida_pseudoforge/version.py", names)
            self.assertIn("README.md", names)
            self.assertNotIn("ida_pseudoforge/__pycache__/ignored.pyc", names)
            self.assertNotIn("tests/not_packaged.py", names)
            self.assertNotIn("tools/not_packaged.py", names)

    def test_prepare_release_no_version_bump_packages_current_version(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = _write_minimal_repo(Path(temp_dir), "0.1.0")

            result = release_pseudoforge.prepare_release(repo_root, no_version_bump=True)

            self.assertEqual(result.old_version, "0.1.0")
            self.assertEqual(result.new_version, "0.1.0")
            self.assertEqual(result.archive_path.name, "PseudoForge-0.1.0.zip")
            self.assertIn('VERSION = "0.1.0"', (repo_root / "ida_pseudoforge" / "version.py").read_text())

    def test_prepare_release_rejects_manifest_runtime_version_mismatch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = _write_minimal_repo(Path(temp_dir), "0.1.0")
            manifest_path = repo_root / "ida-plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["plugin"]["version"] = "0.2.0"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(release_pseudoforge.ReleaseError, "does not match"):
                release_pseudoforge.prepare_release(repo_root)

    def test_prepare_release_dry_run_does_not_write_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = _write_minimal_repo(Path(temp_dir), "0.1.0")

            result = release_pseudoforge.prepare_release(repo_root, dry_run=True)

            self.assertEqual(result.new_version, "0.1.1")
            self.assertFalse(result.archive_path.exists())
            self.assertEqual("", result.sha256)
            self.assertIn('VERSION = "0.1.0"', (repo_root / "ida_pseudoforge" / "version.py").read_text())


def _write_minimal_repo(root: Path, version: str) -> Path:
    package_root = root / "ida_pseudoforge"
    package_root.mkdir(parents=True)
    (package_root / "version.py").write_text(
        'from __future__ import annotations\n\nPLUGIN_NAME = "PseudoForge"\nVERSION = "%s"\n__version__ = VERSION\n'
        % version,
        encoding="utf-8",
    )
    (package_root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    pycache = package_root / "__pycache__"
    pycache.mkdir()
    (pycache / "ignored.pyc").write_bytes(b"ignored")
    (root / "pseudoforge.py").write_text("def PLUGIN_ENTRY():\n    return None\n", encoding="utf-8")
    (root / "ida-plugin.json").write_text(
        json.dumps({"plugin": {"version": version}}, indent=2) + "\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text("Current plugin version: `%s`.\n" % version, encoding="utf-8")
    (root / "pseudoforge_implementation_status.md").write_text(
        "Current plugin version: `%s`.\n" % version,
        encoding="utf-8",
    )
    tests_dir = root / "tests"
    tools_dir = root / "tools"
    tests_dir.mkdir()
    tools_dir.mkdir()
    (tests_dir / "not_packaged.py").write_text("", encoding="utf-8")
    (tools_dir / "not_packaged.py").write_text("", encoding="utf-8")
    return root


if __name__ == "__main__":
    unittest.main()

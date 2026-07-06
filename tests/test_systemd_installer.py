import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class SystemdInstallerTests(unittest.TestCase):
    def make_project_copy(self):
        tmp_dir = tempfile.TemporaryDirectory()
        project_dir = Path(tmp_dir.name) / "GhostMerge"
        shutil.copytree(
            PROJECT_ROOT,
            project_dir,
            ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".pytest_cache"),
        )
        venv_bin = project_dir / ".venv" / "bin"
        venv_bin.mkdir(parents=True)
        flask_path = venv_bin / "flask"
        flask_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        flask_path.chmod(flask_path.stat().st_mode | stat.S_IXUSR)
        shutil.copyfile(project_dir / "ghostmerge_config.example.json", project_dir / "ghostmerge_config.json")
        return tmp_dir, project_dir

    def run_installer(self, project_dir, *args):
        env = os.environ.copy()
        env.pop("SUDO_USER", None)
        return subprocess.run(
            [
                str(project_dir / "install-systemd-service.sh"),
                "--dry-run",
                "--project-dir",
                str(project_dir),
                *args,
            ],
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )

    def test_dry_run_renders_service_with_expected_defaults(self):
        tmp_dir, project_dir = self.make_project_copy()
        with tmp_dir:
            result = self.run_installer(project_dir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Description=GhostMerge Flask web frontend", result.stdout)
        self.assertIn("User=ghostmerge", result.stdout)
        self.assertIn("Group=ghostmerge", result.stdout)
        self.assertIn(f"Documentation=file://{project_dir}/README.md", result.stdout)
        self.assertIn(f"WorkingDirectory={project_dir}", result.stdout)
        self.assertIn(
            f"ExecStart={project_dir}/.venv/bin/flask --app web_app:create_app run --host 127.0.0.1 --port 5000",
            result.stdout,
        )
        self.assertIn(f"ReadWritePaths={project_dir}", result.stdout)

    def test_dry_run_renders_custom_network_binding(self):
        tmp_dir, project_dir = self.make_project_copy()
        with tmp_dir:
            result = self.run_installer(project_dir, "--host", "0.0.0.0", "--port", "8080")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--host 0.0.0.0 --port 8080", result.stdout)

    def test_installer_refuses_missing_config(self):
        tmp_dir, project_dir = self.make_project_copy()
        with tmp_dir:
            (project_dir / "ghostmerge_config.json").unlink()
            result = self.run_installer(project_dir)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ghostmerge_config.json is required", result.stderr)

    def test_installer_rejects_invalid_port(self):
        tmp_dir, project_dir = self.make_project_copy()
        with tmp_dir:
            result = self.run_installer(project_dir, "--port", "70000")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--port must be between 1 and 65535", result.stderr)

    def test_installer_rejects_root_service_user(self):
        tmp_dir, project_dir = self.make_project_copy()
        with tmp_dir:
            result = self.run_installer(project_dir, "--user", "root")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("service must not run as root", result.stderr)

    def test_dry_run_accepts_no_check_access_flag(self):
        tmp_dir, project_dir = self.make_project_copy()
        with tmp_dir:
            result = self.run_installer(project_dir, "--no-check-access")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("User=ghostmerge", result.stdout)


if __name__ == "__main__":
    unittest.main()

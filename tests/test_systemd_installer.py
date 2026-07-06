import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class SystemdInstallerTests(unittest.TestCase):
    def make_project_copy(self, create_venv=True):
        tmp_dir = tempfile.TemporaryDirectory()
        project_dir = Path(tmp_dir.name) / "GhostMerge"
        shutil.copytree(
            PROJECT_ROOT,
            project_dir,
            ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".pytest_cache"),
        )
        if create_venv:
            self.write_fake_flask(project_dir / ".venv")
        shutil.copyfile(project_dir / "ghostmerge_config.example.json", project_dir / "ghostmerge_config.json")
        return tmp_dir, project_dir

    def write_fake_flask(self, venv_dir):
        venv_bin = venv_dir / "bin"
        venv_bin.mkdir(parents=True)
        flask_path = venv_bin / "flask"
        flask_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        flask_path.chmod(flask_path.stat().st_mode | stat.S_IXUSR)
        return flask_path

    def write_fake_pipenv(self, bin_dir, venv_dir):
        bin_dir.mkdir(parents=True)
        pipenv_path = bin_dir / "pipenv"
        pipenv_path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{venv_dir}'\n", encoding="utf-8")
        pipenv_path.chmod(pipenv_path.stat().st_mode | stat.S_IXUSR)
        return pipenv_path

    def run_installer(self, project_dir, *args, env_overrides=None):
        env = os.environ.copy()
        env.pop("SUDO_USER", None)
        if env_overrides:
            env.update(env_overrides)
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

    def test_dry_run_uses_pipenv_virtualenv_when_project_venv_is_missing(self):
        tmp_dir, project_dir = self.make_project_copy(create_venv=False)
        with tmp_dir:
            pipenv_venv = Path(tmp_dir.name) / "pipenv-venv"
            fake_bin = Path(tmp_dir.name) / "bin"
            self.write_fake_flask(pipenv_venv)
            self.write_fake_pipenv(fake_bin, pipenv_venv)
            result = self.run_installer(
                project_dir,
                env_overrides={"PATH": f"{fake_bin}:{os.environ['PATH']}"},
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            f"ExecStart={pipenv_venv}/bin/flask --app web_app:create_app run --host 127.0.0.1 --port 5000",
            result.stdout,
        )

    def test_dry_run_refuses_missing_virtualenv_without_installing_dependencies(self):
        tmp_dir, project_dir = self.make_project_copy(create_venv=False)
        with tmp_dir:
            for manifest_name in ("Pipfile", "requirements.txt"):
                manifest_path = project_dir / manifest_name
                if manifest_path.exists():
                    manifest_path.unlink()
            result = self.run_installer(project_dir, "--no-install-deps")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Flask executable not found or not executable", result.stderr)

    def test_dry_run_ignores_root_pipenv_virtualenv(self):
        tmp_dir, project_dir = self.make_project_copy(create_venv=False)
        with tmp_dir:
            fake_bin = Path(tmp_dir.name) / "bin"
            self.write_fake_pipenv(fake_bin, "/root/.local/share/virtualenvs/GhostMerge-test")
            result = self.run_installer(
                project_dir,
                "--no-install-deps",
                env_overrides={"PATH": f"{fake_bin}:{os.environ['PATH']}"},
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ignoring Pipenv virtualenv under /root", result.stderr)

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

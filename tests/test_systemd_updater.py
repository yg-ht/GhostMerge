import grp
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class SystemdUpdaterTests(unittest.TestCase):
    def make_deployment(self):
        tmp_dir = tempfile.TemporaryDirectory()
        root = Path(tmp_dir.name)
        project_dir = root / "GhostMerge"
        shutil.copytree(
            PROJECT_ROOT,
            project_dir,
            ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".pytest_cache"),
        )
        (project_dir / "ghostmerge_config.json").write_text("{}\n", encoding="utf-8")
        venv_bin = project_dir / ".venv" / "bin"
        venv_bin.mkdir(parents=True)
        (venv_bin / "python").symlink_to(sys.executable)

        subprocess.run(["git", "init", "-q", str(project_dir)], check=True)
        subprocess.run(["git", "-C", str(project_dir), "add", "."], check=True)
        subprocess.run(
            [
                "git", "-C", str(project_dir), "-c", "user.name=GhostMerge tests",
                "-c", "user.email=tests@example.invalid", "commit", "-qm", "fixture",
            ],
            check=True,
        )

        service_user = pwd.getpwuid(os.getuid()).pw_name
        service_group = grp.getgrgid(os.getgid()).gr_name
        unit_path = root / "ghostmerge-web.service"
        unit_path.write_text(
            "[Service]\n"
            f"User={service_user}\n"
            f"Group={service_group}\n"
            f"WorkingDirectory={project_dir}\n"
            f"ExecStart={venv_bin / 'gunicorn'} --bind 127.0.0.1:5000 web_app:create_app()\n",
            encoding="utf-8",
        )
        unit_path.chmod(0o644)

        fake_bin = root / "bin"
        fake_bin.mkdir()
        systemctl = fake_bin / "systemctl"
        systemctl.write_text(
            "#!/bin/sh\n"
            "case \"$*\" in\n"
            "  *--property=FragmentPath*) printf '%s\\n' \"$FAKE_UNIT\" ;;\n"
            "  *--property=WorkingDirectory*) printf '%s\\n' \"$FAKE_PROJECT\" ;;\n"
            "  *--property=User*) printf '%s\\n' \"$FAKE_USER\" ;;\n"
            "  *--property=Group*) printf '%s\\n' \"$FAKE_GROUP\" ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        systemctl.chmod(systemctl.stat().st_mode | stat.S_IXUSR)
        fake_stat = fake_bin / "stat"
        fake_stat.write_text(
            "#!/bin/sh\n"
            "last=''\n"
            "for item in \"$@\"; do last=$item; done\n"
            "if [ \"$last\" = \"$FAKE_METADATA\" ]; then\n"
            "  case \"$*\" in *%U:%G:%a*) printf 'root:root:644\\n'; exit 0 ;; esac\n"
            "fi\n"
            "if [ \"$last\" = \"$FAKE_UNIT\" ]; then\n"
            "  case \"$*\" in *%U:%G*) printf 'root:root\\n'; exit 0 ;; esac\n"
            "fi\n"
            "exec /usr/bin/stat \"$@\"\n",
            encoding="utf-8",
        )
        fake_stat.chmod(fake_stat.stat().st_mode | stat.S_IXUSR)

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{fake_bin}:{env['PATH']}",
                "GHOSTMERGE_METADATA_DIR": str(root / "metadata"),
                "FAKE_METADATA": str(root / "metadata" / "ghostmerge-web.json"),
                "FAKE_UNIT": str(unit_path),
                "FAKE_PROJECT": str(project_dir),
                "FAKE_USER": service_user,
                "FAKE_GROUP": service_group,
            }
        )
        return tmp_dir, project_dir, env

    def write_metadata(self, project_dir, env, **overrides):
        values = {
            "service_name": "ghostmerge-web",
            "project_dir": str(project_dir),
            "venv_dir": str(project_dir / ".venv"),
            "service_user": env["FAKE_USER"],
            "service_group": env["FAKE_GROUP"],
            "host": "127.0.0.1",
            "port": "5000",
        }
        values.update(overrides)
        metadata_path = Path(env["FAKE_METADATA"])
        metadata_path.parent.mkdir()
        metadata_path.write_text(json.dumps(values) + "\n", encoding="utf-8")

    def run_updater(self, project_dir, env, *args):
        return subprocess.run(
            [
                str(project_dir / "update-systemd-service.sh"),
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

    def test_dry_run_recovers_legacy_unit_settings(self):
        tmp_dir, project_dir, env = self.make_deployment()
        with tmp_dir:
            result = self.run_updater(project_dir, env)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GhostMerge update preflight passed", result.stdout)
        self.assertIn(f"Project: {project_dir}", result.stdout)
        self.assertIn(f"Virtualenv: {project_dir / '.venv'}", result.stdout)
        self.assertIn("Bind: 127.0.0.1:5000", result.stdout)

    def test_dry_run_accepts_matching_installer_metadata(self):
        tmp_dir, project_dir, env = self.make_deployment()
        with tmp_dir:
            self.write_metadata(project_dir, env)
            result = self.run_updater(project_dir, env)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dry_run_rejects_metadata_that_disagrees_with_unit(self):
        tmp_dir, project_dir, env = self.make_deployment()
        with tmp_dir:
            self.write_metadata(project_dir, env, port="5999")
            result = self.run_updater(project_dir, env)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the installed systemd unit", result.stderr)

    def test_dry_run_rejects_invalid_local_configuration(self):
        tmp_dir, project_dir, env = self.make_deployment()
        with tmp_dir:
            config_path = project_dir / "ghostmerge_config.json"
            config_path.write_text("[]\n", encoding="utf-8")
            result = self.run_updater(project_dir, env)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Configuration root must be an object", result.stderr)

    def test_dry_run_rejects_checkout_other_than_installed_project(self):
        tmp_dir, project_dir, env = self.make_deployment()
        with tmp_dir:
            different_path = Path(tmp_dir.name) / "different"
            different_path.mkdir()
            result = self.run_updater(project_dir, env, "--project-dir", str(different_path))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match installed project", result.stderr)

    def test_dry_run_rejects_unsafe_service_name_before_systemd_lookup(self):
        tmp_dir, project_dir, env = self.make_deployment()
        with tmp_dir:
            result = self.run_updater(project_dir, env, "--service-name", "../ghostmerge")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("may contain only", result.stderr)


if __name__ == "__main__":
    unittest.main()

import grp
import json
import os
import pwd
import shutil
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class SystemdUpdaterTests(unittest.TestCase):
    def test_deployment_generated_pip_cache_is_ignored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = Path(temp_dir)
            shutil.copyfile(PROJECT_ROOT / ".gitignore", repository / ".gitignore")
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "check-ignore",
                    "--quiet",
                    ".cache/pip/http-v2/example",
                ],
                check=False,
            )

        self.assertEqual(result.returncode, 0)

    def test_candidate_dependency_install_disables_pip_cache(self):
        updater = (PROJECT_ROOT / "update-systemd-service.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "--disable-pip-version-check --no-cache-dir -r requirements.txt",
            updater,
        )

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
        (project_dir / "ghostmerge_web_jobs").mkdir(exist_ok=True)
        venv_bin = project_dir / ".venv" / "bin"
        venv_bin.mkdir(parents=True)
        fake_venv_builder = Path(tmp_dir.name) / "fake_venv_builder.py"
        fake_venv_builder.write_text(
            "import pathlib, shlex, stat, sys\n"
            "target = pathlib.Path(sys.argv[1])\n"
            "runtime = sys.argv[2]\n"
            "(target / 'bin').mkdir(parents=True, exist_ok=True)\n"
            "python = target / 'bin' / 'python'\n"
            "python.write_text(f'#!/bin/sh\\nexec {shlex.quote(runtime)} \\\"$@\\\"\\n')\n"
            "python.chmod(python.stat().st_mode | stat.S_IXUSR)\n",
            encoding="utf-8",
        )
        python_path = venv_bin / "python"
        python_path.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = '-m' ] && [ \"$2\" = 'venv' ]; then\n"
            f"  exec {shlex.quote(sys.executable)} {shlex.quote(str(fake_venv_builder))} \"$3\" "
            f"{shlex.quote(sys.executable)}\n"
            "fi\n"
            f"exec {shlex.quote(sys.executable)} \"$@\"\n",
            encoding="utf-8",
        )
        python_path.chmod(python_path.stat().st_mode | stat.S_IXUSR)

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
            "  is-active*) exit 0 ;;\n"
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

    def run_rollback_harness(self, project_dir, previous_revision, *, dirty=False):
        marker_path = project_dir / "ghostmerge_web_jobs" / ".deployment-maintenance"
        marker_path.touch()
        candidate_dir = project_dir / ".ghostmerge-web-venv.rollback"
        candidate_dir.mkdir()
        if dirty:
            (project_dir / "README.md").write_text("concurrent operator change\n", encoding="utf-8")
        events_path = project_dir.parent / "systemctl-events"
        harness = r'''
source "$1"
PROJECT_DIR="$2"
PREVIOUS_REVISION="$3"
TARGET_REVISION="$(git -C "$2" rev-parse HEAD)"
APP_OWNER="$(id -un)"
APP_OWNER_HOME="$HOME"
SERVICE_NAME="ghostmerge-web"
SERVICE_WAS_STOPPED=1
CHECKOUT_CHANGED=1
UNIT_BACKUP=""
UNIT_PATH=""
HAD_METADATA=0
METADATA_PATH=""
MAINTENANCE_PATH="$4"
MAINTENANCE_CREATED=1
CANDIDATE_VENV_DIR="$5"
CANDIDATE_VENV_KEEP=0
SNAPSHOT_PATH=""
STAGING_DIR=""
EVENTS_PATH="$6"
systemctl() { printf '%s\n' "$*" >> "$EVENTS_PATH"; }
run_as_owner() { "$@"; }
restore_previous_installation
remove_temporary_files
'''
        result = subprocess.run(
            [
                "bash",
                "-c",
                harness,
                "rollback-harness",
                str(project_dir / "update-systemd-service.sh"),
                str(project_dir),
                previous_revision,
                str(marker_path),
                str(candidate_dir),
                str(events_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        events = events_path.read_text(encoding="utf-8") if events_path.exists() else ""
        return result, marker_path, candidate_dir, events

    def run_health_check(self, response_body):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(response_body)

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        harness = r'''
source "$1"
SERVICE_USER="$(id -un)"
SERVICE_USER_HOME="$HOME"
CANDIDATE_VENV_DIR="$2"
HOST="127.0.0.1"
PORT="$3"
HEALTH_TIMEOUT_SECONDS=1
wait_for_ghostmerge_http
'''
        try:
            return subprocess.run(
                [
                    "bash", "-c", harness, "health-harness",
                    str(PROJECT_ROOT / "update-systemd-service.sh"),
                    str(Path(sys.executable).parent.parent),
                    str(server.server_port),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_dry_run_recovers_legacy_unit_settings(self):
        tmp_dir, project_dir, env = self.make_deployment()
        with tmp_dir:
            result = self.run_updater(project_dir, env)

        self.assertEqual(result.returncode, 0, f"{result.stderr}\n{result.stdout}")
        self.assertIn("GhostMerge installation preflight passed", result.stdout)
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

    def test_dry_run_rejects_running_operation_state(self):
        tmp_dir, project_dir, env = self.make_deployment()
        with tmp_dir:
            imports_dir = project_dir / "ghostmerge_web_jobs" / "api_imports"
            imports_dir.mkdir(parents=True)
            (imports_dir / "active123.json").write_text(
                json.dumps({"status": "running", "worker_pid": os.getpid()}),
                encoding="utf-8",
            )
            result = self.run_updater(project_dir, env)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Active GhostMerge operations prevent a safe update", result.stderr)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses discretionary file permissions")
    def test_dry_run_fails_closed_when_operation_state_is_unreadable(self):
        tmp_dir, project_dir, env = self.make_deployment()
        jobs_dir = project_dir / "ghostmerge_web_jobs"
        with tmp_dir:
            jobs_dir.chmod(0)
            try:
                result = self.run_updater(project_dir, env)
            finally:
                jobs_dir.chmod(0o755)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("operation state is not readable", result.stderr)

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

    def test_rollback_restores_clean_checkout_and_removes_candidate_runtime(self):
        tmp_dir, project_dir, _ = self.make_deployment()
        with tmp_dir:
            previous_revision = subprocess.run(
                ["git", "-C", str(project_dir), "rev-parse", "HEAD"],
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
            (project_dir / "README.md").write_text("updated release\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(project_dir), "add", "README.md"], check=True)
            subprocess.run(
                [
                    "git", "-C", str(project_dir), "-c", "user.name=GhostMerge tests",
                    "-c", "user.email=tests@example.invalid", "commit", "-qm", "candidate",
                ],
                check=True,
            )

            result, marker_path, candidate_dir, events = self.run_rollback_harness(
                project_dir,
                previous_revision,
            )
            restored_revision = subprocess.run(
                ["git", "-C", str(project_dir), "rev-parse", "HEAD"],
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(restored_revision, previous_revision)
        self.assertFalse(marker_path.exists())
        self.assertFalse(candidate_dir.exists())
        self.assertIn("start ghostmerge-web.service", events)

    def test_rollback_preserves_concurrent_checkout_changes_and_stays_stopped(self):
        tmp_dir, project_dir, _ = self.make_deployment()
        with tmp_dir:
            previous_revision = subprocess.run(
                ["git", "-C", str(project_dir), "rev-parse", "HEAD"],
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
            (project_dir / "README.md").write_text("candidate release\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(project_dir), "add", "README.md"], check=True)
            subprocess.run(
                [
                    "git", "-C", str(project_dir), "-c", "user.name=GhostMerge tests",
                    "-c", "user.email=tests@example.invalid", "commit", "-qm", "candidate",
                ],
                check=True,
            )
            candidate_revision = subprocess.run(
                ["git", "-C", str(project_dir), "rev-parse", "HEAD"],
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()

            result, _, _, events = self.run_rollback_harness(
                project_dir,
                previous_revision,
                dirty=True,
            )
            retained_revision = subprocess.run(
                ["git", "-C", str(project_dir), "rev-parse", "HEAD"],
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(retained_revision, candidate_revision)
        self.assertIn("refusing to discard", result.stderr)
        self.assertNotIn("start ghostmerge-web.service", events)

    def test_cleanup_preserves_maintenance_marker_it_did_not_create(self):
        tmp_dir, project_dir, _ = self.make_deployment()
        marker_path = project_dir / "ghostmerge_web_jobs" / ".deployment-maintenance"
        marker_path.touch()
        harness = r'''
source "$1"
SERVICE_NAME="ghostmerge-web"
MAINTENANCE_PATH="$2"
MAINTENANCE_CREATED=0
remove_temporary_files
'''
        with tmp_dir:
            result = subprocess.run(
                ["bash", "-c", harness, "cleanup-harness", str(project_dir / "update-systemd-service.sh"), str(marker_path)],
                text=True,
                capture_output=True,
                check=False,
            )
            marker_remained = marker_path.exists()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(marker_remained)

    def test_health_check_requires_ghostmerge_response(self):
        valid = self.run_health_check(b"<html><title>GhostMerge</title></html>")
        unrelated = self.run_health_check(b"<html><title>Different service</title></html>")

        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertNotEqual(unrelated.returncode, 0)
        self.assertIn("did not identify itself as GhostMerge", unrelated.stderr)

    def test_candidate_runtime_is_built_separately_and_removed_until_committed(self):
        tmp_dir, project_dir, _ = self.make_deployment()
        candidate_source = Path(tmp_dir.name) / "candidate-source"
        candidate_source.mkdir()
        (candidate_source / "requirements.txt").write_text("", encoding="utf-8")
        (candidate_source / "candidate_module.py").write_text(
            "CANDIDATE_READY = True\n", encoding="utf-8"
        )
        candidate_tests = candidate_source / "tests"
        candidate_tests.mkdir()
        (candidate_tests / "test_updater_environment.py").write_text(
            "import os\n\n"
            "def test_updater_private_environment_is_not_exposed():\n"
            "    assert 'GHOSTMERGE_UPDATE_PROJECT_DIR' not in os.environ\n"
            "    assert 'GHOSTMERGE_UPDATE_SNAPSHOT' not in os.environ\n"
            "    assert 'GHOSTMERGE_UPDATE_SNAPSHOT_PATH' not in os.environ\n",
            encoding="utf-8",
        )
        candidate_tests.chmod(0o555)
        candidate_source.chmod(0o555)
        harness = r'''
source "$1"
SERVICE_NAME="ghostmerge-web"
VENV_DIR="$2"
VENV_OWNER="$(id -un)"
VENV_OWNER_HOME="$HOME"
STAGING_DIR="$3"
RUN_TESTS=1
prepare_candidate_runtime
printf '%s\n' "$CANDIDATE_VENV_DIR"
STAGING_DIR=""
remove_temporary_files
'''
        with tmp_dir:
            candidate_env = os.environ.copy()
            candidate_env.update(
                {
                    "GHOSTMERGE_UPDATE_PROJECT_DIR": "/unexpected/project",
                    "GHOSTMERGE_UPDATE_SNAPSHOT": "1",
                    "GHOSTMERGE_UPDATE_SNAPSHOT_PATH": "/tmp/ghostmerge-systemd-update.test",
                }
            )
            result = subprocess.run(
                [
                    "bash", "-c", harness, "candidate-harness",
                    str(project_dir / "update-systemd-service.sh"),
                    str(project_dir / ".venv"),
                    str(candidate_source),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=candidate_env,
            )
            candidate_path = Path(result.stdout.strip().splitlines()[-1])
            original_runtime_remained = (project_dir / ".venv" / "bin" / "python").exists()
            candidate_was_removed = not candidate_path.exists()
            source_cache_was_not_created = not (candidate_source / "__pycache__").exists()
            pytest_cache_was_not_created = not (candidate_source / ".pytest_cache").exists()
            candidate_source.chmod(0o755)
            candidate_tests.chmod(0o755)

        self.assertEqual(result.returncode, 0, f"{result.stderr}\n{result.stdout}")
        self.assertNotEqual(candidate_path, project_dir / ".venv")
        self.assertTrue(original_runtime_remained)
        self.assertTrue(candidate_was_removed)
        self.assertTrue(source_cache_was_not_created)
        self.assertTrue(pytest_cache_was_not_created)


if __name__ == "__main__":
    unittest.main()

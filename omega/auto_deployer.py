"""Despliegue remoto IAO mediante SSH, sin proveedor implícito."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class DeploymentResult:
    status: str
    target: str | None = None
    detail: str | None = None
    health_verified: bool = False

    def as_dict(self):
        return {
            "status": self.status,
            "target": self.target,
            "detail": self.detail,
            "health_verified": self.health_verified,
        }


def _iao_enforce_release_gate():
    """Bloquea despliegues si falta evidencia reciente y válida de autorización."""
    import json
    import os
    import time

    if os.environ.get("IAO_RELEASE_GATE_REQUIRED") != "1":
        return None

    def blocked():
        raise RuntimeError("IAO_RELEASE_GATE_BLOCKED")

    report_path = os.environ.get("IAO_RELEASE_GATE_REPORT", "").strip()
    if not report_path:
        blocked()

    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except Exception:
        blocked()

    if not isinstance(report, dict):
        blocked()
    if report.get("version") != 1:
        blocked()
    if report.get("release_authorized") is not True:
        blocked()
    if report.get("status") != "READY_FOR_SEPARATE_DEPLOYMENT_REVIEW":
        blocked()
    if report.get("deployment_performed") is not False:
        blocked()
    if report.get("external_service_verified") is not False:
        blocked()

    passed = report.get("checks_passed")
    failed = report.get("checks_failed")
    checks = report.get("checks")
    timestamp = report.get("timestamp")

    if isinstance(passed, bool) or not isinstance(passed, int) or passed < 1:
        blocked()
    if isinstance(failed, bool) or not isinstance(failed, int) or failed != 0:
        blocked()
    if not isinstance(checks, list) or not checks:
        blocked()
    if any(not isinstance(item, dict) or item.get("ok") is not True
           for item in checks):
        blocked()
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
        blocked()

    age = time.time() - timestamp
    if age < -60 or age > 300:
        blocked()

    return None


class AutoDeployer:
    """Deploy SSH explícito. Nunca crea recursos de terceros automáticamente."""

    def __init__(self, environ=None, runner=None, opener=None):
        self.env = environ if environ is not None else os.environ
        self.runner = runner or subprocess.run
        self.opener = opener or urllib.request.urlopen

    def _configuration(self):
        target = self.env.get("IAO_DEPLOYMENT_TARGET", "").strip()
        repo = self.env.get("IAO_DEPLOYMENT_REPO", "").strip()
        branch = self.env.get("IAO_DEPLOYMENT_BRANCH", "main").strip()
        remote_dir = self.env.get(
            "IAO_DEPLOYMENT_REMOTE_DIR", "~/iao-node"
        ).strip()
        start = self.env.get("IAO_DEPLOYMENT_START_COMMAND", "").strip()
        health = self.env.get("IAO_DEPLOYMENT_HEALTH_URL", "").strip()

        if not target:
            return None, "NO_SSH_TARGET_CONFIGURED"
        if not repo.startswith("https://"):
            return None, "HTTPS_REPOSITORY_REQUIRED"
        if not branch or not remote_dir or not start or not health:
            return None, "DEPLOYMENT_CONFIGURATION_INCOMPLETE"

        parsed = urlparse(health)
        if parsed.scheme != "https" or not parsed.hostname:
            return None, "HTTPS_HEALTH_URL_REQUIRED"
        if parsed.username or parsed.password:
            return None, "HEALTH_URL_CREDENTIALS_FORBIDDEN"
        if any(c in target for c in "\r\n"):
            return None, "INVALID_SSH_TARGET"
        if any(c in remote_dir for c in "\r\n"):
            return None, "INVALID_REMOTE_DIRECTORY"
        return {
            "target": target,
            "repo": repo,
            "branch": branch,
            "remote_dir": remote_dir,
            "start": start,
            "health": health,
        }, None

    def verify_health(self, url, attempts=5, delay=2):
        for attempt in range(attempts):
            try:
                req = urllib.request.Request(
                    url, headers={"Accept": "application/json"}
                )
                with self.opener(req, timeout=8) as response:
                    if response.status != 200:
                        continue
                    data = json.loads(response.read(65536))
                if isinstance(data, dict) and data.get("status") == "live":
                    return True
            except Exception:
                pass
            if attempt + 1 < attempts:
                time.sleep(delay)
        return False

    def deploy_ssh(self):
        _iao_enforce_release_gate()
        cfg, error = self._configuration()
        if error:
            return DeploymentResult("BLOCKED", detail=error).as_dict()

        # El comando remoto se construye con quoting por argumento.
        # El start command es configuración administrativa explícita.
        remote = (
            "set -eu; "
            "command -v git >/dev/null; "
            "command -v python3 >/dev/null; "
            f"if test -d {shlex.quote(cfg['remote_dir'] + '/.git')}; then "
            f"git -C {shlex.quote(cfg['remote_dir'])} fetch --depth=1 origin "
            f"{shlex.quote(cfg['branch'])}; "
            f"git -C {shlex.quote(cfg['remote_dir'])} checkout "
            f"{shlex.quote(cfg['branch'])}; "
            f"git -C {shlex.quote(cfg['remote_dir'])} reset --hard "
            f"FETCH_HEAD; "
            "else "
            f"git clone --depth=1 --branch {shlex.quote(cfg['branch'])} "
            f"{shlex.quote(cfg['repo'])} {shlex.quote(cfg['remote_dir'])}; "
            "fi; "
            f"cd {shlex.quote(cfg['remote_dir'])}; "
            "python3 -m venv .venv; "
            ".venv/bin/python -m pip install --upgrade pip; "
            "if test -f requirements.txt; then "
            ".venv/bin/pip install -r requirements.txt; fi; "
            "mkdir -p .state; "
            f"nohup sh -lc {shlex.quote(cfg['start'])} "
            "> .state/iao-remote.log 2>&1 </dev/null &"
        )

        try:
            result = self.runner(
                [
                    "ssh",
                    "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=yes",
                    "-o", "ConnectTimeout=8",
                    cfg["target"],
                    remote,
                ],
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
        except Exception as exc:
            return DeploymentResult(
                "SSH_EXECUTION_ERROR",
                cfg["target"],
                type(exc).__name__,
            ).as_dict()

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "")[-1000:]
            return DeploymentResult(
                "REMOTE_DEPLOYMENT_FAILED",
                cfg["target"],
                detail,
            ).as_dict()

        healthy = self.verify_health(cfg["health"])
        return DeploymentResult(
            "DEPLOYED_HEALTHY" if healthy else "DEPLOYED_HEALTH_UNVERIFIED",
            cfg["target"],
            None if healthy else "REMOTE_PROCESS_STARTED_BUT_HEALTH_NOT_VERIFIED",
            healthy,
        ).as_dict()

    def create_new_node(self, node_name):
        # Compatibilidad: no se interpreta un nombre como destino SSH.
        if not isinstance(node_name, str) or not node_name.strip():
            return DeploymentResult(
                "BLOCKED", detail="INVALID_NODE_NAME"
            ).as_dict()
        return self.deploy_ssh()


deployer = AutoDeployer()

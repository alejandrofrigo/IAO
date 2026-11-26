import unittest
from unittest.mock import Mock

from omega.auto_deployer import AutoDeployer
from omega.swarm_orchestrator import SwarmOrchestrator


class DeployerTests(unittest.TestCase):
    def test_missing_target_fails_closed(self):
        d = AutoDeployer(environ={})
        r = d.deploy_ssh()
        self.assertEqual(r["status"], "BLOCKED")
        self.assertEqual(r["detail"], "NO_SSH_TARGET_CONFIGURED")

    def test_non_https_health_url_rejected(self):
        env = {
            "IAO_DEPLOYMENT_TARGET": "node",
            "IAO_DEPLOYMENT_REPO": "https://example.org/iao.git",
            "IAO_DEPLOYMENT_START_COMMAND": "python3 server.py",
            "IAO_DEPLOYMENT_HEALTH_URL": "http://example.org/health/live",
        }
        r = AutoDeployer(environ=env).deploy_ssh()
        self.assertEqual(r["detail"], "HTTPS_HEALTH_URL_REQUIRED")

    def test_ssh_failure_never_reports_deployed(self):
        env = {
            "IAO_DEPLOYMENT_TARGET": "node",
            "IAO_DEPLOYMENT_REPO": "https://example.org/iao.git",
            "IAO_DEPLOYMENT_START_COMMAND": "python3 server.py",
            "IAO_DEPLOYMENT_HEALTH_URL": "https://node.example.org/health/live",
        }
        runner = Mock(return_value=Mock(
            returncode=255, stderr="connection refused", stdout=""
        ))
        d = AutoDeployer(environ=env, runner=runner)
        r = d.deploy_ssh()
        self.assertEqual(r["status"], "REMOTE_DEPLOYMENT_FAILED")
        runner.assert_called_once()

    def test_orchestrator_does_not_expand_without_target(self):
        s = SwarmOrchestrator(environ={})
        r = s.start_expansion()
        self.assertEqual(r["status"], "BLOCKED")
        self.assertEqual(r["attempted_deployments"], 0)


if __name__ == "__main__":
    unittest.main()

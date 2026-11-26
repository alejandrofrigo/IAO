"""Orquestación de despliegue acotada; sin expansión infinita."""
from __future__ import annotations

import os
from omega.auto_deployer import AutoDeployer


class SwarmOrchestrator:
    def __init__(self, deployer=None, environ=None):
        self.deployer = deployer or AutoDeployer(environ=environ)
        self.env = environ if environ is not None else os.environ
        self.deployed_nodes = []

    def deploy_replica(self, node_name):
        result = self.deployer.create_new_node(node_name)
        if result.get("status") == "DEPLOYED_HEALTHY":
            self.deployed_nodes.append(result)
        return result

    def start_expansion(self):
        # Una sola operación por invocación. La expansión sostenida
        # requiere un supervisor con presupuesto y política explícitos.
        target = self.env.get("IAO_DEPLOYMENT_TARGET", "").strip()
        if not target:
            return {
                "status": "BLOCKED",
                "reason": "NO_SSH_TARGET_CONFIGURED",
                "attempted_deployments": 0,
            }
        result = self.deploy_replica("iao-node")
        return {
            "status": result.get("status", "UNKNOWN"),
            "attempted_deployments": 1,
            "results": [result],
        }

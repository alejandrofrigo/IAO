from omega.autonomous_core import AutonomousCore

class AutonomousCoordinator:
    def __init__(self, core=None):
        self.core = core or AutonomousCore()

    def receive_plan(self, plan, source="IAO_CORE_1"):
        if not isinstance(plan, dict):
            raise TypeError("plan must be an object")
        return self.core.submit(
            plan.get("kind", "self_check"),
            plan.get("payload", {}),
            source=source,
        )

    def status(self):
        return self.core.status()

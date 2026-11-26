import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argparse  # noqa: E402
import json  # noqa: E402
from omega.autonomous_core import AutonomousCore  # noqa: E402

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["status", "install-check", "cycle", "serve"])
    args = parser.parse_args()
    core = AutonomousCore()

    if args.action == "install-check":
        for kind in ("self_check", "capability_scan", "improvement_plan"):
            core.submit(kind, {}, source="INSTALLATION")
        print(json.dumps(core.cycle(3), indent=2))
    elif args.action == "cycle":
        print(json.dumps(core.cycle(3), indent=2))
    elif args.action == "serve":
        print("CORE2_FOREGROUND_WORKER=STARTED")
        try:
            core.serve()
        except KeyboardInterrupt:
            print("CORE2_STOPPED_BY_OPERATOR")
    else:
        print(json.dumps(core.status(), indent=2))

if __name__ == "__main__":
    main()

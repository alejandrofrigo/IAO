import ast, os, tempfile
from pathlib import Path
from datetime import datetime, timezone

p = Path("omega/autonomous_authority.py")
src = p.read_text()
tree = ast.parse(src)
nodes = {n.name:n for n in tree.body if isinstance(n, ast.FunctionDef)}

for name in ("authorize", "component_permissions"):
    if name not in nodes:
        raise SystemExit("ABORTADO: falta " + name)

policy = '''
COMPONENT_POLICY = {
 "PADGE":{"CODE_IMPROVEMENT":{"CODE_IMPROVEMENT"},"TESTING":{"TESTING"},"READ_ONLY":{"READ_ONLY"}},
 "AUTOBUILDER":{"TESTING":{"TESTING"},"READ_ONLY":{"READ_ONLY"}},
 "AUTOCONSTRUCTION":{"TESTING":{"TESTING"},"READ_ONLY":{"READ_ONLY"}},
 "AUTONOMY":{"READ_ONLY":{"READ_ONLY"},"TESTING":{"TESTING"},"INTERNAL_COORDINATION":{"INTERNAL_COORDINATION"},"TASK_CREATION":{"TASK_CREATION"},"RECOVERY":{"RECOVERY"}},
 "WORKERS":{"READ_ONLY":{"READ_ONLY"},"TESTING":{"TESTING"},"INTERNAL_COORDINATION":{"INTERNAL_COORDINATION"},"TASK_CREATION":{"TASK_CREATION"},"RECOVERY":{"RECOVERY"}},
 "MULTI_LLM":{"LLM_REQUEST":{"LLM_REQUEST"}},
 "GUARDIAN":{"READ_ONLY":{"READ_ONLY"},"RECOVERY":{"RECOVERY"}},
 "FEDERATION":{"READ_ONLY":{"READ_ONLY"},"INTERNAL_COORDINATION":{"INTERNAL_COORDINATION"}},
 "RUNTIME":{"READ_ONLY":{"READ_ONLY"},"INTERNAL_COORDINATION":{"INTERNAL_COORDINATION"}},
 "CONTROL_PLANE":{"READ_ONLY":{"READ_ONLY"},"TESTING":{"TESTING"},"INTERNAL_COORDINATION":{"INTERNAL_COORDINATION"}},
}
'''

authorize = '''
def authorize(component, operation, risk="REVERSIBLE"):
    component = str(component).strip().upper()
    operation = str(operation).strip().upper()
    risk = str(risk).strip().upper()
    if risk in PROTECTED or operation in PROTECTED:
        audit("AUTHORIZATION_DENIED", component=component, operation=operation, risk=risk)
        return {"approved":False,"reason":"PROTECTED_OPERATION","administrator_required":True}
    permitted = COMPONENT_POLICY.get(component, {}).get(operation, set())
    if risk in permitted:
        audit("AUTO_APPROVED", component=component, operation=operation, risk=risk)
        return {"approved":True,"mode":"AUTOMATIC","reason":"EXPLICIT_COMPONENT_POLICY"}
    audit("AUTHORIZATION_DENIED", component=component, operation=operation, risk=risk)
    return {"approved":False,"reason":"COMPONENT_POLICY_DENIED","administrator_required":False}
'''

permissions = '''
def component_permissions():
    return {
        component: {
            operation: sorted(risks)
            for operation, risks in operations.items()
        }
        for component, operations in COMPONENT_POLICY.items()
    }
'''

lines = src.splitlines(keepends=True)
for name, replacement in (("authorize",authorize.strip()),("component_permissions",permissions.strip())):
    n = nodes[name]
    lines[n.lineno-1:n.end_lineno] = [replacement + "\n"]

updated = "".join(lines)
t = ast.parse(updated)
auth = next(n for n in t.body if isinstance(n,ast.FunctionDef) and n.name=="authorize")
ll = updated.splitlines(keepends=True)
ll.insert(auth.lineno-1, policy)
updated = "".join(ll)
compile(updated, str(p), "exec")

stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
bd = Path(".state/iao-authority/patch-backups") / stamp
bd.mkdir(parents=True, exist_ok=False)
backup = bd / "autonomous_authority.py.original"
backup.write_text(src)

fd, tmp = tempfile.mkstemp(prefix=".authority-", dir=str(p.parent))
try:
    with os.fdopen(fd,"w") as f:
        f.write(updated)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, p.stat().st_mode)
    os.replace(tmp,p)
except Exception:
    try: os.unlink(tmp)
    except OSError: pass
    raise

print("AUTHORITY_INSTALL=PASS")
print("BACKUP=" + str(backup))
print("COMPONENT_POLICY=INSTALLED")
print("SYNTAX=PASS")

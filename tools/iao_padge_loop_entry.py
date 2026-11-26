import os as _os, sys as _sys  # IAO_ROOT_PATH_FIX
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))  # IAO_ROOT_PATH_FIX
import sys
from pathlib import Path as _IAOPath
_IAO_ROOT = str(_IAOPath(__file__).resolve().parent.parent)
if _IAO_ROOT not in sys.path:
    sys.path.insert(0, _IAO_ROOT)
import omega.padge

sys.argv = ["omega.padge", "loop"]
omega.padge.main()

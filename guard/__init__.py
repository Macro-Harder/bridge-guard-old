import importlib.util
import types
from pathlib import Path

_LEGACY_PATH = Path(__file__).resolve().parent.parent / "guard.py"
_spec = importlib.util.spec_from_file_location("_bridge_guard_legacy",
                                               _LEGACY_PATH)
_legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_legacy)

__all__ = []
for _name in dir(_legacy):
    if _name.startswith("_"):
        continue
    _obj = getattr(_legacy, _name)
    if isinstance(_obj, types.ModuleType):
        continue
    if _name.isupper() or getattr(_obj, "__module__", None) == \
            "_bridge_guard_legacy":
        globals()[_name] = _obj
        __all__.append(_name)

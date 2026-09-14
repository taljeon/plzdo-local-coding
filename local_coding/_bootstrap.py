"""Fixed package/flat-helper loading; never an entry-point discovery mechanism."""
from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
import sys
import sysconfig

ENGINE_ROOT = Path(__file__).resolve().parent / "_engine"
_MODULES = frozenset({
    "composition", "state_io", "contracts", "scope_authority", "parent_authority", "ledger", "kernel",
    "engine_types", "json_codec", "provider_common", "ollama_engine", "workflow", "workflow_core",
    "workflow_artifacts", "workflow_validation", "workflow_browser", "workflow_preview", "workflow_metrics",
    "workflow_routing", "host_paths", "run_bounded", "generate_edits", "generate_stream", "generation_health",
    "generation_profile", "local_model", "node_runtime_policy",
})
_DEPENDENCIES = ("attr", "attrs", "rpds", "referencing", "jsonschema_specifications", "jsonschema")
_DEPENDENCY_FILES = ("typing_extensions",) if sys.version_info < (3, 13) else ()


def engine_module(name):
    if name not in _MODULES:
        raise RuntimeError("UNKNOWN_FIXED_RUNTIME_MODULE")
    if ENGINE_ROOT.resolve(strict=True) != ENGINE_ROOT:
        raise RuntimeError("RUNTIME_CODE_ROOT_CHANGED")
    target = ENGINE_ROOT / (name + ".py")
    if target.is_symlink() or not target.is_file():
        raise RuntimeError("RUNTIME_CODE_FILE_UNAVAILABLE")
    # Existing frozen check helpers use flat sibling imports. Only this packaged
    # directory is inserted, never the task tree or all of site-packages.
    # An explicit source PYTHONPATH can already contain this directory behind
    # the caller's cwd. Keep the owned helpers first even in that case.
    sys.path[:] = [str(ENGINE_ROOT)] + [value for value in sys.path if value != str(ENGINE_ROOT)]
    # Flat transitive imports also consult sys.modules. Reject a collision
    # anywhere in the finite helper set before importing or returning a module.
    for fixed_name in _MODULES:
        existing = sys.modules.get(fixed_name)
        if existing is not None:
            origin = vars(existing).get("__file__")
            if not isinstance(origin, str) or Path(origin).resolve() != ENGINE_ROOT / (fixed_name + ".py"):
                raise RuntimeError("RUNTIME_MODULE_COLLISION")
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    module = importlib.import_module(name)
    if Path(module.__file__).resolve() != target:
        raise RuntimeError("RUNTIME_MODULE_IDENTITY_CHANGED")
    return module


def _load_package(name, root):
    if name not in _DEPENDENCIES + _DEPENDENCY_FILES:
        raise RuntimeError("UNKNOWN_DECLARED_DEPENDENCY")
    package = root / name
    is_file = name in _DEPENDENCY_FILES
    target = root / (name + ".py") if is_file else package / "__init__.py"
    if package.is_symlink() or target.is_symlink() or target.resolve(strict=True) != target:
        raise RuntimeError("DEPENDENCY_PATH_CHANGED")
    existing = sys.modules.get(name)
    if existing is not None:
        if Path(getattr(existing, "__file__", "")).resolve() != target:
            raise RuntimeError("DEPENDENCY_MODULE_COLLISION")
        return
    spec = importlib.util.spec_from_file_location(name, target,
        submodule_search_locations=None if is_file else [str(package)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise


def bootstrap_dependencies(package_parent=None):
    """Load only the declared jsonschema closure from the selected prefix.

    The installed launcher supplies its package parent. Source tooling may use
    the interpreter's own dependency prefix. No path becomes a sys.path entry;
    .pth/sitecustomize are never evaluated here. Installation integrity and the
    execution-policy fingerprint remain separate required checks.
    """
    roots = ([Path(package_parent).resolve(strict=True)] if package_parent is not None
             else [Path(sysconfig.get_path("purelib")).resolve(strict=False)])
    root = next((value for value in roots if all((value / name / "__init__.py").is_file()
                                                for name in _DEPENDENCIES)
                 and all((value / (name + ".py")).is_file() for name in _DEPENDENCY_FILES)), None)
    if root is None:
        raise RuntimeError("DECLARED_JSONSCHEMA_DEPENDENCIES_MISSING")
    for name in _DEPENDENCY_FILES + _DEPENDENCIES:
        _load_package(name, root)
    return root


def dependency_roots():
    # A single-file dependency grants that file only, never its site-packages parent.
    return tuple(Path(sys.modules[name].__file__).resolve() for name in _DEPENDENCY_FILES
                 if name in sys.modules) + tuple(Path(sys.modules[name].__file__).resolve().parent
                 for name in _DEPENDENCIES if name in sys.modules)

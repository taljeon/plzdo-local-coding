"""Fixed-prefix source/installed launcher. This file is not a plugin selector."""
import sys

if sys.version_info < (3, 11) or not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
    raise SystemExit('plzdo-local-code: use the isolated Python 3.11+ launcher')

import importlib
import importlib.util
from pathlib import Path
import sysconfig


def _roots(prefix):
    values = {prefix}
    variables = {'base': str(prefix), 'platbase': str(prefix), 'userbase': str(prefix)}
    for scheme in ('posix_prefix', 'posix_user', 'osx_framework_user'):
        if scheme in sysconfig.get_scheme_names():
            values.add(Path(sysconfig.get_path('purelib', scheme=scheme, vars=variables)))
    return tuple(sorted(values))


def _package(name, roots, prefix):
    matches = []
    for root in roots:
        package = root / name
        if package.exists() or package.is_symlink():
            if (not package.is_relative_to(prefix) or package.resolve(strict=True) != package
                    or not package.is_dir() or not (package / '__init__.py').is_file()
                    or (package / '__init__.py').is_symlink()):
                raise RuntimeError('PACKAGE_PREFIX_IDENTITY_INVALID')
            matches.append(package)
    if len(matches) != 1:
        raise RuntimeError('EXACTLY_ONE_FIXED_PACKAGE_REQUIRED:' + name)
    return matches[0]


def _load(name, package):
    if name in sys.modules:
        raise RuntimeError('PACKAGE_MODULE_COLLISION:' + name)
    spec = importlib.util.spec_from_file_location(name, package / '__init__.py',
                                                 submodule_search_locations=[str(package)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    if module.__version__ != '0.3.0':
        raise RuntimeError('PACKAGE_VERSION_MISMATCH:' + name)
    return module


def _command(args):
    index = 0
    while index < len(args):
        value = args[index]
        if value == '--state-root':
            index += 2
            continue
        if value == '--json' or value.startswith('--state-root='):
            index += 1
            continue
        return value if not value.startswith('-') else None
    return None


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    prefix = Path(__file__).resolve(strict=True).parent.parent
    runtime = _package('local_coding', _roots(prefix), prefix)
    metadata = prefix / 'pyproject.toml'
    source = (runtime.parent == prefix and prefix.name == 'plzdo-local-coding'
              and (metadata.exists() or metadata.is_symlink()))
    if source and (not metadata.is_file() or metadata.is_symlink()):
        raise RuntimeError('SOURCE_LAYOUT_IDENTITY_INVALID')
    core_prefix = prefix.parent / 'plzdo' if source else prefix
    core_roots = (core_prefix,) if source else _roots(prefix)
    _load('plzdo_local', _package('plzdo_local', core_roots, core_prefix))
    _load('plzdo_local_code_adapter', _package('plzdo_local_code_adapter', core_roots, core_prefix))
    _load('local_coding', runtime)
    # Help/version need no validator dependency. Operational commands require
    # the declared closure in the same fixed installation prefix, never the
    # operator's arbitrary system/user site startup or environment paths.
    if _command(args) != 'doctor' and not any(value in {'-h', '--help', '--version'} for value in args):
        bootstrap = importlib.import_module('local_coding._bootstrap')
        bootstrap.bootstrap_dependencies(runtime.parent)
    return importlib.import_module('local_coding.cli').main(args)


if __name__ == '__main__':
    raise SystemExit(main())

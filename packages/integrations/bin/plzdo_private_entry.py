"""Fixed private entry; Python site startup never precedes this boundary."""
import sys

if sys.version_info < (3, 11) or not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
    raise SystemExit('plzdo-private: use the launcher with Python -I -S -B')

import importlib
import importlib.util
from pathlib import Path
import sysconfig


def load_private():
    prefix = Path(__file__).resolve().parent.parent
    roots = {prefix}
    variables = {'base': str(prefix), 'platbase': str(prefix), 'userbase': str(prefix)}
    for scheme in ('posix_prefix', 'posix_user', 'osx_framework_user'):
        if scheme in sysconfig.get_scheme_names():
            roots.add(Path(sysconfig.get_path('purelib', scheme=scheme, vars=variables)))
    packages = [root / 'plzdo_private_overlay' for root in roots
                if (root / 'plzdo_private_overlay').exists()]
    if len(packages) != 1:
        raise ValueError('Exactly one private package below the launcher prefix is required')
    package = packages[0]
    if (package.resolve(strict=True) != package or not (package / '__init__.py').is_file()
            or (package / '__init__.py').is_symlink()):
        raise ValueError('Unsafe private package path')
    spec = importlib.util.spec_from_file_location('plzdo_private_overlay', package / '__init__.py',
                                                 submodule_search_locations=[str(package)])
    module = importlib.util.module_from_spec(spec)
    sys.modules['plzdo_private_overlay'] = module
    spec.loader.exec_module(module)
    return prefix


if __name__ == '__main__':
    prefix = load_private()
    raise SystemExit(importlib.import_module('plzdo_private_overlay.cli').main(install_prefix=prefix))

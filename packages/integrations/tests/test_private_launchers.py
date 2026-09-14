"""Private source identity binds actual fixed launchers across installation layouts."""
from pathlib import Path
import hashlib
import shutil

import pytest

from local_coding.api import canonical_bytes
from plzdo_private_overlay import engines, transports


def copy_layout(package, launcher):
    original = Path(engines.__file__).resolve().parent
    original_launchers = engines._launcher_directory()
    package.mkdir(parents=True)
    launcher.mkdir(parents=True)
    for name in engines.SOURCE_FILES:
        shutil.copyfile(original / name, package / name)
    for name in engines.LAUNCHER_FILES:
        shutil.copyfile(original_launchers / name, launcher / name)
        (launcher / name).chmod(0o700)


def test_source_and_installed_launcher_hashes_share_logical_identity(tmp_path, monkeypatch):
    source_package = tmp_path / 'source' / 'plzdo_private_overlay'
    source_bin = source_package.parent / 'bin'
    installed_package = tmp_path / 'installed' / 'lib' / 'python3.12' / 'site-packages' / 'plzdo_private_overlay'
    installed_bin = tmp_path / 'installed' / 'bin'
    copy_layout(source_package, source_bin)
    copy_layout(installed_package, installed_bin)
    original = engines.source_sha256()
    monkeypatch.setattr(engines, '__file__', str(source_package / 'engines.py'))
    assert engines._launcher_directory() == source_bin
    assert engines.source_sha256() == original
    monkeypatch.setattr(engines, '__file__', str(installed_package / 'engines.py'))
    assert engines._launcher_directory() == installed_bin
    assert engines.source_sha256() == original
    binary = tmp_path / 'fixture-provider'
    binary.write_bytes(b'fixture executable; never launch\n')
    binary.chmod(0o700)
    selected = engines.ExternalEngine('codex-openai', canonical_bytes({
        'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}))
    identity = selected.identity()
    path = installed_bin / 'plzdo-private'
    path.write_bytes(path.read_bytes() + b'\n# changed fixture launcher\n')
    assert engines.source_sha256() != original
    assert selected.identity() != identity


def test_private_launcher_ambiguity_and_links_refuse(tmp_path, monkeypatch):
    package = tmp_path / 'prefix' / 'lib' / 'python3.12' / 'site-packages' / 'plzdo_private_overlay'
    launcher = tmp_path / 'prefix' / 'bin'
    copy_layout(package, launcher)
    monkeypatch.setattr(engines, '__file__', str(package / 'engines.py'))
    alternate = package.parent / 'bin'
    alternate.mkdir()
    for name in engines.LAUNCHER_FILES:
        shutil.copyfile(launcher / name, alternate / name)
    with pytest.raises(ValueError, match='Exactly one fixed private launcher'):
        engines.source_sha256()
    for path in alternate.iterdir():
        path.unlink()
    alternate.rmdir()
    original = launcher / 'plzdo_private_entry.py'
    saved = launcher / 'saved-entry.py'
    original.rename(saved)
    original.symlink_to(saved)
    with pytest.raises(transports.ProviderError, match='Symlinked provider evidence'):
        engines.source_sha256()

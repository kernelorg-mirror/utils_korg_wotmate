# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 by The Linux Foundation and contributors
"""Shared fixtures, and isolation from the developer's environment.

Read this before you add tests. The isolation does real work:

* GNUPGHOME points to an empty temporary directory for every test, and
  wotmate.GNUPGHOME is reset. A gpg call that forgets --gnupghome reads an
  empty keyring, not the developer's real keyring. Code that runs against a
  real keyring could also change it.
* wotmate caches database lookups in module globals, for the life of the
  process. Each test gets fresh, empty caches, so results from one test's
  database can't leak into the next test.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

import wotmate

from support import GPGBIN, Keyring


def pytest_report_header() -> str:
    """Show the gpg version, since the --with-colons output differs between versions."""
    res = subprocess.run([GPGBIN, '--version'], capture_output=True, text=True, check=False)
    version = res.stdout.splitlines()[0] if res.stdout else 'gpg NOT FOUND'
    return f'wotmate tests using: {version}'


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests away from the developer's keyring, and from each other."""
    decoy = tmp_path / 'decoy-gnupghome'
    decoy.mkdir(mode=0o700)
    monkeypatch.setenv('GNUPGHOME', str(decoy))
    monkeypatch.setattr(wotmate, 'GNUPGHOME', None)
    monkeypatch.setattr(wotmate, 'GPGBIN', GPGBIN)
    for cache in ('_all_signed_by_cache', '_all_sigs_cache', '_all_pub_uiddata_cache'):
        monkeypatch.setattr(wotmate, cache, {})


@pytest.fixture
def keyring(tmp_path: Path) -> Iterator[Keyring]:
    """An empty keyring of our own, separate from the decoy GNUPGHOME."""
    kr = Keyring(tmp_path / 'gnupg')
    yield kr
    kr.close()

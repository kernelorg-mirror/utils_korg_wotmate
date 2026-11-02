# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 by The Linux Foundation and contributors
"""The b4 keyring that export-keyring.py writes with --gen-b4-keyring.

The keyring maps addresses to key files with symlinks. b4 trusts any
signature from an address that has a link, so a link must disappear as
soon as its address is no longer a valid UID on the key.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import wotmate

from support import GPGBIN, REPO, Keyring


@pytest.mark.parametrize(
    'addr, relpath',
    [
        ('uwe@kleine-koenig.org', 'kleine-koenig.org/uwe/default'),
        ('uwe@kleine-könig.de', 'kleine-k%C3%B6nig.de/uwe/default'),
        ('a+b@example.org', 'example.org/a%2Bb/default'),
    ],
)
def test_b4_link_path(tmp_path: Path, addr: str, relpath: str) -> None:
    # b4 looks links up with the same quoting, so it must not change
    assert wotmate.b4_link_path(str(tmp_path), addr) == str(tmp_path / relpath)


# export-keyring.py lints every new key with sq, even with --ignore-linter
@pytest.mark.skipif(shutil.which('sq') is None, reason='sq is not installed')
def test_export_keyring(keyring: Keyring, tmp_path: Path) -> None:
    me = keyring.add_key('Me <me@example.org>', trust='u')
    bob = keyring.add_key('Bob <bob@example.org>')
    # Non-ASCII must survive, or the link lands in a mangled directory
    keyring.add_uid(bob, 'Bob <bob@exämple.de>')
    keyring.add_uid(bob, 'Bob <bob@example.net>')
    # b4 can't look up a UID without an address, so it gets no link
    keyring.add_uid(bob, 'Just Bob')
    keyring.sign(me, bob)
    outdir = tmp_path / 'export'
    links = outdir / '.keyring' / 'openpgp'
    bobkey = outdir / 'keys' / f'{bob.keyid}.asc'

    def export() -> None:
        keyring.make_db()
        cmd = [
            sys.executable,
            str(REPO / 'export-keyring.py'),
            '--quiet',
            '--gen-b4-keyring',
            '--gpgbin',
            GPGBIN,
            '--gnupghome',
            str(keyring.homedir),
            '--dbfile',
            str(keyring.dbfile),
            '--outdir',
            str(outdir),
        ]
        subprocess.run(cmd, check=True)

    def linked() -> dict[str, Path]:
        return {str(p.relative_to(links)): p.resolve() for p in links.rglob('default')}

    export()
    assert linked() == {
        'example.org/me/default': outdir / 'keys' / f'{me.keyid}.asc',
        'example.org/bob/default': bobkey,
        'ex%C3%A4mple.de/bob/default': bobkey,
        'example.net/bob/default': bobkey,
    }

    keyring.revoke_uid(bob, 'Bob <bob@example.net>')
    export()
    assert 'example.net/bob/default' not in linked()
    assert 'example.org/bob/default' in linked()
    # Empty directories would be committed as noise, or not at all by git
    assert not (links / 'example.net').exists()


def make_link(keyring: Path, addr: str, target: Path) -> str:
    spath = wotmate.b4_link_path(str(keyring), addr)
    os.makedirs(os.path.dirname(spath))
    os.symlink(os.path.relpath(target, os.path.dirname(spath)), spath)
    return spath


def test_prune_b4_keyring(tmp_path: Path) -> None:
    # Cases that a single export run can't produce, so the links are made by hand
    keys = tmp_path / 'keys'
    (keys / 'expired').mkdir(parents=True)
    for kf in ('AAAA.asc', 'BBBB.asc', 'expired/EEEE.asc'):
        (keys / kf).touch()
    keyring = tmp_path / '.keyring' / 'openpgp'
    valid = make_link(keyring, 'uwe@kleine-koenig.org', keys / 'AAAA.asc')
    # Left behind by an older export that dropped non-ASCII characters.
    # The key itself did not change, so it was not exported again.
    mangled = make_link(keyring, 'uwe@kleine-knig.de', keys / 'AAAA.asc')
    # Not exported this run (no longer in the WoT database), so we have no
    # UID list to judge it by
    unknown = make_link(keyring, 'someone@example.com', keys / 'BBBB.asc')
    # Expired keys are moved by the pgpkeys scripts, which keep their links
    expired = make_link(keyring, 'gone@example.net', keys / 'expired' / 'EEEE.asc')

    removed = wotmate.prune_b4_keyring(str(keyring), str(keys), {'AAAA': {'uwe@kleine-koenig.org'}})

    assert removed == [mangled]
    for spath in (valid, unknown, expired):
        assert os.path.islink(spath)
    assert not (keyring / 'kleine-knig.de').exists()


def test_prune_b4_keyring_missing(tmp_path: Path) -> None:
    # Running without --gen-b4-keyring before leaves no keyring at all
    assert wotmate.prune_b4_keyring(str(tmp_path / 'nope'), str(tmp_path), {}) == []

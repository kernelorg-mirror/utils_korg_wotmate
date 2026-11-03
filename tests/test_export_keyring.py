# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 by The Linux Foundation and contributors
"""Exporting keys with export-keyring.py."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from support import Keyring


@pytest.mark.parametrize(
    'args, exported, linted',
    [
        ([], False, True),
        # --ignore-linter must work where sq is missing or broken
        (['--ignore-linter'], True, False),
    ],
)
def test_linter(keyring: Keyring, tmp_path: Path, args: list[str], exported: bool, linted: bool) -> None:
    # A fake sq that rejects every key, so the test does not depend on what
    # the real sq thinks of a test key, or on sq being installed at all
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    marker = tmp_path / 'sq-was-run'
    sq = bindir / 'sq'
    sq.write_text(f'#!/bin/sh\ntouch {marker}\nexit 1\n')
    sq.chmod(0o755)
    env = {**os.environ, 'PATH': f'{bindir}{os.pathsep}{os.environ["PATH"]}'}

    me = keyring.add_key('Me <me@example.org>', trust='u')
    keyring.make_db()
    outdir = tmp_path / 'export'
    keyring.export_keyring(outdir, *args, env=env)

    assert (outdir / 'keys' / f'{me.keyid}.asc').exists() == exported
    assert marker.exists() == linted

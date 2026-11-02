# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 by The Linux Foundation and contributors
"""Reading gpg's --with-colons output, which every tool depends on."""

from __future__ import annotations

import pytest

import wotmate

from support import Keyring


@pytest.mark.parametrize(
    'matchonly, records',
    [
        # What make-sqlitedb.py asks for
        ((b'pub:', b'uid'), ['pub', 'uid']),
        # Overlapping prefixes must still give each line only once, or the
        # same key or UID gets loaded twice
        ((b'pub', b'pub:'), ['pub']),
        ((b'uid', b'u', b'uid:'), ['uid']),
        # No filter returns every record
        ((), ['tru', 'pub', 'fpr', 'uid']),
    ],
)
def test_gpg_get_lines(
    keyring: Keyring, monkeypatch: pytest.MonkeyPatch, matchonly: tuple[bytes, ...], records: list[str]
) -> None:
    keyring.add_key('Me <me@example.org>', trust='u')
    monkeypatch.setattr(wotmate, 'GNUPGHOME', str(keyring.homedir))

    lines = wotmate.gpg_get_lines(['--list-public-keys'], matchonly)
    assert [line.split(b':')[0].decode() for line in lines] == records

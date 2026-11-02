# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 by The Linux Foundation and contributors
"""Building the signature database from gpg's output."""

from __future__ import annotations

import shlex
from pathlib import Path

from support import GPGBIN, Keyring, pubrow


def test_uid_added_between_passes(keyring: Keyring, tmp_path: Path) -> None:
    # make-sqlitedb.py reads the keyring twice: once for keys and UIDs, then
    # once for signatures. If a key refresh adds a UID in between, the second
    # pass sees a UID that is not in the db. It must skip that UID's
    # signatures, not crash, and not credit them to some other UID.
    me = keyring.add_key('Me <me@example.org>', trust='u')
    carol = keyring.add_key('Carol <carol@example.org>', trust='f')
    bob = keyring.add_key('Bob <bob@example.org>')
    keyring.sign(me, carol)
    keyring.sign(me, bob)

    newuid = 'Bob New <new@example.org>'
    gpg = f'{shlex.quote(GPGBIN)} --batch --pinentry-mode loopback --passphrase ""'
    wrapper = tmp_path / 'gpg-wrapper'
    wrapper.write_text(
        '#!/bin/sh\n'
        'case " $* " in *" --list-sigs "*)\n'
        f'    {gpg} --quick-add-uid {bob.fpr} {shlex.quote(newuid)} >/dev/null 2>&1 || exit 99\n'
        f'    {gpg} -u {carol.fpr} --quick-sign-key {bob.fpr} {shlex.quote(newuid)} >/dev/null 2>&1 || exit 99\n'
        'esac\n'
        f'exec {shlex.quote(GPGBIN)} "$@"\n'
    )
    wrapper.chmod(0o755)

    c = keyring.make_db('--gpgbin', str(wrapper))

    c.execute(
        """SELECT uid.uiddata, sig.pubrowid
             FROM sig JOIN uid ON sig.uidrowid = uid.rowid
            WHERE uid.pubrowid = ?""",
        (pubrow(c, bob),),
    )
    assert c.fetchall() == [('Bob <bob@example.org>', pubrow(c, me))]

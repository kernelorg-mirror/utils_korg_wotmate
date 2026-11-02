# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 by The Linux Foundation and contributors
"""End-to-end check of the pipeline that every wotmate tool depends on.

Every tool reads the db that make-sqlitedb.py builds from gpg's output. If
that step is wrong, everything after it is wrong too. This test drives the
real script against a real keyring, then searches the result for paths.
"""

from __future__ import annotations

import wotmate

from support import Keyring, pubrow


def test_trust_chain(keyring: Keyring) -> None:
    # me -> alice -> bob, with an unrelated key that must stay out of paths
    me = keyring.add_key('Me <me@example.org>', trust='u')
    alice = keyring.add_key('Alice <alice@example.org>', trust='f')
    bob = keyring.add_key('Bob <bob@example.org>')
    keyring.add_key('Stranger <stranger@example.net>')
    keyring.sign(me, alice)
    keyring.sign(alice, bob)

    c = keyring.make_db()

    # With no --fromkey, the tools start from the ultimate-trust key
    assert wotmate.get_u_key(c) == pubrow(c, me)
    paths = wotmate.get_key_paths(c, pubrow(c, me), pubrow(c, bob))
    assert paths == [[pubrow(c, me), pubrow(c, alice), pubrow(c, bob)]]

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 by The Linux Foundation and contributors
"""The graphs are what people actually look at, so check their structure.

These tests check the graph objects, not rendered images. A rendering
depends on the graphviz version, but the nodes and edges depend only on us.
"""

from __future__ import annotations

import pytest

import wotmate

from support import Keyring, pubrow


@pytest.mark.parametrize(
    'show_trust, label',
    [
        (False, '{Bob Dobbs\nexample.org|{EdDSA 255|%s}}'),
        (True, '{{Bob Dobbs\nexample.org|{val: f|tru: q}}|{EdDSA 255|%s}}'),
    ],
)
def test_node_label(keyring: Keyring, show_trust: bool, label: str) -> None:
    # The label shows almost every column of the pub table, so this also
    # catches a query that returns the wrong columns. The UID comment is
    # left out to keep the nodes small.
    me = keyring.add_key('Me <me@example.org>', trust='u')
    bob = keyring.add_key('Bob Dobbs (work) <bob@example.org>')
    keyring.sign(me, bob)
    c = keyring.make_db()

    node = wotmate.make_graph_node(c, pubrow(c, bob), show_trust)
    assert node.get('label') == label % bob.keyid

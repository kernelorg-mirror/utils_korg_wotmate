# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 by The Linux Foundation and contributors
"""The graphs are what people actually look at, so check their structure.

These tests check the graph objects, not rendered images. A rendering
depends on the graphviz version, but the nodes and edges depend only on us.
"""

from __future__ import annotations

import pydotplus.graphviz as pd
import pytest

import wotmate

from support import Keyring, pubrow


def test_draw_key_paths(keyring: Keyring) -> None:
    # Two paths that share their middle key, which must be drawn only once
    me = keyring.add_key('Me <me@example.org>', trust='u')
    alice = keyring.add_key('Alice <alice@example.org>', trust='f')
    bob = keyring.add_key('Bob <bob@example.org>')
    carol = keyring.add_key('Carol <carol@example.org>')
    keyring.sign(me, alice)
    keyring.sign(alice, bob)
    keyring.sign(alice, carol)
    c = keyring.make_db()
    m, a, b, cr = (f'a_{pubrow(c, k)}' for k in (me, alice, bob, carol))

    graph = pd.Dot(graph_type='digraph')
    paths = [[pubrow(c, k) for k in path] for path in ([me, alice, bob], [me, alice, carol])]
    wotmate.draw_key_paths(c, paths, graph, show_trust=False)

    edges = {(e.get_source(), e.get_destination()) for e in graph.get_edges()}
    assert edges == {(m, a), (a, b), (a, cr)}
    # The start of each path is pinned to the top in its own cluster
    (toplevel,) = graph.get_subgraphs()
    assert [n.get_name() for n in toplevel.get_nodes()] == [m]
    # Each node links to that key's own graph, which export-keyring writes
    assert graph.get_node(b)[0].get('URL') == f'{bob.keyid}.svg'


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

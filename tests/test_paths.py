# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 by The Linux Foundation and contributors
"""Trust path searches, run on real keyrings."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import wotmate

from support import REPO, Key, Keyring, pubrow


@pytest.fixture
def full_trust_web(keyring: Keyring) -> dict[str, Key]:
    #   me(u) -> fred(f) -> target
    #   me(u) -> alice -> bob -> target
    #   dave(f), with no path to target
    keys = {
        'me': keyring.add_key('Me <me@example.org>', trust='u'),
        'fred': keyring.add_key('Fred <fred@example.org>', trust='f'),
        'alice': keyring.add_key('Alice <alice@example.org>'),
        'bob': keyring.add_key('Bob <bob@example.org>'),
        'dave': keyring.add_key('Dave <dave@example.org>', trust='f'),
        'target': keyring.add_key('Target <target@example.org>'),
    }
    for signer, signee in [('me', 'fred'), ('fred', 'target'), ('me', 'alice'), ('alice', 'bob'), ('bob', 'target')]:
        keyring.sign(keys[signer], keys[signee])
    return keys


def test_get_full_trust_paths(keyring: Keyring, full_trust_web: dict[str, Key]) -> None:
    # One shortest path from each fully-trusted key. A path must not pass
    # through another fully-trusted key: that key draws its own, shorter
    # path, so me must go through alice and bob, not through fred. Dave
    # has no path, so he adds nothing.
    c = keyring.make_db()
    row = {name: pubrow(c, key) for name, key in full_trust_web.items()}

    assert wotmate.get_full_trust_paths(c, row['target'], maxdepth=4) == [
        [row['me'], row['alice'], row['bob'], row['target']],
        [row['fred'], row['target']],
    ]
    # Too shallow for me's detour, so only fred's path is left
    assert wotmate.get_full_trust_paths(c, row['target'], maxdepth=2) == [[row['fred'], row['target']]]


@pytest.mark.parametrize(
    'script, edges',
    [
        # From the ultimate-trust key, through fred and then around him
        ('graph-paths.py', [('me', 'fred'), ('fred', 'target'), ('me', 'alice'), ('alice', 'bob'), ('bob', 'target')]),
        ('graph-to-full.py', [('me', 'alice'), ('alice', 'bob'), ('bob', 'target'), ('fred', 'target')]),
    ],
)
def test_graph_scripts(
    keyring: Keyring, full_trust_web: dict[str, Key], tmp_path: Path, script: str, edges: list[tuple[str, str]]
) -> None:
    # Run each script the way a user does and read the graph it writes
    c = keyring.make_db()
    node = {name: f'a_{pubrow(c, key)}' for name, key in full_trust_web.items()}
    # graphviz's plain format has one stable 'edge <tail> <head> ...' line per edge
    out = tmp_path / 'graph.plain'

    subprocess.run(
        [sys.executable, str(REPO / script), '--quiet', '--dbfile', str(keyring.dbfile), '--out', str(out), 'target'],
        check=True,
    )

    drawn = sorted(tuple(line.split()[1:3]) for line in out.read_text().splitlines() if line.startswith('edge '))
    assert drawn == sorted((node[src], node[dst]) for src, dst in edges)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2018-2024 by The Linux Foundation and contributors
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import sqlite3
import sys

import pydotplus.graphviz as pd

import wotmate

if __name__ == '__main__':
    import argparse

    ap = argparse.ArgumentParser(
        description='Make a graph from any key to fully trusted keys',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ap.add_argument('--quiet', action='store_true', default=False, help='Be quiet and only output errors')
    ap.add_argument('--maxdepth', default=4, type=int, help='Try up to this maximum depth')
    ap.add_argument('--font', default='droid sans,dejavu sans,helvetica', help='Font to use in the graph')
    ap.add_argument('--fontsize', default='11', help='Font size to use in the graph')
    ap.add_argument('--dbfile', default='siginfo.db', help='Sig database to use')
    ap.add_argument(
        '--out', default='graph.png', help='Write graph into this file, guessing the output format by extension'
    )
    ap.add_argument(
        '--show-trust', action='store_true', dest='show_trust', default=False, help='Display validity and trust values'
    )
    ap.add_argument('key_id', nargs=1, default=False, help='Bottom key ID for path tracing')

    cmdargs = ap.parse_args()

    logger = wotmate.get_logger(cmdargs.quiet)

    dbconn = sqlite3.connect(cmdargs.dbfile)
    cursor = dbconn.cursor()

    if len(cmdargs.key_id) != 1:
        logger.critical('Please provide a single key id for path tracing')
        sys.exit(1)

    to_rowid = wotmate.get_pubrow_id(cursor, cmdargs.key_id[0])
    if to_rowid is None:
        sys.exit(1)

    if not wotmate.get_all_full_trust(cursor):
        logger.critical('No fully trusted keys found in the db')
        sys.exit(1)

    key_paths = wotmate.get_full_trust_paths(cursor, to_rowid, cmdargs.maxdepth)
    if not key_paths:
        logger.critical('No paths found to any fully trusted keys')
        sys.exit(1)

    graph = pd.Dot(
        graph_type='digraph',
    )
    graph.set_node_defaults(
        fontname=cmdargs.font,
        fontsize=cmdargs.fontsize,
    )

    wotmate.draw_key_paths(cursor, key_paths, graph, cmdargs.show_trust)

    chunks = cmdargs.out.split('.')
    outformat = chunks[-1]
    graph.write(cmdargs.out, format=outformat)
    logger.info('Wrote %s', cmdargs.out)

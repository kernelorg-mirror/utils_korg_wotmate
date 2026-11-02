# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2018-2024 by The Linux Foundation and contributors
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import itertools
import logging
import sqlite3
import subprocess
import sys
from datetime import datetime
from typing import Collection, Dict, List, Optional, Sequence, Set, Tuple

import pydotplus.graphviz as pd

ALGOS: Dict[int, str] = {
    1: 'RSA',
    17: 'DSA',
    18: 'ECDH',
    19: 'ECDSA',
    22: 'EdDSA',
}

DB_VERSION = 1
GPGBIN = '/usr/bin/gpg'
GNUPGHOME = None

logger = logging.getLogger(__name__)

# convenience caching to avoid redundant look-ups
_all_signed_by_cache: Dict[int, List[int]] = dict()
_all_pub_uiddata_cache: Dict[int, Tuple[str, str]] = dict()


def get_pub_uid_by_pubrow(c: sqlite3.Cursor, p_rowid: int) -> Tuple[str, str]:
    if p_rowid not in _all_pub_uiddata_cache:
        c.execute(
            'SELECT pub.keyid, uid.uiddata FROM uid JOIN pub ON uid.pubrowid = pub.rowid WHERE pubrowid=?', (p_rowid,)
        )
        _all_pub_uiddata_cache[p_rowid] = c.fetchone()
    return _all_pub_uiddata_cache[p_rowid]


def get_uiddata_by_pubrow(c: sqlite3.Cursor, p_rowid: int):
    return get_pub_uid_by_pubrow(c, p_rowid)[1]


def get_logger(quiet: bool = False, verbose: bool = False) -> logging.Logger:
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    if quiet:
        ch.setLevel(logging.CRITICAL)
    elif not verbose:
        ch.setLevel(logging.INFO)

    logger.addHandler(ch)
    return logger


def gpg_run_command(args: List[str], with_colons: bool = True, stdin: Optional[bytes] = None) -> bytes:
    cmdargs = [GPGBIN, '--batch', '--display-charset', 'utf-8']
    if with_colons:
        cmdargs += ['--with-colons']

    cmdargs += args
    env = None
    if GNUPGHOME is not None:
        env = {'GNUPGHOME': GNUPGHOME}

    logger.debug('Running %s...' % ' '.join(cmdargs))

    sp = subprocess.Popen(cmdargs, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    (output, error) = sp.communicate(input=stdin)
    output = output.strip()

    if len(error.strip()):
        sys.stderr.buffer.write(error)

    return output


def lint(keydata: bytes) -> bool:
    sp = subprocess.Popen(
        ['sq', 'cert', '-q', 'lint'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=None
    )
    sp.communicate(input=keydata)

    return sp.returncode == 0


def gpg_get_lines(args: List[str], matchonly: Sequence[bytes] = ()) -> List[bytes]:
    output = gpg_run_command(args)
    lines: List[bytes] = list()
    logger.debug('Processing the output...')
    for line in output.split(b'\n'):
        if not len(line.strip()) or line.startswith(b'#'):
            continue
        if not matchonly or line.startswith(tuple(matchonly)):
            lines.append(line)

    return lines


def gpg_get_fields(bline: bytes) -> List[str]:
    line = bline.decode('utf8', 'ignore')
    # gpg uses \x3a to indicate an encoded colon, so explode and de-encode
    fields = [rawchunk.replace('\\x3a', ':') for rawchunk in line.split(':')]
    # fields 5 and 6 are timestamps, so convert them to isoformat for sqlite3 needs
    if len(fields[5]):
        fields[5] = datetime.fromtimestamp(int(fields[5])).isoformat()
    if len(fields[6]):
        fields[6] = datetime.fromtimestamp(int(fields[6])).isoformat()

    return fields


def init_sqlite_db(c: sqlite3.Cursor) -> None:
    # Create primary keys table
    logger.info('Initializing new sqlite3 db with metadata version %s' % DB_VERSION)
    c.execute("""CREATE TABLE metadata (
                  version INTEGER
                 )""")
    c.execute("""INSERT INTO metadata VALUES(?)""", (DB_VERSION,))
    c.execute("""CREATE TABLE pub (
                  keyid TEXT UNIQUE,
                  validity TEXT,
                  size INTEGER,
                  algo INTEGER,
                  created TEXT,
                  expires TEXT,
                  ownertrust TEXT
                 )""")
    c.execute("""CREATE TABLE uid (
                  pubrowid INTEGER,
                  validity TEXT,
                  created TEXT,
                  expires TEXT,
                  uiddata TEXT,
                  is_primary INTEGER,
                  FOREIGN KEY(pubrowid) REFERENCES pub(rowid)
                 )""")
    c.execute("""CREATE TABLE sig (
                  uidrowid INTEGER,
                  pubrowid INTEGER,
                  created TEXT,
                  expires TEXT,
                  sigtype INTEGER,
                  FOREIGN KEY(uidrowid) REFERENCES uid(rowid),
                  FOREIGN KEY(pubrowid) REFERENCES pub(rowid),
                  PRIMARY KEY (uidrowid, pubrowid)
                 ) WITHOUT ROWID""")


def get_all_signed_by(c: sqlite3.Cursor, p_rowid: int) -> List[int]:
    if p_rowid not in _all_signed_by_cache:
        c.execute(
            """SELECT DISTINCT uid.pubrowid
                                FROM uid JOIN sig ON sig.uidrowid = uid.rowid 
                               WHERE sig.pubrowid=?""",
            (p_rowid,),
        )
        _all_signed_by_cache[p_rowid] = [pubrowid for (pubrowid,) in c.fetchall()]

    return _all_signed_by_cache[p_rowid]


def get_all_full_trust(c: sqlite3.Cursor) -> List[int]:
    c.execute("""SELECT pub.rowid
                   FROM pub
                  WHERE ownertrust IN ('u', 'f')
               ORDER BY pub.rowid""")
    return [p_rowid for (p_rowid,) in c.fetchall()]


def make_graph_node(c: sqlite3.Cursor, p_rowid: int, show_trust: bool = False) -> pd.Node:
    c.execute(
        """SELECT pub.keyid, pub.validity, pub.size, pub.algo, pub.ownertrust,
                        uid.uiddata
                   FROM uid JOIN pub
                     ON uid.pubrowid = pub.rowid
                  WHERE pub.rowid=? AND uid.is_primary = 1""",
        (p_rowid,),
    )
    (kid, val, size, algo, trust, uiddata) = c.fetchone()

    nodename = 'a_%s' % p_rowid
    anode = pd.Node(nodename)
    anode.set('shape', 'record')
    anode.set('style', 'rounded')
    if trust == 'u':
        anode.set('color', 'purple')
    elif trust == 'f':
        anode.set('color', 'red')
    elif trust == 'm':
        anode.set('color', 'blue')
    else:
        anode.set('color', 'gray')

    uiddata = uiddata.replace('"', '')
    name = uiddata.split('<')[0].replace('"', '').strip()
    name = name.split('(')[0].strip()

    try:
        email = uiddata.split('<')[1].replace('>', '').strip()
        try:
            domain = email.split('@')[1]
            show = domain
        except IndexError:
            show = email
    except IndexError:
        show = ''

    if algo in ALGOS:
        keyline = '{%s %s|%s}' % (ALGOS[algo], size, kid)
    else:
        keyline = '{%s}' % kid

    if show_trust:
        anode.set('label', '{{%s\n%s|{val: %s|tru: %s}}|%s}' % (name, show, val, trust, keyline))
    else:
        anode.set('label', '{%s\n%s|%s}' % (name, show, keyline))
    anode.set('URL', '%s.svg' % kid)
    return anode


def draw_key_paths(c: sqlite3.Cursor, paths: List[List[int]], graph: pd.Graph, show_trust: bool):
    seenactors: Dict[int, pd.Node] = dict()
    # Paths often share hops, and graphviz draws every edge it is given
    seenedges: Set[Tuple[int, int]] = set()
    # make a subgraph for toplevel nodes
    tl_subgraph = pd.Subgraph('cluster_toplevel')
    tl_subgraph.set('color', 'white')
    for path in paths:
        signer: Optional[int] = None
        for actor in path:
            if actor not in seenactors:
                anode = make_graph_node(c, actor, show_trust)
                seenactors[actor] = anode
                if signer is None:
                    tl_subgraph.add_node(anode)
                else:
                    graph.add_node(anode)

            if signer is not None and (signer, actor) not in seenedges:
                seenedges.add((signer, actor))
                graph.add_edge(pd.Edge(seenactors[signer].get_name(), seenactors[actor].get_name()))

            signer = actor

    graph.add_subgraph(tl_subgraph)


def get_pubrow_id(c: sqlite3.Cursor, whatnot: str) -> Optional[int]:
    # first, attempt to treat it as key id
    try:
        int(whatnot, 16)
        as_keyid = '%%%s' % whatnot[-16:].upper()
        c.execute("""SELECT DISTINCT rowid FROM pub WHERE keyid LIKE ?""", (as_keyid,))
        rows = c.fetchall()
        if len(rows) == 1:
            return rows[0][0]
        elif len(rows) > 1:
            logger.critical('More than one key matched %s, use 16-character keyid' % whatnot)
        else:
            logger.critical('No keyids in the database matching %s' % whatnot)
        return None
    except ValueError:
        # not hexadecimal, so not keyid
        pass

    # attempt to look up in uiddata
    c.execute("""SELECT DISTINCT pubrowid FROM uid WHERE uiddata LIKE ? COLLATE NOCASE""", ('%%%s%%' % whatnot,))
    rows = c.fetchall()
    if len(rows) == 1:
        return rows[0][0]
    elif len(rows) > 1:
        logger.critical('More than one result matching "%s", be more specific' % whatnot)
    else:
        logger.critical('Nothing found matching "%s"' % whatnot)

    return None


def get_key_paths(
    c: sqlite3.Cursor,
    t_p_rowid: int,
    b_p_rowid: int,
    maxdepth: int = 5,
    maxpaths: int = 5,
    avoid: Collection[int] = (),
) -> List[List[int]]:
    # Keys in avoid are never used as hops, only as the start or the end

    def gen_uniq_paths(t_p_rowid: int, b_p_rowid: int, maxdepth: int):
        logger.debug(f'search for {str(b_p_rowid) + " " + get_uiddata_by_pubrow(c, b_p_rowid)}')

        # prioq tracks the pairs (depth, path) that need further inspection
        prioq: List[Tuple[int, List[int]]] = [(0, [t_p_rowid])]

        found: Set[int] = set()
        used_keys: Set[int] = set(avoid) - {b_p_rowid}

        while prioq:
            depth, path = prioq.pop(0)

            if path[-1] in found:
                # We already know a path to `path[-1]` of depth <= `depth`
                continue

            if path[-1] == b_p_rowid:
                logger.debug(f'found: {[str(p) + " " + get_uiddata_by_pubrow(c, p) for p in path]} @{depth=}')
                yield path

                # if we found a path of length 1, this is good enough
                if depth <= 1:
                    return

                new_used_keys = set(path[1:-1])
                used_keys.update(new_used_keys)

                # We might have pruned some paths that are interesting again now that there are new keys in used_keys
                prioq = [(0, [t_p_rowid])]
                found = set()
                continue

            # logger.debug(f'consider: {[str(p) + " " + get_uiddata_by_pubrow(c, p) for p in path]} @{depth=}')

            # We found a shortest path to path[-1], so we don't need to consider further paths leading to it
            found.add(path[-1])

            if depth < maxdepth:
                sigs = set(get_all_signed_by(c, path[-1])) - used_keys - found

                # If the cert to find a path for is reachable from path[-1], the other sigs are not interesting
                if b_p_rowid in sigs:
                    prioq.append((depth + 1, path + [b_p_rowid]))
                else:
                    prioq.extend((depth + 1, path + [s]) for s in sorted(sigs))

    ret = list(itertools.islice(gen_uniq_paths(t_p_rowid, b_p_rowid, maxdepth), maxpaths))
    if not ret:
        logger.info(
            'No valid paths between %s and %s', get_uiddata_by_pubrow(c, t_p_rowid), get_uiddata_by_pubrow(c, b_p_rowid)
        )

    return ret


def get_u_key(c: sqlite3.Cursor) -> Optional[int]:
    c.execute("""SELECT rowid 
                   FROM pub
                  WHERE ownertrust = 'u' 
                  LIMIT 1
    """)
    try:
        (p_rowid,) = c.fetchone()
        return p_rowid
    except (ValueError, TypeError):
        return None


def get_full_trust_paths(c: sqlite3.Cursor, b_p_rowid: int, maxdepth: int = 5) -> List[List[int]]:
    """Find the shortest path from each fully-trusted key to b_p_rowid."""
    full_trust = get_all_full_trust(c)
    paths: List[List[int]] = list()
    for t_p_rowid in full_trust:
        if t_p_rowid == b_p_rowid:
            continue
        # A path through another fully-trusted key adds nothing: that key's
        # own path is shorter and is drawn anyway. Avoiding them sends each
        # path along a different route.
        paths += get_key_paths(c, t_p_rowid, b_p_rowid, maxdepth, maxpaths=1, avoid=full_trust)
    return paths

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2018-2024 by The Linux Foundation and contributors
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import pathlib
import sqlite3
import sys

import pydotplus.graphviz as pd

import wotmate


def get_header(kid):
    args = [
        '--list-options',
        'show-notations',
        '--list-options',
        'no-show-uid-validity',
        '--with-subkey-fingerprints',
        '--list-key',
        kid,
    ]
    header = wotmate.gpg_run_command(args, with_colons=False)
    return header + b'\n\n'


if __name__ == '__main__':
    import argparse

    ap = argparse.ArgumentParser(
        description='Export a keyring as individual .asc files with graphs',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ap.add_argument('--quiet', action='store_true', default=False, help='Be quiet and only output errors')
    ap.add_argument('--verbose', action='store_true', default=False, help='emit extra logging')
    ap.add_argument(
        '--ignore-linter',
        dest='ignore_linter',
        action='store_true',
        default=False,
        help='Also update keys that fail the Sequoia linter check',
    )
    ap.add_argument('--fromkey', help='Top key ID (if omitted, will use the key with ultimate trust)')
    ap.add_argument('--maxdepth', default=4, type=int, help='Try up to this maximum depth')
    ap.add_argument('--maxpaths', default=4, type=int, help='Stop after finding this many paths')
    ap.add_argument('--font', default='droid sans,dejavu sans,helvetica', help='Font to use in the graph')
    ap.add_argument('--fontsize', default='11', help='Font size to use in the graph')
    ap.add_argument('--dbfile', default='siginfo.db', help='Sig database to use')
    ap.add_argument('--gpgbin', default='/usr/bin/gpg', help='Location of the gpg binary to use')
    ap.add_argument('--gnupghome', help='Set this as gnupghome instead of using the default')
    ap.add_argument('--outdir', default='export', help='Export keyring data into this dir as keys/ and graphs/ subdirs')
    ap.add_argument(
        '--show-trust', action='store_true', dest='show_trust', default=False, help='Display validity and trust values'
    )
    ap.add_argument('--graph-out-format', dest='graph_out_format', default='svg', help='Export graphs in this format')
    ap.add_argument(
        '--key-export-options',
        dest='key_export_options',
        default='export-attributes,export-clean',
        help='The value to pass to gpg --export-options',
    )
    ap.add_argument(
        '--use-weak-algos',
        dest='use_weak_algos',
        action='store_true',
        default=False,
        help='Do not discard cross-signatures that use weak algorithms',
    )
    ap.add_argument(
        '--gen-b4-keyring',
        action='store_true',
        dest='gen_b4_keyring',
        default=False,
        help='Generate a b4-style symlinked keyring as well',
    )
    ap.add_argument(
        '--update-header',
        action='store_true',
        dest='update_header',
        default=False,
        help='Update certificate files also on header changes',
    )

    cmdargs = ap.parse_args()

    if cmdargs.gnupghome:
        wotmate.GNUPGHOME = cmdargs.gnupghome
    if cmdargs.gpgbin:
        wotmate.GPGBIN = cmdargs.gpgbin

    logger = wotmate.get_logger(cmdargs.quiet, cmdargs.verbose)

    dbconn = sqlite3.connect(cmdargs.dbfile)
    c = dbconn.cursor()

    if not cmdargs.fromkey:
        from_rowid = wotmate.get_u_key(c)
        if from_rowid is None:
            logger.critical('Could not find ultimate-trust key, try specifying --fromkey')
            sys.exit(1)
    else:
        from_rowid = wotmate.get_pubrow_id(c, cmdargs.fromkey)
        if from_rowid is None:
            sys.exit(1)

    # Iterate through all keys
    c.execute("""SELECT pub.rowid,
                        pub.keyid,
                        uid.uiddata
                   FROM uid JOIN pub
                     ON uid.pubrowid = pub.rowid
                  WHERE uid.is_primary = 1""")

    if not os.path.isdir(cmdargs.outdir):
        os.mkdir(cmdargs.outdir)
    keydir = os.path.join(cmdargs.outdir, 'keys')
    if not os.path.isdir(keydir):
        os.mkdir(keydir)
    graphdir = os.path.join(cmdargs.outdir, 'graphs')
    if not os.path.isdir(graphdir):
        os.mkdir(graphdir)

    keyring_dir = os.path.join(cmdargs.outdir, '.keyring', 'openpgp')

    kcount = wcount = 0
    my_symlinks: set[str] = set()
    rows = c.fetchall()
    for to_rowid, kid, uiddata in rows:
        kcount += 1
        # First, export the key
        args: list[str] = ['-a', '--export']
        if cmdargs.use_weak_algos:
            args += ['--allow-weak-digest-algos', '--allow-weak-key-signatures']
        args += ['--export-options', cmdargs.key_export_options, kid]

        keydata = wotmate.gpg_run_command(args, with_colons=False)
        keyout = os.path.join(keydir, f'{kid}.asc')

        # Is there already a key file in place?
        key_changed = False
        if os.path.exists(keyout):
            key_already_exists = True
            # Load it up and see if it's different
            with open(keyout, 'rb') as fin:
                old_keyexport = fin.read()
                if keydata not in old_keyexport:
                    key_changed = True
                    logger.debug('Key changes detected for %s', kid)
                elif cmdargs.update_header:
                    header = get_header(kid)
                    if header not in old_keyexport:
                        key_changed = True
                        logger.debug('Header changes detected for %s', kid)

        else:
            key_already_exists = False
            key_changed = True

        key_paths = wotmate.get_key_paths(c, from_rowid, to_rowid, cmdargs.maxdepth, cmdargs.maxpaths)
        if not len(key_paths):
            if key_already_exists:
                logger.debug('%s has an to invalid WoT, but already exists, so still update it', kid)
            else:
                logger.info('Skipping %s due to invalid WoT', kid)
                continue

        kpblock = ''
        for kp in key_paths:
            for lvl, rowid in enumerate(kp):
                kid, kpuid = wotmate.get_pub_uid_by_pubrow(c, rowid)
                kpblock += f'   {lvl}' if lvl > 0 else 'from'
                kpblock += f'  {kid}  {kpuid}\n'
            kpblock += '\n'
        key_paths_repr = kpblock.encode()

        txtgraphout = os.path.join(graphdir, f'{kid}.txt')
        if not os.path.exists(txtgraphout):
            logger.debug('Forcing generation of the text graph for %s', kid)
            trust_changed = True
        else:
            # Load it up and see if trust relationships changed
            with open(txtgraphout, 'rb') as fin:
                old_key_paths_repr = fin.read()
                trust_changed = key_paths_repr != old_key_paths_repr
                if trust_changed:
                    logger.debug('Trust changes detected for %s', kid)

        logger.debug(
            '%s key_changed=%s trust_changed=%s key_already_exists=%s paths=%s',
            kid,
            key_changed,
            trust_changed,
            key_already_exists,
            len(key_paths),
        )

        if not (key_changed or trust_changed):
            logger.debug('No changes detected for %s', kid)
            continue

        if key_changed:
            header = get_header(kid)
            keyexport = header + keydata + b'\n'

            # Only do this for newly added keys
            if not key_already_exists and not wotmate.lint(keydata):
                if not cmdargs.ignore_linter:
                    logger.info('Skipping %s due to bad linter results', kid)
                    continue
                else:
                    logger.debug('%s: Ignore bad linter results', kid)

            with open(keyout, 'wb') as fout:
                fout.write(keyexport)
                logger.info('Wrote %s', keyout)

            if cmdargs.gen_b4_keyring:
                for addr in wotmate.header_addresses(header):
                    spath = wotmate.b4_link_path(keyring_dir, addr)
                    kpath = os.path.dirname(spath)
                    pathlib.Path(kpath).mkdir(parents=True, exist_ok=True)
                    tpath = os.path.relpath(keyout, kpath)
                    if os.path.islink(spath):
                        if os.readlink(spath) == tpath:
                            continue
                        if spath in my_symlinks:
                            # There's multiple keys with the same identity. First one wins, for the lack of a
                            # better solution that is also sane.
                            logger.info('Notice: multiple keys with the same UID %s', addr)
                            continue
                        os.unlink(spath)
                        logger.info('Notice: fixing symlink for %s', addr)
                    os.symlink(tpath, spath)
                    my_symlinks.add(spath)
                    logger.info('Symlinked %s to %s', kid, spath)

        if trust_changed:
            graph = pd.Dot(
                graph_type='digraph',
            )
            graph.set_node_defaults(
                fontname=cmdargs.font,
                fontsize=cmdargs.fontsize,
            )

            wotmate.draw_key_paths(c, key_paths, graph, cmdargs.show_trust)
            graphout = os.path.join(graphdir, f'{kid}.{cmdargs.graph_out_format}')
            graph.write(graphout, format=cmdargs.graph_out_format)
            logger.info('Wrote %s', graphout)

            logger.debug('Writing out the text graph')
            with open(txtgraphout, 'wb') as fout:
                fout.write(key_paths_repr)
                logger.info('Wrote %s', txtgraphout)

        wcount += 1

    if cmdargs.gen_b4_keyring:
        # Links are only added while exporting a changed key, so the link of
        # a UID that went away would otherwise stay forever. Check every key
        # we just exported, changed or not, against the UIDs in its header.
        wanted: dict[str, set[str]] = {}
        for _, kid, _ in rows:
            keyout = os.path.join(keydir, f'{kid}.asc')
            if not os.path.exists(keyout):
                continue
            with open(keyout, 'rb') as fin:
                # Stop at the armor, whose base64 lines could start with "uid"
                header = fin.read().split(b'-----BEGIN', 1)[0]
            wanted[kid] = set(wotmate.header_addresses(header))
        for spath in wotmate.prune_b4_keyring(keyring_dir, keydir, wanted):
            logger.info('Removed stale symlink %s', spath)
            wcount += 1

    logger.info('Processed %s keys, made %s changes', kcount, wcount)

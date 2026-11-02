# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 by The Linux Foundation and contributors
"""Build small, real GnuPG keyrings for tests.

wotmate's input is whatever gpg prints, so the tests build real keyrings
with real gpg instead of mocking its output. Hand-written --with-colons
fixtures would only show what we believe gpg prints. Ed25519 keys take
milliseconds to make, so this is cheap.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GPGBIN = shutil.which('gpg') or '/usr/bin/gpg'

# --import-ownertrust takes numbers; --with-colons shows these letters.
OWNERTRUST = {'q': 2, 'n': 3, 'm': 4, 'f': 5, 'u': 6}


@dataclass(frozen=True)
class Key:
    uid: str
    fpr: str

    @property
    def keyid(self) -> str:
        """The long key ID, which is what the db stores in pub.keyid."""
        return self.fpr[-16:]


class Keyring:
    """A throwaway GnuPG homedir, with helpers to fill it and turn it into a db."""

    def __init__(self, homedir: Path) -> None:
        self.homedir = homedir
        # gpg refuses to use a homedir that other users can read
        homedir.mkdir(mode=0o700)
        self.dbfile = homedir.parent / 'siginfo.db'

    def gpg(self, *args: str, stdin: bytes | None = None) -> bytes:
        # No passphrases, so nothing ever waits for a pinentry
        cmd = [GPGBIN, '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', *args]
        env = {**os.environ, 'GNUPGHOME': str(self.homedir)}
        res = subprocess.run(cmd, input=stdin, capture_output=True, env=env, check=False)
        if res.returncode != 0:
            msg = f'{" ".join(cmd)} failed:\n{res.stderr.decode(errors="replace")}'
            raise RuntimeError(msg)
        return res.stdout

    def add_key(self, uid: str, trust: str = 'q', algo: str = 'ed25519') -> Key:
        """Make a certify-only key.

        gpg gives every key it generates ultimate ownertrust, which would
        make every key a trust root. So the ownertrust is set right after.
        """
        self.gpg('--quick-gen-key', uid, algo, 'cert', 'never')
        out = self.gpg('--with-colons', '--list-keys', f'={uid}')
        fpr = next(line.split(':')[9] for line in out.decode().splitlines() if line.startswith('fpr:'))
        self.set_trust(Key(uid, fpr), trust)
        return Key(uid, fpr)

    def add_uid(self, key: Key, uid: str) -> None:
        self.gpg('--quick-add-uid', key.fpr, uid)

    def revoke_uid(self, key: Key, uid: str) -> None:
        self.gpg('--quick-revoke-uid', key.fpr, uid)

    def set_trust(self, key: Key, trust: str) -> None:
        self.gpg('--import-ownertrust', stdin=f'{key.fpr}:{OWNERTRUST[trust]}:\n'.encode())

    def revoke_key(self, key: Key) -> None:
        # gpg writes a revocation certificate for every key it makes. It is
        # "defused" with a leading colon so that nobody imports it by accident.
        revcert = (self.homedir / 'openpgp-revocs.d' / f'{key.fpr}.rev').read_text()
        self.gpg('--import', stdin=revcert.replace(':-----BEGIN', '-----BEGIN').encode())

    def sign(self, signer: Key, target: Key) -> None:
        self.gpg('--local-user', signer.fpr, '--quick-sign-key', target.fpr)

    def revoke_sig(self, signer: Key, target: Key) -> None:
        self.gpg('--quick-revoke-sig', target.fpr, signer.fpr)

    def make_db(self, *args: str) -> sqlite3.Cursor:
        """Run make-sqlitedb.py exactly as a user would, and open the result."""
        cmd = [
            sys.executable,
            str(REPO / 'make-sqlitedb.py'),
            '--quiet',
            '--gpgbin',
            GPGBIN,
            '--gnupghome',
            str(self.homedir),
            '--dbfile',
            str(self.dbfile),
            *args,
        ]
        subprocess.run(cmd, check=True)
        return sqlite3.connect(self.dbfile).cursor()

    def close(self) -> None:
        # Each homedir gets its own gpg-agent. Stop it, or every test leaves
        # one running.
        env = {**os.environ, 'GNUPGHOME': str(self.homedir)}
        subprocess.run(['gpgconf', '--kill', 'all'], env=env, check=False, capture_output=True)


def pubrow(c: sqlite3.Cursor, key: Key) -> int:
    """Map a key to the sqlite rowid that the wotmate functions work with."""
    c.execute('SELECT rowid FROM pub WHERE keyid = ?', (key.keyid,))
    row = c.fetchone()
    assert row is not None, f'{key.uid} is not in the db'
    return int(row[0])

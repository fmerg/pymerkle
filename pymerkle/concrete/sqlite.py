import sqlite3
from typing import Any, Generator, Iterator, Optional

from pymerkle.core import BaseMerkleTree


class SqliteTree(BaseMerkleTree):
    """
    Persistent Merkle-tree implementation using a SQLite database as storage.

    Inserted data is expected to be in binary format and hashed without
    further processing.

    .. note:: The database schema consists of a single table called *leaf*
        with two columns: *index*, which is the primary key serving as leaf
        index, and *entry*, which is a blob field storing the appended data.

    :param dbfile: database filepath
    :type dbfile: str
    :param algorithm: [optional] hashing algorithm. Defaults to *sha256*
    :type algorithm: str
    """

    def __init__(self, dbfile: str, algorithm: str = 'sha256', **opts) -> None:
        self.dbfile: str = dbfile
        self.con: sqlite3.Connection = sqlite3.connect(database=self.dbfile)
        self.con.row_factory = lambda cursor, row: row[0]
        self.cur: sqlite3.Cursor = self.con.cursor()

        with self.con:
            query: str = f'''
                CREATE TABLE IF NOT EXISTS leaf(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry BLOB,
                    hash BLOB
                );'''
            self.cur.execute(query)

        super().__init__(algorithm=algorithm, **opts)

    def __enter__(self) -> 'SqliteTree':
        return self

    def __exit__(self, *exc) -> None:
        self.con.close()

    def _encode_entry(self, data: bytes) -> bytes:
        """
        Returns the binary format of the provided data entry.

        :param data: data to encode
        :type data: bytes
        :rtype: bytes
        """
        return data

    def _store_leaf(self, data: bytes, digest: bytes) -> Optional[int]:
        """
        Creates a new leaf storing the provided data along with its
        hash value.

        :param data: data entry
        :type data: whatever expected according to application logic
        :param digest: hashed data
        :type digest: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """
        if not isinstance(data, bytes):
            raise ValueError('Provided data is not binary')

        cur: sqlite3.Cursor = self.cur

        with self.con:
            query = f'''
                INSERT INTO leaf(entry, hash) VALUES (?, ?)
            '''
            cur.execute(query, (data, digest))

        return cur.lastrowid

    def _get_leaf(self, index: int) -> bytes:
        """
        Returns the hash stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        cur: sqlite3.Cursor = self.cur

        query: str = f'''
            SELECT hash FROM leaf WHERE id = ?
        '''
        cur.execute(query, (index,))

        return bytes(cur.fetchone())

    def _get_leaves(self, offset: int, width: int) -> list[bytes]:
        """
        Returns in respective order the hashes stored by the leaves in the
        specified range.

        :param offset: starting position counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        """
        cur: sqlite3.Cursor = self.cur

        query: str = f'''
            SELECT hash FROM leaf WHERE id BETWEEN ? AND ?
        '''
        cur.execute(query, (offset + 1, offset + width))

        return cur.fetchall()

    def _get_size(self) -> int:
        """
        :returns: current number of leaves
        :rtype: int
        """
        cur: sqlite3.Cursor = self.cur

        query: str = f'''
            SELECT COUNT(*) FROM leaf
        '''
        cur.execute(query)

        return cur.fetchone()

    def get_entry(self, index: int) -> bytes:
        """
        Returns the unhashed data stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        cur: sqlite3.Cursor = self.cur

        query: str = f'''
            SELECT entry FROM leaf WHERE id = ?
        '''
        cur.execute(query, (index,))

        return cur.fetchone()

    def _hash_per_chunk(self, entries: list[bytes], chunksize: int) -> Generator[Iterator[tuple[bytes, bytes]], Any, None]:
        """
        Generator yielding in chunks pairs of entry data and hash value.

        :param entries:
        :type entries: iterable of bytes
        :param chunksize:
        :type chunksize: int
        """
        _hash_entry = self.hash_buff

        offset = 0
        chunk: list[bytes] = entries[offset: chunksize]
        while chunk:
            hashes: list[bytes] = [_hash_entry(data=data) for data in chunk]
            yield zip(chunk, hashes)

            offset += chunksize
            chunk = entries[offset: offset + chunksize]

    def append_entries(self, entries: list[bytes], chunksize: int = 100_000) -> int:
        """
        Bulk operation for appending a batch of entries.

        :param entries: data entries to append
        :type entries: iterable of bytes
        :param chunksize: [optional] number entries to insert per
            database transaction.
        :type chunksize: int
        :returns: index of last appended entry
        :rtype: int
        """
        cur: sqlite3.Cursor = self.cur

        with self.con:
            query: str = f'''
                INSERT INTO leaf(entry, hash) VALUES (?, ?)
            '''
            for chunk in self._hash_per_chunk(entries=entries, chunksize=chunksize):
                cur.execute('BEGIN TRANSACTION')

                for (data, digest) in chunk:
                    cur.execute(query, (data, digest))

                cur.execute('END TRANSACTION')

        result = cur.lastrowid
        if result is None:
            raise Exception(
                'Query returned no result. Integrity of the database cannot be guranteed.')
        return result

import sqlite3
from pymerkle.core import BaseMerkleTree


class SqliteTree(BaseMerkleTree):
    """
    Persistent Merkle-tree implementation using a SQLite database as storage

    The database schema consists of a single table called *leaf* with two
    columns: *index*, which is the primary key serving as leaf index, and
    *entry*, which is a blob field storing the appended data. Inserted data are
    expected by the tree to be in binary format and stored without further
    processing

    :param dbfile: database filepath
    :type dbfile: str
    :param algorithm: [optional] hashing algorithm. Defaults to *sha256*
    :type algorithm: str
    """

    def __init__(self, dbfile, algorithm='sha256', **opts):
        self.dbfile = dbfile
        self.con = sqlite3.connect(self.dbfile)
        self.con.row_factory = lambda cursor, row: row[0]
        self.cur = self.con.cursor()

        with self.con:
            query = f'''
                CREATE TABLE IF NOT EXISTS leaf(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry BLOB,
                    hash BLOB
                );'''
            self.cur.execute(query)

        super().__init__(algorithm, **opts)


    def __enter__(self):
        return self


    def __exit__(self, *exc):
        self.con.close()


    def _encode_entry(self, data):
        """
        Returns the binary format of the provided data entry.

        :param data: data to encode
        :type data: bytes
        :rtype: bytes
        """
        return data


    def _store_leaf(self, data, digest):
        """
        Creates a new leaf storing the provided data along with
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

        cur = self.cur

        with self.con:
            query = f'''
                INSERT INTO leaf(entry, hash) VALUES (?, ?)
            '''
            cur.execute(query, (data, digest))

        return cur.lastrowid


    def _get_leaf(self, index):
        """
        Returns the hash stored by the leaf specified

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        cur = self.cur

        query = f'''
            SELECT hash FROM leaf WHERE id = ?
        '''
        cur.execute(query, (index,))

        return cur.fetchone()


    def _get_leaves(self, offset, width):
        """
        Returns in respective order the hashes stored by the leaves in the
        range specified

        :param offset: starting position counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        """
        cur = self.cur

        query = f'''
            SELECT hash FROM leaf WHERE id BETWEEN ? AND ?
        '''
        cur.execute(query, (offset + 1, offset + width))

        return cur.fetchall()


    def _get_size(self):
        """
        :returns: current number of leaves
        :rtype: int
        """
        cur = self.cur

        query = f'''
            SELECT COUNT(*) FROM leaf
        '''
        cur.execute(query)

        return cur.fetchone()


    def get_entry(self, index):
        """
        Returns the original data stored by the leaf specified

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        cur = self.cur

        query = f'''
            SELECT entry FROM leaf WHERE id = ?
        '''
        cur.execute(query, (index,))

        return cur.fetchone()


    def _hash_per_chunk(self, entries, chunksize):
        """
        :param entries:
        :type entries: iterable of bytes
        :param chunksize:
        :type chunksize: int
        """
        _hash_entry = self.hash_buff

        offset = 0
        chunk = entries[offset: chunksize]
        while chunk:
            hashes = [_hash_entry(data) for data in chunk]
            yield zip(chunk, hashes)

            offset += chunksize
            chunk = entries[offset: offset + chunksize]


    def append_entries(self, entries, chunksize=100_000):
        """
        Bulk operation for appending a batch of entries.

        :param entries: new data entries
        :type entries: iterable of bytes
        :param chunksize: [optional] nr entries to append per db transaction.
            Defaults to 1,000,000.
        :type chunksize: int
        :returns: index of last appended entry
        :rtype: int
        """
        cur = self.cur

        with self.con:
            query = f'''
                INSERT INTO leaf(entry, hash) VALUES (?, ?)
            '''
            for chunk in self._hash_per_chunk(entries, chunksize):
                cur.execute('BEGIN TRANSACTION')

                for (data, digest) in chunk:
                    cur.execute(query, (data, digest))

                cur.execute('END TRANSACTION')

        return cur.lastrowid

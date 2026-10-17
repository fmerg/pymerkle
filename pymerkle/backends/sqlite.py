import sqlite3
from itertools import islice

from pymerkle.core import BaseMerkleTree, synchronized


class SqliteTree(BaseMerkleTree):
    """
    Persistent Merkle-tree implementation using a SQLite database as storage.

    Inserted data is expected to be in binary format and hashed without
    further processing.

    .. note:: The database schema consists of a single table called *leaf*
        with three columns: *id*, which is the primary key serving as leaf
        index, *entry*, which is a blob field storing the appended data, and
        *hash*, which stores its hash value. The table is append-only:
        deleting or updating rows is rejected by triggers, since leaf indices
        must remain contiguous.

    :raises ValueError: if the leaf indices of an existing database are not
        contiguous

    .. note:: A tree can be shared between threads, its database connection
        being guarded by the tree lock.

    :param dbfile: database filepath
    :type dbfile: str
    :param algorithm: [optional] hashing algorithm. Defaults to *sha256*
    :type algorithm: str
    """

    def __init__(self, dbfile, algorithm='sha256', **opts):
        self.dbfile = dbfile
        # Access to the connection is serialized by the tree lock
        self.con = sqlite3.connect(self.dbfile, check_same_thread=False)
        # All queries select a single column; return its value instead of
        # one-element tuples
        self.con.row_factory = lambda cursor, row: row[0]
        self.cur = self.con.cursor()

        with self.con:
            query = '''
                CREATE TABLE IF NOT EXISTS leaf(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry BLOB,
                    hash BLOB
                );'''
            self.cur.execute(query)

            # Leaf indices must remain contiguous, i.e., the table is
            # append-only
            for (name, action) in (('leaf_no_delete', 'DELETE'),
                                   ('leaf_no_update', 'UPDATE')):
                query = f'''
                    CREATE TRIGGER IF NOT EXISTS {name}
                    BEFORE {action} ON leaf
                    BEGIN
                        SELECT RAISE(ABORT, 'leaf table is append-only');
                    END;'''
                self.cur.execute(query)

        self.cur.execute('SELECT COUNT(*) = COALESCE(MAX(id), 0) FROM leaf')
        if not self.cur.fetchone():
            self.con.close()
            raise ValueError('Leaf indices are not contiguous')

        super().__init__(algorithm, **opts)


    def __enter__(self):
        return self


    def __exit__(self, *exc):
        self.close()


    @synchronized
    def close(self):
        """
        Closes the database connection.
        """
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

        cur = self.cur

        with self.con:
            query = '''
                INSERT INTO leaf(entry, hash) VALUES (?, ?)
            '''
            cur.execute(query, (data, digest))

        return cur.lastrowid


    def _get_leaf(self, index):
        """
        Returns the hash stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        cur = self.cur

        query = '''
            SELECT hash FROM leaf WHERE id = ?
        '''
        cur.execute(query, (index,))

        return cur.fetchone()


    def _get_leaves(self, offset, width):
        """
        Returns in respective order the hashes stored by the leaves in the
        specified range.

        :param offset: starting position counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        """
        cur = self.cur

        query = '''
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

        # Leaf indices are contiguous (append-only table), so that the largest
        # one equals the number of leaves and is read off the primary key index
        # instead of scanning the table
        query = '''
            SELECT COALESCE(MAX(id), 0) FROM leaf
        '''
        cur.execute(query)

        return cur.fetchone()


    @synchronized
    def get_entry(self, index):
        """
        Returns the unhashed data stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        cur = self.cur

        query = '''
            SELECT entry FROM leaf WHERE id = ?
        '''
        cur.execute(query, (index,))

        return cur.fetchone()


    def _hash_per_chunk(self, entries, chunksize):
        """
        Generator yielding in chunks pairs of entry data and hash value.

        :param entries:
        :type entries: iterable of bytes
        :param chunksize:
        :type chunksize: int
        :raises ValueError: if some entry is not binary
        """
        entries = iter(entries)

        chunk = list(islice(entries, chunksize))
        while chunk:
            pairs = []
            for data in chunk:
                if not isinstance(data, bytes):
                    raise ValueError('Provided data is not binary')

                digest = self.hash_buff(self._encode_entry(data))
                pairs += [(data, digest)]

            yield pairs

            chunk = list(islice(entries, chunksize))


    @synchronized
    def append_entries(self, entries, chunksize=100_000):
        """
        Bulk operation for appending a batch of entries.

        .. note:: The operation is atomic, i.e., if it fails, none of the
            provided entries is appended.

        :param entries: data entries to append
        :type entries: iterable of bytes
        :param chunksize: [optional] number of entries to hash and insert at a
            time.
        :type chunksize: int
        :returns: index of last appended entry, i.e., the current tree size
        :rtype: int
        :raises ValueError: if some entry is not binary
        """
        cur = self.cur

        with self.con:
            query = '''
                INSERT INTO leaf(entry, hash) VALUES (?, ?)
            '''
            for chunk in self._hash_per_chunk(entries, chunksize):
                cur.executemany(query, chunk)

        return self._get_size()

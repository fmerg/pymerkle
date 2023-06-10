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
    :param security: [optional] resistance against second-preimage attack.
        Defaults to *True*
    :type security: bool
    """

    def __init__(self, dbfile, algorithm='sha256', security=True):
        self.con = sqlite3.connect(dbfile)
        self.cur = self.con.cursor()

        with self.con:
            query = f'''
                CREATE TABLE IF NOT EXISTS leaf(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry BLOB,
                    hash BLOB
                );'''
            self.cur.execute(query)

        super().__init__(algorithm, security)


    def __enter__(self):
        return self


    def __exit__(self, *exc):
        self.con.close()


    def _encode_leaf(self, entry):
        """
        Returns the binary format of the provided entry

        :param entry: data to encode
        :type entry: bytes
        :rtype: bytes
        """
        return entry


    def _store_leaf(self, entry, value):
        """
        Creates a new leaf storing the provided entry along with its binary
        format and corresponding hash value

        :param entry: data to append
        :type entry: whatever expected according to application logic
        :param value: hashed data
        :type value: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """
        if not isinstance(entry, bytes):
            raise ValueError('Provided data is not binary')

        cur = self.cur

        with self.con:
            query = f'''
                INSERT INTO leaf(entry, hash) VALUES (?, ?)
            '''
            cur.execute(query, (entry, value))

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

        return cur.fetchone()[0]


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

        return cur.fetchone()[0]


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

        return cur.fetchone()[0]

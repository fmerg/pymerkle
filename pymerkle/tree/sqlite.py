import sqlite3 as orm
from pymerkle.base import BaseMerkleTree


class SqliteTree(BaseMerkleTree):
    """
    Merkle-tree implementation using sqlite as data storage

    :param algorithm: [optional] hashing algorithm. Defaults to sha256
    :type algorithm: str
    :param security: [optional] resistance against 2nd-preimage attack.
        Defaults to true
    :type security: bool
    """

    def __init__(self, algorithm='sha256', security=True):
        dbfile = ':memory:'
        con = orm.connect(dbfile)

        self.con = con
        self.cur = con.cursor()

        query = f'''
            CREATE TABLE IF NOT EXISTS leaf(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry BLOB
            );'''
        self.cur.execute(query)

        super().__init__(algorithm, security)


    def _store_data(self, entry):
        """
        Stores the provided data in a new leaf and returns its index

        :param entry: blob to append
        :type entry: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: bytes
        """
        cur = self.cur

        query = f'''
            INSERT INTO leaf(entry) VALUES (?)
        '''
        cur.execute(query, (data,))
        self.con.commit()

        return cur.lastrowid


    def _get_blob(self, index):
        """
        Returns the blob stored at the leaf specified

        :param index:
        :type index: int
        :rtype: bytes
        """
        cur = self.cur

        query = f'''
            SELECT entry FROM leaf WHERE id = ?
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

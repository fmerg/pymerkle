from pymerkle.core import BaseMerkleTree
from sqlalchemy import MetaData, Table, Column, Integer, LargeBinary, create_engine, func, insert, select, between


class SqlAlchemyTree(BaseMerkleTree):

    def __init__(self, engine_url='sqlite://', algorithm='sha256', **opts):
        self.engine = create_engine(engine_url)
        self.metadata_obj = MetaData()
        self.leaf_table = Table(
            "leaf",
            self.metadata_obj,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("entry", LargeBinary),
            Column("hash", LargeBinary),
        )
        self.metadata_obj.create_all(self.engine)

        super().__init__(algorithm, **opts)


    def __enter__(self):
        return self


    def __exit__(self, *exc):
        self.engine.dispose()


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

        stmt = insert(self.leaf_table).values(entry=data, hash=digest)
        with self.engine.connect() as conn:
            result = conn.execute(stmt)
            conn.commit()

        return result.inserted_primary_key[0]


    def _get_leaf(self, index):
        """
        Returns the hash stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        stmt = select(self.leaf_table.c.hash).where(self.leaf_table.c.id == index)
        with self.engine.connect() as conn:
            result = conn.execute(stmt)
            return result.scalar_one()


    def _get_leaves(self, offset, width):
        """
        Returns in respective order the hashes stored by the leaves in the
        specified range.

        :param offset: starting position counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        """
        stmt = select(self.leaf_table.c.hash).where(between(self.leaf_table.c.id, offset + 1, offset + width))
        with self.engine.connect() as conn:
            result = conn.execute(stmt)
            return result.scalars().all()


    def _get_size(self):
        """
        :returns: current number of leaves
        :rtype: int
        """
        stmt = select(func.count("*")).select_from(self.leaf_table)
        with self.engine.connect() as conn:
            result = conn.execute(stmt)
            return result.scalar_one()


    def get_entry(self, index):
        """
        Returns the unhashed data stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        stmt = select(self.leaf_table.c.entry).where(self.leaf.c.id == index)
        with self.engine.connect() as conn:
            result = conn.execute(stmt)
            return result.scalar_one()


    def _hash_per_chunk(self, entries, chunksize):
        """
        Generator yielding in chunks pairs of entry data and hash value.

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

        :param entries: data entries to append
        :type entries: iterable of bytes
        :param chunksize: [optional] number entries to insert per
            database transaction.
        :type chunksize: int
        :returns: index of last appended entry
        :rtype: int
        """
        with self.engine.connect() as conn:
            for chunk in self._hash_per_chunk(entries, chunksize):
                for (data, digest) in chunk:
                    stmt = insert(self.leaf_table).values(entry=data, hash=digest)
                    result = conn.execute(stmt)
                conn.commit()
        return result.inserted_primary_key[0]

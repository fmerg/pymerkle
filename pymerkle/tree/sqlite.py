from pymerkle.base import BaseMerkleTree


class SqliteTree(BaseMerkleTree):
    """
    Simplest Merkle-tree implementation using a list as storage

    :param algorithm: [optional] hashing algorithm. Defaults to sha256
    :type algorithm: str
    :param security: [optional] resistance against 2nd-preimage attack.
        Defaults to true
    :type security: bool
    """

    def __init__(self, algorithm='sha256', security=True):
        self.leaves = []

        super().__init__(algorithm, security)


    def _get_size(self):
        """
        :returns: current number of leaves
        :rtype: int
        """
        return len(self.leaves)


    def _store_blob(self, data):
        """
        Stores the provided data in a new leaf and returns its index

        :param data: blob to append
        :type data: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: bytes
        """
        self.leaves += [data]

        return len(self.leaves)


    def _get_blob(self, index):
        """
        Returns the blob stored at the leaf specified

        :param index:
        :type index: int
        :rtype: bytes
        """
        return self.leaves[index - 1]

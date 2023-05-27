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


    def get_size(self):
        """
        Returns the current number of leaf nodes

        :rtype: int
        """
        return len(self.leaves)


    def append_leaf(self, data):
        """
        Appends a new leaf node with the hash of the provided entry and returns
        its index counting from zero

        :param data:
        :type data: bytes
        :rtype: bytes
        """
        value = self.hash_entry(data)
        self.leaves += [value]

        return len(self.leaves)


    def get_leaf(self, index):
        """
        Returns the leaf hash located at the provided position counting from
        zero

        :param index:
        :type index: int
        :rtype: bytes
        """
        return self.leaves[index - 1]

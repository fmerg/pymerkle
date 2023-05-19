"""
Abstract merkle-tree interface
"""

from abc import ABCMeta, abstractmethod

from pymerkle.hashing import HashEngine
from pymerkle.proof import MerkleProof


class InvalidChallenge(Exception):
    """
    Raised when no merkle-proof exists for the provided challenge
    """
    pass


class BaseMerkleTree(HashEngine, metaclass=ABCMeta):
    """
    Merkle-tree interface

    :param algorithm: [optional] hashing algorithm
    :type algorithm: str
    :param encoding: [optional] encoding scheme
    :type encoding: str
    :param security: [optional] defense against 2nd-preimage attack
    :type security: bool
    """

    @abstractmethod
    def get_size(self):
        """
        Should return the current number of leaves

        :rtype: int
        """

    @abstractmethod
    def append_leaf(self, data):
        """
        Should append and return the hash of the provided data

        :param data: the data whose hash is to be appended
        :type data: bytes or str
        :rtype: int
        """

    @abstractmethod
    def get_leaf(self, index):
        """
        Shoulw return the leaf-hash located at the provided position

        :param index: leaf position counting from one
        :type index: int
        :rtype: bytes
        """

    @abstractmethod
    def get_state(self, size=None):
        """
        Should return the root-hash of the tree specified by the provided size

        :param size: [optional] number of leaves. Defaults to current tree size
        :type size: int
        :rtype: bytes
        """

    @classmethod
    def init_from_entries(cls, *entries, algorithm='sha256', encoding='utf_8',
            security=True):
        """
        Create tree from initial data

        :param entries: initial data to append
        :type entries: iterable of bytes or str
        :param algorithm: [optional] hashing algorithm
        :type algorithm: str
        :param encoding: [optional] encoding scheme
        :type encoding: str
        :param security: [optional] defense against 2nd-preimage attack
        :type security: bool
        """
        tree = cls(algorithm, encoding, security)

        append_leaf = tree.append_leaf
        for data in entries:
            append_leaf(data)

        return tree


    def build_proof(self, offset, path):
        """
        Create a merkle-proof from the provided path

        :param offset: starting position of the verification procedure
        :type offset: int
        :param path: path of hashes
        :type path: iterable of (+1/-1, bytes)
        :returns: proof object consisting of the above components
        :rtype: MerkleProof
        """
        return MerkleProof(self.algorithm, self.encoding, self.security,
                offset, path)

        return proof


    @abstractmethod
    def inclusion_path(self, start, offset, end, bit):
        """
        Should return the inclusion path based on the provided leaf-hash
        against the given leaf range

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: base leaf index counring from zero
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[0/1], list[bytes])
        """

    def prove_inclusion(self, index, size=None):
        """
        Proves inclusion of the hash located at the provided index against the
        subtree specified by the provided size

        :param index: leaf index counting from one
        :type index: int
        :param size: [optional] size of subtree to consider. Defaults to
            current tree size
        :type size: int
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided parameters are invalid or
            incompatible with each other
        """
        if size is None:
            size = self.get_size()

        if size > self.get_size():
            raise InvalidChallenge('Provided size is out of bounds')

        if index <= 0 or index > size:
            raise InvalidChallenge('Provided index is out of bounds')

        offset, path = self.inclusion_path(0, index - 1, size, 0)

        proof = self.build_proof(offset, path)
        return proof


    @abstractmethod
    def consistency_path(self, start, offset, end, bit):
        """
        Should return the consistency path for the state corresponding to the
        provided offset against the specified leaf range

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: represents the state currently under consisteration
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[0/1], list[0/1], list[bytes])
        """

    def prove_consistency(self, size1, size2=None):
        """
        Prove consistency betwee the states corresponding to the respective
        sizes provided

        :param size1: acclaimed size of prior state
        :type size1: int
        :param size2: [optional] acclaimed size of later state. Defaults to
            current tree size
        :type size2: int
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided parameters are invalid or
            incompatible with each other
        """
        if size2 is None:
            size2 = self.get_size()

        if size2 < 0 or size2 > self.get_size():
            raise InvalidChallenge('Provided size2 is out of bounds')

        if size1 < 0 or size1 > size2:
            raise InvalidChallenge('Provided size1 is out of bounds')

        offset, principals, path = self.consistency_path(0, size1, size2, 0)

        proof = self.build_proof(offset, path)
        return proof

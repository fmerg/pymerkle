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

    def get_metadata(self):
        """
        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'encoding': self.encoding,
                'security': self.security}

    @abstractmethod
    def __bool__(self):
        """
        Should return *False* iff the tree is empty
        """

    @abstractmethod
    def get_state(self, size=None):
        """
        Should return the root-hash of the tree specified by the provided size

        :param size: [optional] number of leaves. Defaults to current tree size
        :type size: int
        :rtype: bytes
        """

    @abstractmethod
    def get_size(self):
        """
        Should return the current number of leaves

        :rtype: int
        """

    @abstractmethod
    def get_leaf(self, offset):
        """
        Shoulw return the leaf-hash located at the provided position

        :param index: leaf position counting from 0 (TODO: counting from 1)
        :type index: int
        :rtype: bytes
        """

    @abstractmethod
    def append_entry(self, data):
        """
        Should append and return the hash of the provided data
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

        append_entry = tree.append_entry
        for data in entries:
            append_entry(data)

        return tree


    @abstractmethod
    def find_leaf(self, value):
        """
        Should return the leaf storing the provided hash
        """

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
    def generate_inclusion_path(self, leaf):
        """
        Should return the inclusion path based on the provided leaf
        """

    def prove_inclusion(self, data):
        """
        Prove inclusion of the provided entry

        :param data:
        :type data: str or bytes
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided entry is not included
        """
        checksum = self.hash_entry(data)
        leaf = self.find_leaf(checksum)

        if not leaf:
            raise InvalidChallenge("Provided entry is not included")

        offset, path = self.generate_inclusion_path(leaf)

        proof = self.build_proof(offset, path)
        return proof

    @abstractmethod
    def generate_consistency_path(self, subsize):
        """
        Should return the consistency path based on the provided size
        """

    def prove_consistency(self, subsize, subroot):
        """
        Prove consistency against the provided state

        :param subsize: acclaimed size of requested state
        :type subsize: int
        :param subroot: acclaimed root hash of requested state
        :type subroot: str or bytes
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided parameters do not define
            a previous state
        """
        if isinstance(subroot, str):
            subroot = subroot.encode(self.encoding)

        offset, principals, path = self.generate_consistency_path(subsize)

        if subroot != self.hash_path(len(principals) - 1, principals):
            raise InvalidChallenge("Provided subroot was never root")

        proof = self.build_proof(offset, path)
        return proof

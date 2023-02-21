"""
Abstract interface for Merkle-trees
"""

from abc import ABCMeta, abstractmethod

from pymerkle.hashing import HashEngine
from pymerkle.proof import MerkleProof


class InvalidChallenge(Exception):
    """
    Raised when no Merkle-proof can be generated for the provided challenge
    """
    pass


class BaseMerkleTree(HashEngine, metaclass=ABCMeta):
    """
    Merkle-tree interface

    :param algorithm: [optional] hashing algorithm (default: sha256)
    :type algorithm: str
    :param encoding: [optional] encoding type (default: utf-8)
    :type encoding: str
    :param security: [optional] defence against 2nd-preimage attack (default:
        true)
    :type security: bool
    """

    def __init__(self, algorithm='sha256', encoding='utf-8', security=True):
        self.algorithm = algorithm
        self.encoding = encoding
        self.security = security

        HashEngine.__init__(self, algorithm, encoding, security)

    def get_config(self):
        """
        :returns: a triple consisting of the hash algorithm, encoding type and
            security mode
        :rtype:
        """
        return self.algorithm, self.encoding, self.security

    @abstractmethod
    def __bool__(self):
        """
        Should return *False* iff the tree is empty
        """

    @property
    @abstractmethod
    def length(self):
        """
        Should return the current number of leaf nodes
        """

    @property
    @abstractmethod
    def size(self):
        """
        Should return the current number of nodes
        """

    @property
    @abstractmethod
    def height(self):
        """
        Should return the current height
        """

    @abstractmethod
    def append_entry(self, data):
        """
        Define here the growing strategy of the tree
        """

    @classmethod
    def init_from_entries(cls, *entries, algorithm='sha256', encoding='utf_8',
            security=True):
        """
        Create tree from initial data

        :param data: initial data to append
        :type data: iterable of bytes or str
        :param config: tree configuration
        :type config: dict
        """
        tree = cls(algorithm, encoding, security)

        append_entry = tree.append_entry
        for data in entries:
            append_entry(data)

        return tree

    @abstractmethod
    def get_root(self):
        """
        Should return the current root hash
        """

    @abstractmethod
    def find_leaf(self, value):
        """
        Should return the leaf storing the provided hash value
        """

    def build_proof(self, offset, path):
        """
        Create a Merkle-proof from the provided path of hashes

        :param offset: starting position of the verification procedure
        :type offset: int
        :param path: path of hashes
        :type path: iterable of (+1/-1, bytes)
        :returns: proof object consisting of the above components
        :rtype: MerkleProof
        """
        commitment = self.get_root()
        proof = MerkleProof(self.algorithm, self.encoding, self.security,
                offset, path, commitment=commitment)

        return proof

    @abstractmethod
    def generate_inclusion_path(self, leaf):
        """
        Should return the inclusion path for the provided challenge
        """

    def prove_inclusion(self, challenge):
        """
        Return inclusion Merkle-proof for the provided challenge

        :param challenge: hash value to be proven
        :type challenge: bytes
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided hash value is not appended
        """
        leaf = self.find_leaf(value=challenge)
        if not leaf:
            raise InvalidChallenge("Provided hash is not included")

        offset, path = self.generate_inclusion_path(leaf)
        proof = self.build_proof(offset, path)

        return proof

    @abstractmethod
    def generate_consistency_path(self, sublength):
        """
        Should return the consistency path for the provided challenge
        """

    def prove_consistency(self, challenge):
        """
        Return consistency Merkle-proof for the provided challenge

        :param challenge: acclaimed root-hash of some previous state of the tree
        :type challenge: bytes
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided hash value is not a previous
            state
        """
        flag = False    # TODO
        for sublength in range(1, self.length + 1):
            offset, left_path, path = self.generate_consistency_path(sublength)

            if challenge == self.hash_path(left_path, len(left_path) - 1):
                flag = True
                break

        if not flag:
            raise InvalidChallenge

        proof = self.build_proof(offset, path)
        return proof

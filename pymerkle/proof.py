import os
import json
from time import time

from pymerkle.hasher import MerkleHasher


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


def verify_inclusion(base, root, proof):
    """
    Verifies the provided Merkle-proof of inclusion against the provided leaf
    hash and tree state.

    :param base: acclaimed leaf hash
    :type base: bytes
    :param root: acclaimed root hash
    :type root: bytes
    :param proof: proof of inclusion
    :type proof: MerkleProof
    :raises InvalidProof: if the proof is found invalid
    """
    if not proof.path[0] == base:
        raise InvalidProof('Base hash does not match')

    if not proof.resolve() == root:
        raise InvalidProof('State does not match')


def verify_consistency(state1, state2, proof):
    """
    Verifies the provided Merkle-proof of consistency against the given states.

    :param state1: acclaimed prior state
    :type state1: bytes
    :param state2: acclaimed later state
    :type state2: bytes
    :raises InvalidProof: if the proof is found invalid
    :param proof: proof of consistency
    :type proof: MerkleProof
    """
    if not proof.retrieve_prior_state() == state1:
        raise InvalidProof('Prior state does not match')

    if not proof.resolve() == state2:
        raise InvalidProof('Later state does not match')


class MerkleProof:
    """
    Verifiable Merkle-proof object

    :param algorithm: hash algorithm to be applied during state resolution
    :type algorithm: str
    :param security: resistance against 2-nd preimage attack indicator
    :type security: bool
    :param size: tree size corresponding to requested state
    :type size: int
    :param rule: specifies parenthetization of hashes during state
        resolution
    :type rule: list[int]
    :param subset: indicates subset of hashes during prior state resolution
        (makes sense only for consistency proofs)
    :type subset: list[int]
    :param path: path of hashes
    :type path: list[bytes]
    """

    def __init__(self, algorithm, security, size, rule, subset, path):
        self.algorithm = algorithm
        self.security = security
        self.size = size
        self.rule = rule
        self.subset = subset
        self.path = path
        self.hasher = MerkleHasher(**self.get_metadata())


    def get_metadata(self):
        """
        Returns the information needed to configure the hashing machinery.

        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'security': self.security,
                'size': self.size}

    def serialize(self):
        """
        Returns the JSON representation of the verifiable object.

        :rtype: dict
        """
        return {
            'metadata': {
                'algorithm': self.algorithm,
                'security': self.security,
                'size': self.size,
            },
            'rule': self.rule,
            'subset': self.subset,
            'path': [digest.hex() for digest in self.path]
        }


    @classmethod
    def deserialize(cls, data):
        """
        :param data:
        :type data: dict
        :rtype: MerkleProof
        """
        metadata = data['metadata']
        rule = data['rule']
        subset = data['subset']
        path = [bytes.fromhex(checksum) for checksum in data['path']]

        return cls(**metadata, rule=rule, subset=subset, path=path)


    def retrieve_prior_state(self):
        """
        Computes the acclaimed prior state as specified by the included path of
        hashes.

        .. note:: Makes sense only for consistency proofs.

        :rtype: bytes
        """
        subpath = [digest for (mask, digest) in zip(self.subset, self.path) if
            mask]

        if not subpath:
            return self.hasher.hash_empty()

        result = subpath[0]
        index = 0
        hash_pair = self.hasher.hash_pair
        while index < len(subpath) - 1:
            result = hash_pair(subpath[index + 1], result)
            index += 1

        return result


    def resolve(self):
        """
        Computes the target hash of the included path of hashes.

        :rtype: bytes
        """
        path = list(zip(self.rule, self.path))

        if not path:
            return self.hasher.hash_empty()

        bit, result = path[0]
        index = 0
        hash_pair = self.hasher.hash_pair
        while index < len(path) - 1:
            next_bit, digest = path[index + 1]

            match bit:
                case 0:
                    result = hash_pair(result, digest)
                case 1:
                    result = hash_pair(digest, result)
                case _:
                    raise ValuError('Invalid bit found')

            bit = next_bit
            index += 1

        return result

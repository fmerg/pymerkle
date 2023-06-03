"""
Merkle-proof machinery
"""

import os
import json
from time import time

from pymerkle.hasher import MerkleHasher


class InvalidProof(Exception):
    """
    Raised when a merkle-proof is found to be invalid
    """
    pass


def verify_inclusion(base, target, proof):
    """
    Verifies the provided merkle-proof of inclusion for the given base entry
    against the provided state

    :param base: acclaimed hash to verify
    :type base: str
    :param target: acclaimed state during proof generation
    :type target: str
    :param proof: proof of inclusion
    :type proof: MerkleProof
    :raises InvalidProof: if the proof is found invalid
    """
    if not proof.path[0] == bytes.fromhex(base):
        raise InvalidProof('Base hash does not match')

    if not proof.resolve() == bytes.fromhex(target):
        raise InvalidProof('State does not match')


def verify_consistency(state1, state2, proof):
    """
    Verifies the provided merkle-proof of consistency for the given state
    against the provided root hash.

    :param state1: acclaimed prior state
    :type state1: str
    :param state2: acclaimed state during proof generation
    :type state2: str
    :raises InvalidProof: if the proof is found invalid
    :param proof: proof of consistency
    :type proof: MerkleProof
    """
    if not proof.retrieve_prior_state() == bytes.fromhex(state1):
        raise InvalidProof('Prior state does not match')

    if not proof.resolve() == bytes.fromhex(state2):
        raise InvalidProof('Later state does not match')


class MerkleProof(MerkleHasher):

    def __init__(self, algorithm, security, size, rule, subset, path):
        """
        :param algorithm: hash algorithm
        :type algorithm: str
        :param security: defense against 2-nd preimage attack
        :type security: bool
        :param size: nr leaves corresponding to requested current state
        :typw size: int
        :param rule: specifies parenthetization of hashes during current state
            recovery
        :type rule: list[int]
        :param subset: indicates subset of hashes for prior state recovery
        :type subset: list[int]
        :param path: path of hashes
        :type path: list[bytes]
        """
        self.algorithm = algorithm
        self.security = security
        self.size = size
        self.rule = rule
        self.subset = subset
        self.path = path

        MerkleHasher.__init__(self, **self.get_metadata())


    def get_metadata(self):
        """
        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'security': self.security,
                'size': self.size}

    def serialize(self):
        """
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
            'path': [value.hex() for value in self.path]
        }


    @classmethod
    def deserialize(cls, proof):
        """
        :rtype: MerkleProof
        """
        metadata = proof['metadata']
        rule = proof['rule']
        subset = proof['subset']
        path = [bytes.fromhex(value) for value in proof['path']]

        return cls(**metadata, rule=rule, subset=subset, path=path)


    def retrieve_prior_state(self):
        """
        :rtype: bytes
        """
        subpath = [value for (mask, value) in zip(self.subset, self.path) if
            mask]

        if not subpath:
            return h.consume(b'')

        result = subpath[0]
        index = 0
        while index < len(subpath) - 1:
            result = self.hash_nodes(subpath[index + 1], result)
            index += 1

        return result


    def resolve(self):
        """
        :rtype: bytes
        """
        path = list(zip(self.rule, self.path))

        if not path:
            return h.consume(b'')

        bit, result = path[0]
        index = 0
        while index < len(path) - 1:
            next_bit, value = path[index + 1]

            match bit:
                case 0:
                    result = self.hash_nodes(result, value)
                case 1:
                    result = self.hash_nodes(value, result)
                case _:
                    raise Exception('Invalid bit found')

            bit = next_bit
            index += 1

        return result

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


def verify_inclusion(base, state, proof):
    """
    Verifies the provided merkle-proof of inclusion for the given base entry
    against the provided state

    :param base: acclaimed hash to verify
    :type base: str or bytes
    :param state: acclaimed state during proof generation
    :type state: str or bytes
    :param proof: proof of inclusion
    :type proof: MerkleProof
    :raises InvalidProof: if the proof is found invalid
    """
    if isinstance(base, str):
        base = base.encode(proof.encoding)

    if isinstance(state, str):
        state = state.encode(proof.encoding)

    if not proof.path[0] == base:
        raise InvalidProof('Base hash does not match')

    if not proof.resolve() == state:
        raise InvalidProof('State does not match')


def verify_consistency(prior, state, proof):
    """
    Verifies the provided merkle-proof of consistency for the given state
    against the provided root hash.

    :param prior: acclaimed prior state
    :type prior: str or bytes
    :param state: acclaimed state during proof generation
    :type state: str or bytes
    :raises InvalidProof: if the proof is found invalid
    :param proof: proof of consistency
    :type proof: MerkleProof
    """
    if isinstance(prior, str):
        prior = prior.encode(proof.encoding)

    if isinstance(state, str):
        state = state.encode(proof.encoding)

    if not proof.retrieve_prior_state() == prior:
        raise InvalidProof('Prior state does not match')

    if not proof.resolve() == state:
        raise InvalidProof('Later state does not match')


class MerkleProof:

    def __init__(self, algorithm, encoding, security, size, rule, subset,
            path):
        """
        :param algorithm: hash algorithm
        :type algorithm: str
        :param encoding: encoding scheme
        :type encoding: str
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
        self.encoding = encoding
        self.security = security
        self.size = size
        self.rule = rule
        self.subset = subset
        self.path = path


    def get_metadata(self):
        """
        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'encoding': self.encoding,
                'security': self.security}

    def serialize(self):
        """
        :rtype: dict
        """
        return {
            'metadata': {
                'algorithm': self.algorithm,
                'encoding': self.encoding,
                'security': self.security,
            },
            'size': self.size,
            'rule': self.rule,
            'subset': self.subset,
            'path': [value.decode(self.encoding) for value in self.path]
        }


    @classmethod
    def deserialize(cls, proof):
        """
        :rtype: MerkleProof
        """
        metadata = proof['metadata']
        encoding = metadata['encoding']
        rule = proof['rule']
        size = proof['size']
        subset = proof['subset']
        path = [value.encode(encoding) for value in proof['path']]

        return cls(**metadata, size=size, rule=rule, subset=subset, path=path)


    def retrieve_prior_state(self):
        """
        :rtype: bytes
        """
        subpath = [value for (mask, value) in zip(self.subset, self.path) if
            mask]

        h = MerkleHasher(**self.get_metadata())

        if not subpath:
            return h.consume(b'')

        result = subpath[0]
        index = 0
        while index < len(subpath) - 1:
            result = h.hash_nodes(subpath[index + 1], result)
            index += 1

        return result


    def resolve(self):
        """
        :rtype: bytes
        """
        path = list(zip(self.rule, self.path))

        h = MerkleHasher(**self.get_metadata())

        if not path:
            return h.consume(b'')

        bit, result = path[0]
        index = 0
        while index < len(path) - 1:
            next_bit, value = path[index + 1]

            match bit:
                case 0:
                    result = h.hash_nodes(result, value)
                case 1:
                    result = h.hash_nodes(value, result)
                case _:
                    raise Exception('Invalid bit found')

            bit = next_bit
            index += 1

        return result

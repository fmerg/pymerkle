"""
Merkle-proof machinery
"""

import os
import json
from time import time

from pymerkle.hashing import HashEngine


class InvalidProof(Exception):
    """
    Raised when a merkle-proof is found to be invalid
    """
    pass


def verify_inclusion(base, target, proof):
    """
    Verifies the provided merkle-proof of inclusion for the given data against
    the provided root hash.

    :param base: entry to verify
    :type base: str or bytes
    :param target: root hash during proof generation
    :type target: str or bytes
    :param proof: proof of inclusion
    :type proof: MerkleProof
    :raises InvalidProof: if the proof is invalid
    """
    engine = HashEngine(**proof.get_metadata())

    if isinstance(base, str):
        base = base.encode(proof.encoding)

    if isinstance(target, str):
        target = target.encode(proof.encoding)

    offset = proof.offset

    if not proof.path[offset][1] == base:
        raise InvalidProof("Path not based on provided entry")

    if target != engine.hash_path(offset, proof.path):
        raise InvalidProof("Path failed to resolve")


def verify_consistency(state1, state2, proof):
    """
    Verifies the provided merkle-proof of consistency for the given state
    against the provided root hash.

    :param state1:
    :type state1: str or bytes
    :param state2: root during proof generation
    :type state2: str or bytes
    :raises InvalidProof: if the proof is invalid
    :param proof: proof of consistency
    :type proof: MerkleProof
    """
    engine = HashEngine(**proof.get_metadata())

    if isinstance(state1, str):
        state1 = state1.encode(proof.encoding)

    if isinstance(state2, str):
        state2 = state2.encode(proof.encoding)

    offset = proof.offset

    principals = [(-1, value) for (_, value) in proof.path[:offset + 1]]
    if state1 != engine.hash_path(offset, principals):
        raise InvalidProof("Path not based on provided state")

    if state2 != engine.hash_path(offset, proof.path):
        raise InvalidProof("Path failed to resolve")


class MerkleProof:
    """
    :param algorithm: hash algorithm
    :type algorithm: str
    :param encoding: encoding scheme
    :type encoding: str
    :param security: defense against 2-nd preimage attack
    :type security: bool
    :param offset: starting position for hashing during verification
    :type offset: int
    :param path: path of hashes
    :type path: list[(+1/-1, bytes)]
    """

    def __init__(self, algorithm, encoding, security, offset, path):
        self.algorithm = algorithm
        self.encoding = encoding
        self.security = security
        self.offset = offset
        self.path = path


    def get_metadata(self):
        """
        .. note:: These are parameters required for configuring the hashing
            machinery during proof verification

        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'encoding': self.encoding,
                'security': self.security}


    def serialize(self):
        """
        :rtype: dict
        """
        algorithm = self.algorithm
        encoding = self.encoding
        security = self.security
        offset = self.offset
        path = [[sign, value.decode(self.encoding)] for (sign, value) in
                self.path]

        return {
            'metadata': {
                'algorithm': algorithm,
                'encoding': encoding,
                'security': security,
            },
            'offset': offset,
            'path': path,
        }


    @classmethod
    def deserialize(cls, proof):
        """
        :rtype: MerkleProof
        """
        metadata = proof['metadata']
        encoding = metadata['encoding']
        path = [(sign, value.encode(encoding)) for [sign, value] in
                proof['path']]
        offset = proof['offset']

        return cls(**metadata, path=path, offset=offset)

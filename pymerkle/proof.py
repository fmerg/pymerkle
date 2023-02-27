"""
Merkle-proof machinery
"""

import os
import json
from time import time

from pymerkle.hashing import HashEngine


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid
    """
    pass


def verify_inclusion(proof, data, target):
    """
    :param proof: proof of inclusion
    :type proof: MerkleProof
    :param data: entry to verify
    :type data: str or bytes
    :param target: state during proof generation
    :type target: str or bytes
    :raises InvalidProof: if the proof is invalid
    """
    engine = HashEngine(**proof.get_metadata())

    if isinstance(target, str):
        target = target.encode(proof.encoding)

    offset = proof.offset

    if proof.path[offset][1] != engine.hash_entry(data):
        raise InvalidProof("Path not based on provided entry")

    if target != engine.hash_path(offset, proof.path):
        raise InvalidProof("Path failed to resolve")


def verify_consistency(proof, state, target):
    """
    :param proof: proof of consistency
    :type proof: MerkleProof
    :param state:
    :type state: str or bytes
    :param target: root during proof generation
    :type target: str or bytes
    :raises InvalidProof: if the proof is invalid
    """
    engine = HashEngine(**proof.get_metadata())

    if isinstance(state, str):
        state = state.encode(proof.encoding)

    if isinstance(target, str):
        target = target.encode(proof.encoding)

    offset = proof.offset

    principals = [(-1, value) for (_, value) in proof.path[:offset + 1]]
    if state != engine.hash_path(offset, principals):
        raise InvalidProof("Path not based on provided state")

    if target != engine.hash_path(offset, proof.path):
        raise InvalidProof("Path failed to resolve")


class MerkleProof:
    """
    :param algorithm: hash algorithm
    :type algorithm: str
    :param encoding: encoding type
    :type encoding: str
    :param security: defence against 2-nd preimage attack
    :type security: bool
    :param offset: starting position of hashing during verification
    :type offset: int
    :param path: path of hashes
    :type path: list of (+1/-1, bytes)
    """

    def __init__(self, algorithm, encoding, security, offset, path,
                 timestamp=None):
        self.algorithm = algorithm
        self.encoding = encoding
        self.security = security
        self.timestamp = timestamp or int(time())
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
        timestamp = self.timestamp
        algorithm = self.algorithm
        encoding = self.encoding
        security = self.security
        offset = self.offset
        path = [[sign, value.decode(self.encoding)] for (sign, value) in
                self.path]

        return {
            'metadata': {
                'timestamp': timestamp,
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

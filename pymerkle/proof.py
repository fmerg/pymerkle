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

    offset = proof.offset
    path = proof.path

    if isinstance(target, str):
        target = target.encode(proof.encoding)

    if path[offset][1] != engine.hash_entry(data):
        raise InvalidProof("Path not based on entry")

    if target != engine.hash_path(path, offset):
        raise InvalidProof("Path failed to resolve")


def verify_consistency(proof, state, target):
    """
    :param proof: proof of consistency
    :type proof: MerkleProof
    :param state: past state to verify
    :type state: str or bytes
    :param target: state during proof generation
    :type target: str or bytes
    :raises InvalidProof: if the proof is invalid
    """
    pass


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
                 timestamp=None, commitment=None):
        self.algorithm = algorithm
        self.encoding = encoding
        self.security = security
        self.timestamp = timestamp or int(time())
        self.commitment = commitment
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

    def resolve(self):
        """
        Computes the hash value resulting from the proof's path of hashes.

        :rtype: bytes
        """
        engine = HashEngine(**self.get_metadata())
        result = engine.hash_path(self.path, self.offset)

        return result

    def verify(self, target=None):
        """
        Merkle-proof verification.

        Verifies that the hash value resulting from the included path of hashes
        coincides with the target.

        :raises InvalidProof: if the proof fails to verify.

        :param target: [optional] target hash to compare against. Defaults to
            the commitment included in the proof.
        :type target: bytes
        :returns: the verification result (*True*) in case of success.
        :rtype: bool
        """
        target = self.commitment if target is None else target

        if target != self.resolve():
            raise InvalidProof

        return True

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
        commitment = self.commitment.decode(encoding) if self.commitment \
            else None

        return {
            'metadata': {
                'timestamp': timestamp,
                'algorithm': algorithm,
                'encoding': encoding,
                'security': security,
            },
            'body': {
                'offset': offset,
                'path': path,
                'commitment': commitment,
            }
        }

    @classmethod
    def deserialize(cls, proof):
        """
        :rtype: MerkleProof
        """
        metadata = proof['metadata']
        body = proof['body']
        encoding = metadata['encoding']
        path = [(sign, value.encode(encoding)) for [sign, value] in
                body['path']]
        offset = body['offset']

        kw = {**metadata, 'path': path, 'offset': offset}

        commitment = body.get('commitment', None)
        if commitment:
            kw['commitment'] = commitment.encode(encoding)

        return cls(**kw)

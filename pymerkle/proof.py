"""
Provides the Merkle-proof object.
"""

import os
import json
from time import time, ctime

from pymerkle.hashing import HashEngine


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


class MerkleProof:
    """
    :param algorithm: hash type of the provider tree
    :type algorithm: str
    :param encoding: encoding type of the provider tree
    :type encoding: str
    :param security: security mode of the provider tree
    :type security: bool
    :param offset: starting position of hashing during verification
    :type offset: int
    :param path: path of hashes
    :type path: list of (+1/-1, bytes)
    """

    def __init__(self, algorithm, encoding, security, offset, path,
                 timestamp=None, created_at=None, commitment=None):
        self.timestamp = timestamp or int(time())
        self.created_at = created_at or ctime()
        self.algorithm = algorithm
        self.encoding = encoding
        self.security = security
        self.commitment = commitment
        self.offset = offset
        self.path = path

    def __eq__(self, other):
        return all((
            isinstance(other, __class__),
            self.timestamp == other.timestamp,
            self.created_at == other.created_at,
            self.algorithm == other.algorithm,
            self.encoding == other.encoding,
            self.security == other.security,
            self.commitment == other.commitment,
            self.offset == other.offset,
            self.path == other.path,
        ))


    def get_verification_params(self):
        """
        Parameters required for configuring the verification hashing machinery.

        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'encoding': self.encoding,
                'security': self.security}

    def resolve(self):
        """
        Computes the hash value resulting from the proof's path of hashes.

        :rtype: bytes
        """
        engine = HashEngine(**self.get_verification_params())
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
        created_at = self.created_at
        timestamp = self.timestamp
        algorithm = self.algorithm
        encoding = self.encoding
        security = self.security
        commitment = self.commitment.decode(self.encoding) if self.commitment \
                else None
        offset = self.offset

        path = []
        for (sign, value) in self.path:
            checksum = value if isinstance(value, str) else \
                    value.decode(self.encoding)
            path += [[sign, checksum]]

        return {
            'metadata': {
                'timestamp': timestamp,
                'created_at': created_at,
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
        kw = {}

        metadata = proof['metadata']
        kw.update(metadata)

        body = proof['body']
        kw['offset'] = body['offset']
        encoding = metadata['encoding']
        kw['path'] = [(pair[0], pair[1].encode(encoding)) for pair in
                body['path']]
        commitment = body.get('commitment', None)
        if commitment:
            kw['commitment'] = commitment.encode()

        return cls(**kw)

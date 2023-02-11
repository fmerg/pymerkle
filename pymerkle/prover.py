"""
Provides the Merkle-proof objects.
"""

import os
import json
from time import time, ctime
from abc import ABCMeta, abstractmethod

from pymerkle.hashing import HashEngine
from pymerkle.utils import log10, generate_uuid


PROOF_TEMPLATE = """
    ----------------------------------- PROOF ------------------------------------

    uuid        : {uuid}

    timestamp   : {timestamp} ({created_at})

    hash-type   : {algorithm}
    encoding    : {encoding}
    security    : {security}

    {path}

    offset      : {offset}

    commitment  : {commitment}

    -------------------------------- END OF PROOF --------------------------------
"""


def _order_of_magnitude(num):
    return int(log10(num)) if num != 0 else 0


def _get_signed(num):
    return f'{"+" if num >= 0 else ""}{num}'


def stringify_path(path, encoding):
    """
    Returns a string composed of the provided path of hashes.

    :param path: sequence of signed hashes
    :type path: list of (+1/-1, bytes) or (+1/-1, str)
    :param encoding: encoding type to be used for decoding
    :type encoding: str
    :rtype: str
    """
    pairs = []
    pair_template = '\n{left}[{index}]{middle}{sign}{right}{value}'
    for index, curr in enumerate(path):
        pairs.append(
            pair_template.format(left=(7 - _order_of_magnitude(index)) * ' ',
                                 index=index,
                                 middle=3 * ' ',
                                 sign=_get_signed(curr[0]),
                                 right=3 * ' ',
                                 value=curr[1].decode(encoding) if not isinstance(curr[1], str)
                                 else curr[1]))
    return ''.join(pairs)


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


class MerkleProof(metaclass=ABCMeta):
    """
    Interface and abstract functionality for Merkle-proofs.

    :param algorithm: hash-type of the provider tree
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

    def __init__(self, algorithm, encoding, security, offset, path, uuid=None,
                 timestamp=None, created_at=None, commitment=None):
        self.uuid = uuid or generate_uuid()
        self.timestamp = timestamp or int(time())
        self.created_at = created_at or ctime()
        self.algorithm = algorithm
        self.encoding = encoding
        self.security = security
        self.commitment = commitment
        self.offset = offset
        self.path = path

    def get_verification_params(self):
        """
        Parameters required for configuring the verification hashing machinery.

        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'encoding': self.encoding,
                'security': self.security}

    def load_hash_engine(self):
        """
        Load hashing machinery according to the included verification
        parameters.

        :rtype: HashEngine
        """
        return HashEngine(**self.get_verification_params())

    def compute_checksum(self):
        """
        Computes the hash value resulting from the proof's path of hashes.

        :rtype: bytes
        """
        engine = self.load_hash_engine()
        checksum = engine.hash_path(self.path, self.offset)

        return checksum

    @abstractmethod
    def verify(self, *args, **kwargs):
        """
        Should specify how to verify the proof.
        """

    def __repr__(self):
        """
        .. warning:: Contrary to convention, the output of this method is not
            insertable into the *eval()* builtin Python function.
        """
        uuid = self.uuid
        timestamp = self.timestamp
        created_at = self.created_at
        algorithm = self.algorithm.upper().replace('_', '')
        encoding = self.encoding.upper().replace('_', '-')
        security = 'ACTIVATED' if self.security else 'DEACTIVATED'
        commitment = self.commitment.decode(self.encoding) if self.commitment \
                else None
        offset = self.offset
        path = stringify_path(self.path, self.encoding)

        kw = {'uuid': uuid, 'timestamp': timestamp, 'created_at': created_at,
              'algorithm': algorithm, 'encoding': encoding, 'security': security,
              'commitment': commitment, 'offset': offset, 'path': path}

        return PROOF_TEMPLATE.format(**kw)

    def serialize(self):
        """
        Returns a JSON dictionary with the proof's characteristics as key-value
        pairs.

        :rtype: dict
        """
        uuid = self.uuid
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
            path.append([sign, checksum])

        return {
            'header': {
                'uuid': uuid,
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
    def from_dict(cls, proof):
        """
        :param proof: serialized proof as JSON dict.
        :type proof: dict
        """
        kw = {}

        header = proof['header']
        kw.update(header)

        body = proof['body']
        kw['offset'] = body['offset']
        encoding = header['encoding']
        kw['path'] = [(pair[0], pair[1].encode(encoding)) for pair in
                body['path']]
        commitment = body.get('commitment', None)
        if commitment:
            kw['commitment'] = commitment.encode()

        return cls(**kw)

    def toJSONText(self, indent=4):
        """
        Returns a JSON text with the proof's characteristics as key-value
        pairs.

        :rtype: str
        """
        return json.dumps(self.serialize(), sort_keys=False, indent=indent)

    @classmethod
    def fromJSONText(cls, text):
        """
        :param text: serialized proof as JSON text.
        :type text: str
        """
        return cls.from_dict(json.loads(text))

    @classmethod
    def deserialize(cls, serialized):
        """
        :params serialized: JSON dict or text, assumed to be the serialization
            of a Merkle-proof
        :type: dict or str
        :rtype: MerkleProof
        """
        if isinstance(serialized, dict):
            return cls.from_dict(serialized)
        elif isinstance(serialized, str):
            return cls.fromJSONText(serialized)


class AuditProof(MerkleProof):

    def verify(self, target=None):
        """
        Audit-proof verification.

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

        if self.offset == -1 and self.path == []:
            raise InvalidProof

        if target != self.compute_checksum():
            raise InvalidProof

        return True


class ConsistencyProof(MerkleProof):

    def verify(self, target=None, challenge=None):
        """
        Consistencty-proof verification.

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

        if self.offset == -1 and self.path == []:
            raise InvalidProof

        if target != self.compute_checksum():
            raise InvalidProof

        if challenge:
            left_path = [(-1, r[1]) for r in self.path[:self.offset + 1]]
            engine = self.load_hash_engine()
            awaited = engine.hash_path(left_path, self.offset)
            if challenge != awaited:
                raise InvalidProof

        return True

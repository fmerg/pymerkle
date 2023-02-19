"""
Provides the Merkle-proof object.
"""

import os
import json
from time import time, ctime

from pymerkle.hashing import HashEngine
from pymerkle.utils import log10


PROOF_TEMPLATE = """
    ----------------------------------- PROOF ------------------------------------

    timestamp   : {timestamp} ({created_at})

    algorithm   : {algorithm}
    encoding    : {encoding}
    security    : {security}

    {path}

    offset      : {offset}

    commitment  : {commitment}

    -------------------------------- END OF PROOF --------------------------------
"""


def order_of_magnitude(num):
    return int(log10(num)) if num != 0 else 0


def get_with_sign(num):
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
        pair = pair_template.format(
            left=(7 - order_of_magnitude(index)) * ' ',
            index=index,
            middle=3 * ' ',
            sign=get_with_sign(curr[0]),
            right=3 * ' ',
            value=curr[1].decode(encoding) if not isinstance(curr[1], str) else curr[1]
        )
        pairs += [pair]
    return ''.join(pairs)


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

    def __repr__(self):
        """
        .. warning:: Contrary to convention, the output of this method is not
            insertable into the *eval()* builtin Python function.
        """
        timestamp = self.timestamp
        created_at = self.created_at
        algorithm = self.algorithm.upper().replace('_', '')
        encoding = self.encoding.upper().replace('_', '-')
        security = 'ACTIVATED' if self.security else 'DEACTIVATED'
        commitment = self.commitment.decode(self.encoding) if self.commitment \
                else None
        offset = self.offset
        path = stringify_path(self.path, self.encoding)

        kw = {'timestamp': timestamp, 'created_at': created_at,
              'algorithm': algorithm, 'encoding': encoding, 'security': security,
              'commitment': commitment, 'offset': offset, 'path': path}

        return PROOF_TEMPLATE.format(**kw)

    def serialize(self):
        """
        Returns a JSON dictionary with the proof's characteristics as key-value
        pairs.

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
    def from_dict(cls, proof):
        """
        :param proof: serialized proof as JSON dict.
        :type proof: dict
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

"""
Provides the Merkle-proof object.
"""

import os
import json
from time import time, ctime

from pymerkle.hashing import HashEngine
from pymerkle.utils import log10, generate_uuid


PROOF_TEMPLATE = """
    ----------------------------------- PROOF ------------------------------------

    uuid        : {uuid}

    timestamp   : {timestamp} ({created_at})
    provider    : {provider}

    hash-type   : {hash_type}
    encoding    : {encoding}
    security    : {security}

    {path}

    offset      : {offset}

    commitment  : {commitment}

    -------------------------------- END OF PROOF --------------------------------
"""


def stringify_path(path, encoding):
    """
    Returns a string composed of the provided path of hashes.

    :param path: sequence of signed hashes
    :type path: list of (+1/-1, bytes) or (+1/-1, str)
    :param encoding: encoding type to be used for decoding
    :type encoding: str
    :rtype: str
    """
    def order_of_magnitude(num): return int(log10(num)) if num != 0 else 0
    def get_with_sign(num): return f'{"+" if num >= 0 else ""}{num}'
    pairs = []
    pair_template = '\n{left}[{index}]{middle}{sign}{right}{digest}'
    for index, curr in enumerate(path):
        pairs.append(
            pair_template.format(left=(7 - order_of_magnitude(index)) * ' ',
                                 index=index,
                                 middle=3 * ' ',
                                 sign=get_with_sign(curr[0]),
                                 right=3 * ' ',
                                 digest=curr[1].decode(encoding) if not isinstance(curr[1], str)
                                 else curr[1]))
    return ''.join(pairs)


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


class Proof:
    """
    :param provider: uuid of the provider tree
    :type provider: str
    :param hash_type: hash-type of the provider tree
    :type hash_type: str
    :param encoding: encoding type of the provider tree
    :type encoding: str
    :param security: security mode of the provider tree
    :type security: bool
    :param offset: starting position of hashing during verification
    :type offset: int
    :param path: path of hashes
    :type path: list of (+1/-1, bytes)
    """

    def __init__(self, provider, hash_type, encoding, security, offset, path,
                 uuid=None, timestamp=None, created_at=None, commitment=None):
        self.uuid = uuid or generate_uuid()
        self.timestamp = timestamp or int(time())
        self.created_at = created_at or ctime()
        self.provider = provider
        self.hash_type = hash_type
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
        return {'hash_type': self.hash_type, 'encoding': self.encoding,
                'security': self.security}

    def compute_checksum(self):
        """
        Computes the hash value resulting from the proof's path of hashes.

        :rtype: bytes
        """
        engine = HashEngine(**self.get_verification_params())
        checksum = engine.multi_hash(self.path, self.offset)

        return checksum

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

        if self.offset == -1 and self.path == []:
            raise InvalidProof

        if target != self.compute_checksum():
            raise InvalidProof

        return True

    def __repr__(self):
        """
        .. warning:: Contrary to convention, the output of this method is not
            insertable into the *eval()* builtin Python function.
        """
        uuid = self.uuid
        timestamp = self.timestamp
        created_at = self.created_at
        provider = self.provider
        hash_type = self.hash_type.upper().replace('_', '')
        encoding = self.encoding.upper().replace('_', '-')
        security = 'ACTIVATED' if self.security else 'DEACTIVATED'
        commitment = self.commitment.decode(self.encoding) if self.commitment \
                else None
        offset = self.offset
        path = stringify_path(self.path, self.encoding)

        kw = {'uuid': uuid, 'timestamp': timestamp, 'created_at': created_at,
              'provider': provider, 'hash_type': hash_type,
              'encoding': encoding, 'security': security,
              'commitment': commitment, 'offset': offset,
              'path': path}

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
        provider = self.provider
        hash_type = self.hash_type
        encoding = self.encoding
        security = self.security
        commitment = self.commitment.decode(self.encoding) if self.commitment \
                else None
        offset = self.offset

        path = []
        for (sign, digest) in self.path:
            checksum = digest if isinstance(digest, str) else \
                    digest.decode(self.encoding)
            path.append([sign, checksum])

        return {
            'header': {
                'uuid': uuid,
                'timestamp': timestamp,
                'created_at': created_at,
                'provider': provider,
                'hash_type': hash_type,
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
        :rtype: Proof

        .. note:: Merkle-proofs are intended to be the output of proof generation
            mechanisms and not be manually constructed. Retrieval via
            deserialization might though have practical importance, so that given
            a proof ``p`` the following constructions are possible:

            >>> from pymerkle import Proof
            >>>
            >>> q = Proof.from_dict(p.serialize())
            >>> r = Proof.fromJSONText(p.toJSONText())

            or, more uniformly,

            >>> q = Proof.deserialize(p.serialize())
            >>> r = Proof.deserialize(p.toJSONText())
        """
        if isinstance(serialized, dict):
            return cls.from_dict(serialized)
        elif isinstance(serialized, str):
            return cls.fromJSONText(serialized)

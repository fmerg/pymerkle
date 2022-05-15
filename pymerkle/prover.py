"""
Provides the Merkle-proof object
"""

import os
import json
from time import time, ctime

from pymerkle.exceptions import NoPathException
from pymerkle.hashing import HashEngine
from pymerkle.utils import stringify_path, generate_uuid
from pymerkle.exceptions import UndecodableRecord


PROOF_TEMPLATE = """
    ----------------------------------- PROOF ------------------------------------

    uuid        : {uuid}

    timestamp   : {timestamp} ({created_at})
    provider    : {provider}

    hash-type   : {hash_type}
    encoding    : {encoding}
    raw_bytes   : {raw_bytes}
    security    : {security}

    {path}

    offset      : {offset}

    commitment  : {commitment}

    status      : {status}

    -------------------------------- END OF PROOF --------------------------------
"""


class MerkleProof:
    """
    :param provider: uuid of the provider tree
    :type provider: str
    :param hash_type: hash-type of the provider tree
    :type hash_type: str
    :param encoding: encoding type of the provider tree
    :type encoding: str
    :param raw_bytes: raw-bytes mode of the provider tree
    :type raw_bytes: bool
    :param security: security mode of the provider tree
    :type security: bool
    :param offset: starting position of hashing during verification
    :type offset: int
    :param path: path of hashes
    :type path: tuple of (+1/-1, bytes)


    .. note:: Merkle-proofs are intended to be the output of proof generation
        mechanisms and not be manually constructed. Construction via
        deserialization might though have practical importance, so that given
        a proof *p* the following constructions are possible:

        >>> from pymerkle import MerkleProof
        >>>
        >>> q = MerkleProof.from_dict(p.serialize())
        >>> r = MerkleProof.from_json(p.toJSONtext())

        or, more uniformly,

        >>> q = MerkleProof.deserialize(p.serialize())
        >>> r = MerkleProof.deserialize(p.toJSONtext())
    """

    def __init__(self, provider, hash_type, encoding, raw_bytes, security,
                 offset, path, uuid=None, timestamp=None, created_at=None,
                 commitment=None, status=None):
        self.uuid = uuid or generate_uuid()
        self.timestamp = timestamp or int(time())
        self.created_at = created_at or ctime()
        self.provider = provider
        self.hash_type = hash_type
        self.encoding = encoding
        self.raw_bytes = raw_bytes
        self.security = security
        self.commitment = commitment
        self.status = status
        self.offset = offset
        self.path = path

    @classmethod
    def from_dict(cls, proof):
        """
        :param proof: proof
        :type proof: dict
        """
        kw = {}
        header = proof['header']
        body = proof['body']
        kw.update(header)
        commitment = header.get('commitment', None)
        if commitment:
            kw['commitment'] = commitment.encode()
        kw['offset'] = body['offset']
        encoding = header['encoding']
        kw['path'] = tuple((
            pair[0],
            pair[1].encode(encoding)
        ) for pair in body['path'])

        return cls(**kw)

    @classmethod
    def from_json(cls, text):
        return cls.from_dict(json.loads(text))

    @classmethod
    def deserialize(cls, serialized):
        """Deserializes the provided JSON entity

        :params serialized: a Python dict or JSON text, assumed to be the
            serialization of a *MerkleProof* object
        :type: dict or str
        :rtype: MerkleProof
        """
        if isinstance(serialized, dict):
            return cls.from_dict(serialized)
        elif isinstance(serialized, str):
            return cls.from_json(serialized)

    def get_verification_params(self):
        """
        Parameters required for configuring the verification hashing machinery.

        :rtype: dict
        """
        return {'hash_type': self.hash_type, 'encoding': self.encoding,
                'raw_bytes': self.raw_bytes, 'security': self.security}

    def get_commitment(self):
        return self.commitment

    def compute_checksum(self):
        """
        Compute the hash value resulting from the included path of hashes.

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

        :param target: [optional] target hash to compare against. Defaults to
            the commitment included in the proof.
        :type target: bytes
        :returns: the verification result
        :rtype: bool
        """
        target = self.get_commitment() if target is None else target

        if self.offset == -1 and self.path == ():
            return False

        if target != self.compute_checksum():
            return False

        return True

    def __repr__(self):
        """
        .. warning:: Contrary to convention, the output of this method is not
            insertable into the *eval()* builtin Python function.
        """
        encoding = self.encoding

        return PROOF_TEMPLATE.format(
            uuid=self.uuid,
            timestamp=self.timestamp,
            created_at=self.created_at,
            provider=self.provider,
            hash_type=self.hash_type.upper().replace('_', ''),
            encoding=encoding.upper().replace('_', '-'),
            raw_bytes='TRUE' if self.raw_bytes else 'FALSE',
            security='ACTIVATED' if self.security else 'DEACTIVATED',
            commitment=self.commitment,
            offset=self.offset,
            path=stringify_path(self.path, self.encoding),
            status='UNVERIFIED' if self.status is None
            else 'VERIFIED' if self.status is True else 'INVALID')

    def serialize(self):
        """
        Returns a JSON dictionary with the proof's characteristics as key-value
        pairs.

        :rtype: dict
        """
        return MerkleProofSerialilzer().default(self)

    def toJSONtext(self):
        """
        Returns a JSON text with the proof's characteristics as key-value
        pairs.

        .. note:: This is the minimum required information for recostruction
            the tree from its serialization.

        :rtype: str
        """
        return json.dumps(self, cls=MerkleProofSerialilzer,
                          sort_keys=True, indent=4)


class MerkleProofSerialilzer(json.JSONEncoder):

    def default(self, obj):
        """
        """
        try:
            uuid = obj.uuid
            created_at = obj.created_at
            timestamp = obj.timestamp
            provider = obj.provider
            hash_type = obj.hash_type
            encoding = obj.encoding
            security = obj.security
            raw_bytes = obj.raw_bytes
            offset = obj.offset
            path = obj.path
            commitment = obj.commitment
            status = obj.status
        except AttributeError:
            return json.JSONEncoder.default(self, obj)

        return {
            'header': {
                'uuid': uuid,
                'timestamp': timestamp,
                'created_at': created_at,
                'provider': provider,
                'hash_type': hash_type,
                'encoding': encoding,
                'security': security,
                'raw_bytes': raw_bytes,
                'commitment': commitment.decode() if commitment else None,
                'status': status
            },
            'body': {
                'offset': offset,
                'path': [
                    [sign, digest if isinstance(
                        digest, str) else digest.decode()]
                    for (sign, digest) in path
                ]
            }
        }

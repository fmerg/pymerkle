"""Provides encryption and prover API of Merkle-trees
"""

import os
import json
from time import time, ctime
from tqdm import tqdm

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
    """Class for Merkle-proofs

    :param provider: uuid of the provider Merkle-tree
    :type provider: str
    :param hash_type: hash type of the provider Merkle-tree
    :type hash_type: str
    :param encoding: encoding type of the provider Merkle-tree
    :type encoding: str
    :param raw_bytes: raw-bytes mode of the provider Merkle-tree
    :type raw_bytes: bool
    :param security: security mode of the provider Merkle-tree
    :type security: bool
    :param offset: starting position of subsequent verification procedure
    :type offset: int
    :param path: path of signed hashes
    :type path: tuple of (+1/-1, bytes)

    Proofs are meant to be output of proof generation mechanisms and not
    manually constructed. MerkleProof construction via deserialization might though
    have practical importance, so that given a proof *p* the following
    constructions are possible:

    >>> from pymerkle import MerkleProof
    >>>
    >>> q = MerkleProof.from_dict(p.serialize())
    >>> r = MerkleProof.from_json(p.toJSONtext())

    or, more uniformly,

    >>> q = MerkleProof.deserialize(p.serialize())
    >>> r = MerkleProof.deserialize(p.toJSONtext())

    .. note:: This is a genuine replication, since deserializations will have
        the same uuid and timestamp as the original.

    :ivar header: (*dict*) contains the keys *uuid*, *timestamp*,
        *created_at*, *provider*, *hash_type*, *encoding*,
        *raw_bytes*, *security* and *status*
    :ivar body: (*dict*) Contains the keys *offset* and *path*
    """

    def __init__(self, provider, hash_type, encoding, raw_bytes, security,
                 offset, path, uuid=None, timestamp=None, created_at=None,
                 commitment=None, status=None):

        self.header = {
            'uuid': uuid or generate_uuid(),
            'timestamp': timestamp or int(time()),
            'created_at': created_at or ctime(),
            'provider': provider,
            'hash_type': hash_type,
            'encoding': encoding,
            'raw_bytes': raw_bytes,
            'security': security,
            'commitment': commitment,
            'status': status,
        }
        self.body = {
            'offset': offset,
            'path': path,
        }

    @classmethod
    def from_dict(cls, proof):
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
        """Extracts from the proof's header the fields required for configuring
        correctly the verifier's hashing machinery.

        :rtype: dict
        """
        header = self.header
        return {
            'hash_type': header['hash_type'],
            'encoding': header['encoding'],
            'raw_bytes': header['raw_bytes'],
            'security': header['security'],
        }

    def get_commitment(self):
        return self.header.get('commitment', None)

    def compute_checksum(self):
        """
        Compute the hash value resulting from the included path of hashes.

        :rtype: bytes
        """
        offset = self.body['offset']
        path = self.body['path']

        engine = HashEngine(**self.get_verification_params())
        checksum = engine.multi_hash(path, offset)

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

        offset = self.body['offset']
        path = self.body['path']

        if offset == -1 and path == ():
            return False

        if target != self.compute_checksum():
            return False

        return True

    def __repr__(self):
        """Sole purpose of this function is to display info
        about a proof by just invoking it at console

        .. warning:: Contrary to convention, the output of this implementation
            is not insertable into the *eval()* builtin Python function
        """
        header = self.header
        body = self.body
        encoding = header['encoding']

        return PROOF_TEMPLATE.format(
            uuid=header['uuid'],
            timestamp=header['timestamp'],
            created_at=header['created_at'],
            provider=header['provider'],
            hash_type=header['hash_type'].upper().replace('_', ''),
            encoding=header['encoding'].upper().replace('_', '-'),
            raw_bytes='TRUE' if header['raw_bytes'] else 'FALSE',
            security='ACTIVATED' if header['security'] else 'DEACTIVATED',
            commitment=header['commitment'].decode()
            if header['commitment'] else None,
            offset=body['offset'],
            path=stringify_path(body['path'], header['encoding']),
            status='UNVERIFIED' if header['status'] is None
            else 'VERIFIED' if header['status'] is True else 'INVALID')

    def serialize(self):
        """Returns a JSON entity with the proof's characteristics
        as key-value pairs.

        :rtype: dict
        """
        return MerkleProofSerialilzer().default(self)

    def toJSONtext(self):
        """Returns a JSON text with the proof's characteristics
        as key-value pairs.

        :rtype: str
        """
        return json.dumps(self, cls=MerkleProofSerialilzer,
                          sort_keys=True, indent=4)


class MerkleProofSerialilzer(json.JSONEncoder):
    """Used implicitly in the JSON serialization of proofs.
    """

    def default(self, obj):
        """Overrides the built-in method of JSON encoders.
        """
        try:
            uuid = obj.header['uuid']
            created_at = obj.header['created_at']
            timestamp = obj.header['timestamp']
            provider = obj.header['provider']
            hash_type = obj.header['hash_type']
            encoding = obj.header['encoding']
            security = obj.header['security']
            raw_bytes = obj.header['raw_bytes']
            offset = obj.body['offset']
            path = obj.body['path']
            commitment = obj.header['commitment']
            status = obj.header['status']
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

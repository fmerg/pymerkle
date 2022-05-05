"""Provides high-level prover interface for Merkle-trees
"""

from abc import ABCMeta, abstractmethod
import uuid
from time import time, ctime
import json
from pymerkle.exceptions import NoPathException
from pymerkle.serializers import ProofSerializer
from pymerkle.utils import stringify_path


class Prover(object, metaclass=ABCMeta):
    """High-level prover interface for Merkle-trees
    """

    @property
    @abstractmethod
    def length(self):
        """
        """

    @abstractmethod
    def find_index(self, checksum):
        """
        """

    @abstractmethod
    def multi_hash(self, signed_hashes, start):
        """
        """

    @abstractmethod
    def get_commitment(self):
        """
        """

    @abstractmethod
    def generate_audit_path(self, index):
        """
        """

    @abstractmethod
    def generate_consistency_path(self, sublength):
        """
        """

    def get_proof_params(self):
        return {
            'provider': self.uuid,
            'hash_type': self.hash_type,
            'encoding': self.encoding,
            'security': self.security,
            'raw_bytes': self.raw_bytes,
        }

    def generate_audit_proof(self, checksum, commit=False):
        """Response of the Merkle-tree to the request of providing an
        audit proof based upon the provided checksum

        :param checksum: Checksum which the requested proof is to be based upon
        :type checksum: bytes
        :rtype: MerkleProof
        """
        params = self.get_proof_params()
        commitment = self.get_commitment() if commit else None

        index = self.find_index(checksum)
        try:
            offset, path = self.generate_audit_path(index)
        except NoPathException:
            return MerkleProof(**params, commitment=commitment, offset=-1,
                               path=())

        return MerkleProof(**params, commitment=commitment, offset=offset,
                           path=path)

    def generate_consistency_proof(self, subhash, commit=False):
        """Response of the Merkle-tree to the request of providing a consistency
        proof for the acclaimed root-hash of some previous state

        :param subhash: acclaimed root-hash of some previous
                state of the Merkle-tree
        :type subhash: bytes
        :type subhash: bytes
        :rtype: MerkleProof

        """
        params = self.get_proof_params()
        commitment = self.get_commitment() if commit else None

        proof = MerkleProof(**params, commitment=commitment, offset=-1,
                            path=())
        for sublength in range(1, self.length + 1):
            try:
                offset, left_path, full_path = self.generate_consistency_path(
                    sublength)
            except NoPathException:
                pass
            else:
                if subhash == self.multi_hash(left_path, len(left_path) - 1):
                    proof = MerkleProof(**params, commitment=commitment,
                                        offset=offset, path=full_path)
                    break

        return proof


class MerkleProof(object):
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
    >>> q = MerkleProof(from_dict=p.serialize())
    >>> r = MerkleProof(from_json=p.toJSONtext())

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

    def __init__(self, **kwargs):
        """
        """
        header = {}
        body = {}
        if kwargs.get('from_dict'):
            input = kwargs['from_dict']
            header.update(input['header'])
            if header['commitment']:
                header['commitment'] = header['commitment'].encode()
            body['offset'] = input['body']['offset']
            body['path'] = tuple((
                pair[0],
                bytes(pair[1], header['encoding'])
            ) for pair in input['body']['path'])
        elif kwargs.get('from_json'):
            input = json.loads(kwargs['from_json'])
            header.update(input['header'])
            if header['commitment']:
                header['commitment'] = header['commitment'].encode()
            body['offset'] = input['body']['offset']
            body['path'] = tuple((
                pair[0],
                bytes(pair[1], header['encoding'])
            ) for pair in input['body']['path'])
        else:
            header.update({
                'uuid': str(uuid.uuid1()),
                'timestamp': int(time()),
                'created_at': ctime(),
                'provider': kwargs['provider'],
                'hash_type': kwargs['hash_type'],
                'encoding': kwargs['encoding'],
                'raw_bytes': kwargs['raw_bytes'],
                'security': kwargs['security'],
                'commitment': kwargs.get('commitment'),
                'status': None})
            body.update({
                'offset': kwargs['offset'],
                'path': kwargs['path']})
        self.header = header
        self.body = body

    @classmethod
    def deserialize(cls, serialized):
        """Deserializes the provided JSON entity

        :params serialized: a Python dict or JSON text, assumed to be the
            serialization of a *MerkleProof* object
        :type: dict or str
        :rtype: MerkleProof
        """
        kwargs = {}
        if isinstance(serialized, dict):
            kwargs.update({'from_dict': serialized})
        elif isinstance(serialized, str):
            kwargs.update({'from_json': serialized})

        return cls(**kwargs)

    def get_verification_params(self):
        """Extracts from the proof's header the fields required for configuring
        correctly the verifier's hashing machinery.

        :rtype: dict
        """
        header = self.header
        verification_params = dict({
            'hash_type': header['hash_type'],
            'encoding': header['encoding'],
            'raw_bytes': header['raw_bytes'],
            'security': header['security'],
        })

        return verification_params

    def __repr__(self):
        """Sole purpose of this function is to display info
        about a proof by just invoking it at console

        .. warning:: Contrary to convention, the output of this implementation
            is not insertable into the *eval()* builtin Python function
        """
        header = self.header
        body = self.body
        encoding = header['encoding']

        return '\n    ----------------------------------- PROOF ------------------------------------\
                \n\
                \n    uuid        : {uuid}\
                \n\
                \n    timestamp   : {timestamp} ({created_at})\
                \n    provider    : {provider}\
                \n\
                \n    hash-type   : {hash_type}\
                \n    encoding    : {encoding}\
                \n    raw_bytes   : {raw_bytes}\
                \n    security    : {security}\
                \n\
                \n    offset : {offset}\
                \n    path  :\
                \n    {path}\
                \n\
                \n    commitment  : {commitment}\
                \n\
                \n    status      : {status}\
                \n\
                \n    -------------------------------- END OF PROOF --------------------------------\
                \n'.format(
            uuid=header['uuid'],
            timestamp=header['timestamp'],
            created_at=header['created_at'],
            provider=header['provider'],
            hash_type=header['hash_type'].upper().replace('_', '-'),
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
        return ProofSerializer().default(self)

    def to_json_str(self):
        """Returns a JSON text with the proof's characteristics
        as key-value pairs.

        :rtype: str
        """
        return json.dumps(self, cls=ProofSerializer, sort_keys=True, indent=4)

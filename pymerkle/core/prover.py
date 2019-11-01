"""
Provides high-level prover interface for Merkle-trees
"""

from abc import ABCMeta, abstractmethod
import uuid
from time import time, ctime
import json
from pymerkle.exceptions import (NoPathException, InvalidChallengeError,)
from pymerkle.serializers import ProofSerializer
from pymerkle.utils import stringify_path


class Prover(object, metaclass=ABCMeta):
    """
    High-level prover interface for Merkle-trees
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
    def audit_path(self, index):
        """
        """

    @abstractmethod
    def multi_hash(self, signed_hashes, start):
        """
        """

    @abstractmethod
    def consistency_path(self, sublength):
        """
        """

    @abstractmethod
    def get_commitment(self):
        """
        """

    def merkleProof(self, challenge, commit=True):
        """
        Response of the Merkle-tree to the request of providing a
        Merkle-proof based upon the provided challenge

        :type challenge: dict
        :rtype: Proof

        .. warning:: Provided challenge must be of the form

            ``{'checksum': <str> or <bytes>}`` or ``{'subhash': <str> or <bytes>}``,

            otherwise an ``InvalidChallengeError`` is raised.
        """
        keys = set(challenge.keys())
        if keys == {'checksum'}:
            checksum = challenge['checksum']
            return self.auditProof(checksum, commit=commit)
        elif keys == {'subhash'}:
            subhash = challenge['subhash']
            return self.consistencyProof(subhash, commit=commit)
        raise InvalidChallengeError


    def auditProof(self, checksum, commit=False):
        """
        Response of the Merkle-tree to the request of providing an
        audit proof based upon the provided checksum

        :param checksum: Checksum which the requested proof is to be based upon
        :type checksum: str or bytes
        :rtype: Proof

        :raises InvalidChallengeError: if the provided argument's type
            is not as prescribed
        """
        if isinstance(checksum, str):
            checksum = checksum.encode()
        elif not isinstance(checksum, bytes):
            raise InvalidChallengeError

        index = self.find_index(checksum)
        commitment = self.get_commitment() if commit else None

        try:
            proof_index, audit_path = self.audit_path(index)
        except NoPathException:
            proof = Proof(
                provider=self.uuid,
                hash_type=self.hash_type,
                encoding=self.encoding,
                security=self.security,
                raw_bytes=self.raw_bytes,
                commitment=commitment,
                proof_index=-1,
                proof_path=())
        else:
            proof = Proof(
                provider=self.uuid,
                hash_type=self.hash_type,
                encoding=self.encoding,
                security=self.security,
                raw_bytes=self.raw_bytes,
                commitment=commitment,
                proof_index=proof_index,
                proof_path=audit_path)

        return proof


    def consistencyProof(self, subhash, commit=False):
        """
        Response of the Merkle-tree to the request of providing a consistency
        proof for the acclaimed root-hash of some previous state

        :param subhash: acclaimed root-hash of some previous
                state of the Merkle-tree
        :type subhash: str or bytes
        :type subhash: bytes
        :rtype: Proof

        :raises InvalidChallengeError: if type of *subhash* is not as prescribed
        """
        if isinstance(subhash, str):
            subhash = subhash.encode()
        elif not isinstance(subhash, bytes):
            raise InvalidChallengeError

        commitment = self.get_commitment() if commit is True else None

        proof = Proof(
            provider=self.uuid,
            hash_type=self.hash_type,
            encoding=self.encoding,
            raw_bytes=self.raw_bytes,
            security=self.security,
            commitment=commitment,
            proof_index=-1,
            proof_path=())

        for sublength in range(1, self.length + 1):
            try:
                proof_index, left_path, full_path = self.consistency_path(sublength)
            except NoPathException:
                pass
            else:
                if subhash == self.multi_hash(left_path, len(left_path) - 1):
                    proof = Proof(
                        provider=self.uuid,
                        hash_type=self.hash_type,
                        encoding=self.encoding,
                        raw_bytes=self.raw_bytes,
                        security=self.security,
                        commitment=commitment,
                        proof_index=proof_index,
                        proof_path=full_path)
                    break

        return proof


class Proof(object):
    """
    Class for Merkle-proofs

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
    :param proof_index: starting position of subsequent validation procedure
    :type proof_index: int
    :param proof_path: path of signed hashes
    :type proof_path: tuple of (+1/-1, bytes)

    Proofs are meant to be output of proof generation mechanisms and not
    manually constructed. Proof construction via deserialization might though
    have practical importance, so that given a proof *p* the following
    constructions are possible:

    >>> from pymerkle import Proof
    >>>
    >>> q = Proof(from_dict=p.serialize())
    >>> r = Proof(from_json=p.toJSONtext())

    or, more uniformly,

    >>> q = Proof.deserialize(p.serialize())
    >>> r = Proof.deserialize(p.toJSONtext())

    .. note:: This is a genuine replication, since deserializations will have
        the same uuid and timestamp as the original.

    :ivar header: (*dict*) contains the keys *uuid*, *timestamp*,
        *creation_moment*, *provider*, *hash_type*, *encoding*,
        *raw_bytes*, *security* and *status*
    :ivar body: (*dict*) Contains the keys *proof_index* and *proof_path*
    """

    def __init__(self, **kwargs):
        """
        """
        header = {}
        body = {}
        if kwargs.get('from_dict'):                             # from json dict
            input = kwargs['from_dict']
            header.update(input['header'])
            if header['commitment']:
                header['commitment'] = header['commitment'].encode()
            body['proof_index'] = input['body']['proof_index']
            body['proof_path'] = tuple((
                pair[0],
                bytes(pair[1], header['encoding'])
            ) for pair in input['body']['proof_path'])
        elif kwargs.get('from_json'):                           # from json text
            input = json.loads(kwargs['from_json'])
            header.update(input['header'])
            if header['commitment']:
                header['commitment'] = header['commitment'].encode()
            body['proof_index'] = input['body']['proof_index']
            body['proof_path'] = tuple((
                pair[0],
                bytes(pair[1], header['encoding'])
            ) for pair in input['body']['proof_path'])
        else:                                                  # multiple kwargs
            header.update({
                'uuid': str(uuid.uuid1()),
                'timestamp': int(time()),
                'creation_moment': ctime(),
                'provider': kwargs['provider'],
                'hash_type': kwargs['hash_type'],
                'encoding': kwargs['encoding'],
                'raw_bytes': kwargs['raw_bytes'],
                'security': kwargs['security'],
                'commitment': kwargs.get('commitment'),
                'status': None})
            body.update({
                'proof_index': kwargs['proof_index'],
                'proof_path': kwargs['proof_path']})
        self.header = header
        self.body = body


    @classmethod
    def deserialize(cls, serialized):
        """
        Deserializes the provided JSON entity

        :params serialized: a Python dict or JSON text, assumed to be the
            serialization of a *Proof* object
        :type: dict or str
        :rtype: Proof
        """
        kwargs = {}
        if isinstance(serialized, dict):
            kwargs.update({'from_dict': serialized})
        elif isinstance(serialized, str):
            kwargs.update({'from_json': serialized})
        return cls(**kwargs)


    def get_validation_params(self):
        """
        Extracts from the proof's header the fields required for configuring
        correctly the validator's hashing machinery.

        :rtype: dict
        """
        header = self.header
        validation_params = dict({
            'hash_type': header['hash_type'],
            'encoding': header['encoding'],
            'raw_bytes': header['raw_bytes'],
            'security': header['security'],
        })
        return validation_params


    def __repr__(self):
        """
        Overrides the default implementation.

        Sole purpose of this function is to display info
        about a proof by just invoking it at console

        .. warning:: Contrary to convention, the output of this implementation
            is not insertible into the *eval()* builtin Python function
        """
        header = self.header
        body = self.body
        encoding = header['encoding']

        return '\n    ----------------------------------- PROOF ------------------------------------\
                \n\
                \n    uuid        : {uuid}\
                \n\
                \n    timestamp   : {timestamp} ({creation_moment})\
                \n    provider    : {provider}\
                \n\
                \n    hash-type   : {hash_type}\
                \n    encoding    : {encoding}\
                \n    raw_bytes   : {raw_bytes}\
                \n    security    : {security}\
                \n\
                \n    proof-index : {proof_index}\
                \n    proof-path  :\
                \n    {proof_path}\
                \n\
                \n    commitment  : {commitment}\
                \n\
                \n    status      : {status}\
                \n\
                \n    -------------------------------- END OF PROOF --------------------------------\
                \n'.format(
                    uuid=header['uuid'],
                    timestamp=header['timestamp'],
                    creation_moment=header['creation_moment'],
                    provider=header['provider'],
                    hash_type=header['hash_type'].upper().replace('_', '-'),
                    encoding=header['encoding'].upper().replace('_', '-'),
                    raw_bytes='TRUE' if header['raw_bytes'] else 'FALSE',
                    security='ACTIVATED' if header['security'] else 'DEACTIVATED',
                    commitment=header['commitment'].decode() \
                    if header['commitment'] else None,
                    proof_index=body['proof_index'],
                    proof_path=stringify_path(body['proof_path'], header['encoding']),
                    status='UNVALIDATED' if header['status'] is None \
                    else 'VALID' if header['status'] is True else 'NON VALID')


# Serialization

    def serialize(self):
        """
        Returns a JSON entity with the proof's characteristics
        as key-value pairs.

        :rtype: dict
        """
        return ProofSerializer().default(self)

    def toJSONString(self):
        """
        Returns a JSON text with the proof's characteristics
        as key-value pairs.

        :rtype: str
        """
        return json.dumps(self, cls=ProofSerializer, sort_keys=True, indent=4)

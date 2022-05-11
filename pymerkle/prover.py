"""Provides encryption and prover API of Merkle-trees
"""

import os
import json
import mmap
import contextlib
import json
from abc import ABCMeta, abstractmethod
from time import time, ctime
from tqdm import tqdm

from pymerkle.exceptions import NoPathException
from pymerkle.utils import stringify_path, generate_uuid
from pymerkle.exceptions import UndecodableRecord

abspath = os.path.abspath


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


class Prover(metaclass=ABCMeta):
    """Encryption and prover API of Merkle-trees
    """

    @property
    @abstractmethod
    def length(self):
        """
        """

    @abstractmethod
    def _detect_offset(self, checksum):
        """
        """

    @abstractmethod
    def multi_hash(self, path, offset):
        """
        """

    @abstractmethod
    def update(self, record):
        """
        """

    @abstractmethod
    def get_root_hash(self):
        """
        """

    @abstractmethod
    def generate_audit_path(self, offset):
        """
        """

    @abstractmethod
    def generate_consistency_path(self, sublength):
        """
        """

    def create_proof(self, offset, path, commit=False):
        commitment = self.get_root_hash() if commit else None
        proof = MerkleProof(provider=self.uuid,
                            hash_type=self.hash_type,
                            encoding=self.encoding,
                            security=self.security,
                            raw_bytes=self.raw_bytes,
                            commitment=commitment,
                            offset=offset,
                            path=path)
        return proof

    def encrypt(self, record):
        """Updates the Merkle-tree by storing the checksum of the provided record
        into a newly-created leaf.

        :param record: Record whose checksum is to be stored into a new leaf
        :type record: str or bytes

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided record is out of its configured encoding type
        """
        try:
            self.update(record)
        except UndecodableRecord:
            raise

    def encrypt_file_content(self, filepath):
        """Encrypts the provided file as a single new leaf into the Merkle-tree.

        Updates the Merkle-tree with *one* newly-created leaf storing the
        checksum of the provided file's content.

        :param filepath: Relative path of the file under encryption with
                respect to the current working directory
        :type filepath: str

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided files contains sequences out of the tree's
            configured encoding type
        """
        with open(abspath(filepath), mode='r') as f:
            with contextlib.closing(
                mmap.mmap(
                    f.fileno(),
                    0,
                    access=mmap.ACCESS_READ
                )
            ) as buff:
                try:
                    self.update(buff.read())
                except UndecodableRecord:
                    raise

    def encrypt_file_per_line(self, filepath):
        """Per line encryption of the provided file into the Merkle-tree.

        Successively updates the tree with each line of the provided
        file in respective order

        :param filepath: Relative path of the file under enryption with
            respect to the current working directory
        :type filepath: str

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided files contains sequences out of the tree's
            configured encoding type
        """
        absolute_filepath = abspath(filepath)
        with open(absolute_filepath, mode='r') as f:
            buff = mmap.mmap(
                f.fileno(),
                0,
                access=mmap.ACCESS_READ
            )

        # Extract lines
        records = []
        readline = buff.readline
        append = records.append
        if not self.raw_bytes:
            # Check that no line of the provided file is outside
            # the tree's encoding type and discard otherwise
            encoding = self.encoding
            while True:
                record = readline()
                if not record:
                    break
                try:
                    record = record.decode(encoding)
                except UnicodeDecodeError as err:
                    raise UndecodableRecord(err)
                append(record)
        else:
            # No need to check anything, just load all lines
            while True:
                record = readline()
                if not record:
                    break
                append(record)

        # Perform line by line encryption
        tqdm.write('')
        update = self.update
        for record in tqdm(
                records, desc='Encrypting file per line', total=len(records)):
            update(record)
        tqdm.write('Encryption complete\n')

    def generate_audit_proof(self, checksum, commit=False):
        """Response of the Merkle-tree to the request of providing an
        audit proof based upon the provided checksum

        :param checksum: checksum which the requested proof should be based
            upon
        :type checksum: bytes
        :rtype: MerkleProof
        """
        offset = -1
        path = ()
        offset = self._detect_offset(checksum)
        try:
            offset, path = self.generate_audit_path(offset)
        except NoPathException:
            pass

        proof = self.create_proof(offset, path, commit=commit)
        return proof

    def generate_consistency_proof(self, subhash, commit=False):
        """Response of the Merkle-tree to the request of providing a consistency
        proof for the acclaimed root-hash of some previous state

        :param subhash: acclaimed root-hash of some previous
                state of the Merkle-tree
        :type subhash: bytes
        :rtype: MerkleProof

        """
        offset = -1
        path = ()
        for sublength in range(1, self.length + 1):
            try:
                _offset, left_path, _path = self.generate_consistency_path(
                    sublength)
            except NoPathException:
                continue
            if subhash == self.multi_hash(left_path, len(left_path) - 1):
                offset = _offset
                path = _path
                break

        proof = self.create_proof(offset, path, commit=commit)
        return proof


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

    def get_root_hash(self):
        return self.header.get('commitment', None)

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

from hmac import compare_digest
from typing import Any

from pymerkle.hasher import MerkleHasher


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


def verify_inclusion(base: bytes, root: bytes, proof: 'MerkleProof') -> None:
    """
    Verifies the provided Merkle-proof of inclusion against the provided leaf
    hash and tree state.

    :param base: acclaimed leaf hash
    :type base: bytes
    :param root: acclaimed root hash
    :type root: bytes
    :param proof: proof of inclusion
    :type proof: MerkleProof
    :raises InvalidProof: if the proof is found invalid
    """
    if not compare_digest(proof.path[0], base):
        raise InvalidProof('Base hash does not match')

    if not compare_digest(proof.resolve(), root):
        raise InvalidProof('State does not match')


def verify_consistency(state1: bytes, state2: bytes, proof: 'MerkleProof') -> None:
    """
    Verifies the provided Merkle-proof of consistency against the given states.

    :param state1: acclaimed prior state
    :type state1: bytes
    :param state2: acclaimed later state
    :type state2: bytes
    :raises InvalidProof: if the proof is found invalid
    :param proof: proof of consistency
    :type proof: MerkleProof
    """
    if not compare_digest(proof.retrieve_prior_state(), state1):
        raise InvalidProof('Prior state does not match')

    if not compare_digest(proof.resolve(), state2):
        raise InvalidProof('Later state does not match')


class MerkleProof:
    """
    Verifiable Merkle-proof object

    :param algorithm: hash algorithm to be applied during state resolution
    :type algorithm: str
    :param security: resistance against 2-nd preimage attack indicator
    :type security: bool
    :param size: tree size corresponding to requested state
    :type size: int
    :param rule: specifies parenthetization of hashes during state
        resolution
    :type rule: list[int]
    :param subset: indicates subset of hashes during prior state resolution
        (makes sense only for consistency proofs)
    :type subset: list[int]
    :param path: path of hashes
    :type path: list[bytes]
    """

    algorithm: str
    security: bool
    size: int
    rule: list[int]
    subset: list[int]
    path: list[bytes]
    hasher: MerkleHasher

    def __init__(self, algorithm: str, security: bool, size: int, rule: list[int], subset: list[int], path: list[bytes]) -> None:
        self.algorithm = algorithm
        self.security = security
        self.size = size
        self.rule = rule
        self.subset = subset
        self.path = path
        self.hasher = MerkleHasher(**self.get_metadata())

    def get_metadata(self) -> dict[str, Any]:
        """
        Returns the information needed to configure the hashing machinery.

        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'security': self.security,
                'size': self.size}

    def serialize(self) -> dict[str, Any]:
        """
        Returns the JSON representation of the verifiable object.

        :rtype: dict
        """
        return {
            'metadata': {
                'algorithm': self.algorithm,
                'security': self.security,
                'size': self.size,
            },
            'rule': self.rule,
            'subset': self.subset,
            'path': [digest.hex() for digest in self.path]
        }

    @classmethod
    def deserialize(cls, data: dict) -> 'MerkleProof':
        """
        :param data:
        :type data: dict
        :rtype: MerkleProof
        """
        metadata = data['metadata']
        rule = data['rule']
        subset = data['subset']
        path: list[bytes] = [bytes.fromhex(checksum)
                             for checksum in data['path']]

        return cls(**metadata, rule=rule, subset=subset, path=path)

    def retrieve_prior_state(self) -> bytes:
        """
        Computes the acclaimed prior state as specified by the included path of
        hashes.

        .. note:: Makes sense only for consistency proofs.

        :rtype: bytes
        """
        subpath: list[bytes] = [digest for (mask, digest) in zip(self.subset, self.path) if
                                mask]

        if not subpath:
            return self.hasher.hash_empty()

        result: bytes = subpath[0]
        index: int = 0
        hash_pair = self.hasher.hash_pair
        while index < len(subpath) - 1:
            result = hash_pair(buff1=subpath[index + 1], buff2=result)
            index += 1

        return result

    def resolve(self) -> bytes:
        """
        Computes the target hash of the included path of hashes.

        :rtype: bytes
        """
        path: list[tuple[int, bytes]] = list(zip(self.rule, self.path))

        if not path:
            return self.hasher.hash_empty()

        bit, result = path[0]
        index: int = 0
        hash_pair = self.hasher.hash_pair
        while index < len(path) - 1:
            next_bit, digest = path[index + 1]

            if bit == 0:
                result = hash_pair(result, digest)
            elif bit == 1:
                result = hash_pair(digest, result)
            else:
                raise ValueError('Invalid bit found')

            bit = next_bit
            index += 1

        return result

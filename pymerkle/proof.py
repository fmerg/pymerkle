import os
import json
from hmac import compare_digest

from pymerkle.hasher import MerkleHasher
from pymerkle.utils import log2


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


def _digests_match(digest1, digest2):
    """
    Constant-time comparison of digests that treats values of incompatible
    type as non-matching instead of raising.

    :type digest1: bytes
    :type digest2: bytes
    :rtype: bool
    """
    try:
        return compare_digest(digest1, digest2)
    except TypeError:
        return False


def verify_inclusion(base, root, proof):
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
    if not proof.path or not _digests_match(proof.path[0], base):
        raise InvalidProof('Base hash does not match')

    if not _digests_match(proof.resolve(), root):
        raise InvalidProof('State does not match')


def _consistency_structure(size1, size2):
    """
    Computes the rule and subset of a well-formed consistency proof between
    the states corresponding to the provided sizes, independently of the
    proof under verification.

    :param size1: number of leaves for prior state
    :type size1: int
    :param size2: number of leaves for later state
    :type size2: int
    :rtype: (list[int], list[int])
    """
    offset, limit, bit = size1, size2, 0
    bits, masks = [], []
    while not offset == limit and not (offset == 0 and limit == 1):
        k = 1 << log2(limit)
        if k == limit:
            k >>= 1

        bits += [bit]
        if offset < k:
            masks += [0]
            limit = k
            bit = 0
        else:
            masks += [1]
            offset -= k
            limit -= k
            bit = 1

    mask = int(offset == limit)

    return [bit] + bits[::-1], [mask] + masks[::-1]


def verify_consistency(state1, state2, proof, size1=None, size2=None):
    """
    Verifies the provided Merkle-proof of consistency against the given states.

    .. note:: The structure of the proof is recomputed from the sizes it
        claims and must match exactly. Pass *size1* and *size2* to also
        ensure that these are the sizes of the states under consideration.

    :param state1: acclaimed prior state
    :type state1: bytes
    :param state2: acclaimed later state
    :type state2: bytes
    :param proof: proof of consistency
    :type proof: MerkleProof
    :param size1: [optional] expected number of leaves for prior state
    :type size1: int
    :param size2: [optional] expected number of leaves for later state
    :type size2: int
    :raises InvalidProof: if the proof is found invalid
    """
    prior_size = proof.prior_size
    if not (isinstance(prior_size, int) and isinstance(proof.size, int)
            and 0 < prior_size <= proof.size):
        raise InvalidProof('Invalid sizes')

    if size1 is not None and prior_size != size1:
        raise InvalidProof('Prior size does not match')

    if size2 is not None and proof.size != size2:
        raise InvalidProof('Later size does not match')

    rule, subset = _consistency_structure(prior_size, proof.size)
    if proof.rule != rule or proof.subset != subset or \
            len(proof.path) != len(rule):
        raise InvalidProof('Invalid proof structure')

    if not _digests_match(proof.retrieve_prior_state(), state1):
        raise InvalidProof('Prior state does not match')

    if not _digests_match(proof.resolve(), state2):
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
    :param prior_size: [optional] tree size corresponding to prior state
        (makes sense only for consistency proofs)
    :type prior_size: int
    """

    def __init__(self, algorithm, security, size, rule, subset, path,
            prior_size=None):
        self.algorithm = algorithm
        self.security = security
        self.size = size
        self.rule = rule
        self.subset = subset
        self.path = path
        self.prior_size = prior_size
        self.hasher = MerkleHasher(**self.get_metadata())


    def get_metadata(self):
        """
        Returns the information needed to configure the hashing machinery.

        :rtype: dict
        """
        metadata = {'algorithm': self.algorithm, 'security': self.security,
                    'size': self.size}

        if self.prior_size is not None:
            metadata['prior_size'] = self.prior_size

        return metadata

    def serialize(self):
        """
        Returns the JSON representation of the verifiable object.

        :rtype: dict
        """
        return {
            'metadata': self.get_metadata(),
            'rule': self.rule,
            'subset': self.subset,
            'path': [digest.hex() for digest in self.path]
        }


    @classmethod
    def deserialize(cls, data):
        """
        :param data:
        :type data: dict
        :rtype: MerkleProof
        """
        metadata = data['metadata']
        rule = data['rule']
        subset = data['subset']
        path = [bytes.fromhex(checksum) for checksum in data['path']]

        return cls(**metadata, rule=rule, subset=subset, path=path)


    def retrieve_prior_state(self):
        """
        Computes the acclaimed prior state as specified by the included path of
        hashes.

        .. note:: Makes sense only for consistency proofs.

        :rtype: bytes
        """
        subpath = [digest for (mask, digest) in zip(self.subset, self.path) if
            mask]

        if not subpath:
            return self.hasher.hash_empty()

        result = subpath[0]
        index = 0
        hash_pair = self.hasher.hash_pair
        while index < len(subpath) - 1:
            result = hash_pair(subpath[index + 1], result)
            index += 1

        return result


    def resolve(self):
        """
        Computes the target hash of the included path of hashes.

        :rtype: bytes
        """
        path = list(zip(self.rule, self.path))

        if not path:
            return self.hasher.hash_empty()

        bit, result = path[0]
        index = 0
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

from hmac import compare_digest

from pymerkle.hasher import MerkleHasher
from pymerkle.layout import inclusion_layout, consistency_layout


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


# Upper bound for tree sizes accepted upon verification. Well-formed proofs
# against such trees have paths of at most 2 * 64 hashes.
MAX_SIZE = 1 << 64
MAX_PATH = 2 * 64


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


def _check_hashing(proof, algorithm, security):
    """
    Ensures that the proof is resolved with the hashing configuration expected
    by the verifier and that its path consists of digests of proper length.

    :param proof: proof under verification
    :type proof: MerkleProof
    :param algorithm: expected hash algorithm, or *None* to accept the one
        specified by the proof
    :type algorithm: str
    :param security: expected resistance against second-preimage attack
    :type security: bool
    :raises InvalidProof: if the proof does not comply
    """
    if bool(proof.security) != bool(security):
        raise InvalidProof('Security mode does not match')

    if algorithm is not None and \
            algorithm.lower().replace('-', '_') != proof.hasher.algorithm:
        raise InvalidProof('Hash algorithm does not match')

    digest_size = proof.hasher.hashfunc().digest_size
    for digest in proof.path:
        if not isinstance(digest, bytes) or len(digest) != digest_size:
            raise InvalidProof('Invalid digest found in path')


def verify_inclusion(base, root, proof, index=None, size=None,
        algorithm=None, security=True):
    """
    Verifies the provided Merkle-proof of inclusion against the provided leaf
    hash and tree state.

    .. note:: The structure of the proof is recomputed from the leaf index
        and size it claims and must match exactly. Pass *index* and *size*
        to also ensure that these are the position of the leaf and the size
        of the state under consideration.

    :param base: acclaimed leaf hash
    :type base: bytes
    :param root: acclaimed root hash
    :type root: bytes
    :param proof: proof of inclusion
    :type proof: MerkleProof
    :param index: [optional] expected leaf index counting from one
    :type index: int
    :param size: [optional] expected number of leaves
    :type size: int
    :param algorithm: [optional] expected hash algorithm. Defaults to the one
        specified by the proof.
    :type algorithm: str
    :param security: [optional] expected resistance against second-preimage
        attack. Defaults to *True*.
    :type security: bool
    :raises InvalidProof: if the proof is found invalid
    """
    if not (isinstance(proof.index, int) and isinstance(proof.size, int)
            and 0 < proof.index <= proof.size < MAX_SIZE):
        raise InvalidProof('Invalid index or size')

    if index is not None and proof.index != index:
        raise InvalidProof('Index does not match')

    if size is not None and proof.size != size:
        raise InvalidProof('Size does not match')

    rule, _ = inclusion_layout(proof.index - 1, proof.size)
    if proof.rule != rule or proof.subset != [] or \
            not isinstance(proof.path, list) or \
            len(proof.path) != len(rule):
        raise InvalidProof('Invalid proof structure')

    _check_hashing(proof, algorithm, security)

    if not _digests_match(proof.path[0], base):
        raise InvalidProof('Base hash does not match')

    if not _digests_match(proof.resolve(), root):
        raise InvalidProof('State does not match')


def verify_consistency(state1, state2, proof, size1=None, size2=None,
        algorithm=None, security=True):
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
    :param algorithm: [optional] expected hash algorithm. Defaults to the one
        specified by the proof.
    :type algorithm: str
    :param security: [optional] expected resistance against second-preimage
        attack. Defaults to *True*.
    :type security: bool
    :raises InvalidProof: if the proof is found invalid
    """
    prior_size = proof.prior_size
    if not (isinstance(prior_size, int) and isinstance(proof.size, int)
            and 0 < prior_size <= proof.size < MAX_SIZE):
        raise InvalidProof('Invalid sizes')

    if size1 is not None and prior_size != size1:
        raise InvalidProof('Prior size does not match')

    if size2 is not None and proof.size != size2:
        raise InvalidProof('Later size does not match')

    rule, subset, _ = consistency_layout(prior_size, proof.size)
    if proof.rule != rule or proof.subset != subset or \
            not isinstance(proof.path, list) or \
            len(proof.path) != len(rule):
        raise InvalidProof('Invalid proof structure')

    _check_hashing(proof, algorithm, security)

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
    :param index: [optional] leaf index counting from one (makes sense only
        for inclusion proofs)
    :type index: int
    :param prior_size: [optional] tree size corresponding to prior state
        (makes sense only for consistency proofs)
    :type prior_size: int
    """

    def __init__(self, algorithm, security, size, rule, subset, path,
            index=None, prior_size=None):
        self.algorithm = algorithm
        self.security = security
        self.size = size
        self.rule = rule
        self.subset = subset
        self.path = path
        self.index = index
        self.prior_size = prior_size
        self.hasher = MerkleHasher(algorithm, security)


    def get_metadata(self):
        """
        Returns the parameters of the proof.

        :rtype: dict
        """
        metadata = {'algorithm': self.algorithm, 'security': self.security,
                    'size': self.size}

        if self.index is not None:
            metadata['index'] = self.index

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
        :raises InvalidProof: if the provided data are malformed
        """
        try:
            metadata = data['metadata']
            rule = data['rule']
            subset = data['subset']
            if len(data['path']) > MAX_PATH:
                raise InvalidProof('Path too long')
            path = [bytes.fromhex(checksum) for checksum in data['path']]

            return cls(**metadata, rule=rule, subset=subset, path=path)
        except (KeyError, TypeError, ValueError, AttributeError) as err:
            raise InvalidProof('Malformed proof') from err


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

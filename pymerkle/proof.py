from hmac import compare_digest

from pymerkle.hasher import MerkleHasher


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


# Upper bound for tree sizes accepted upon verification. Well-formed proofs
# against such trees have paths of at most 2 * 64 hashes.
MAX_SIZE = 1 << 64
MAX_PATH = 2 * 64


def _digests_match(lhs, rhs):
    """
    Constant-time comparison of digests that treats values of incompatible
    type as non-matching instead of raising.

    :type lhs: bytes
    :type rhs: bytes
    :rtype: bool
    """
    try:
        return compare_digest(lhs, rhs)
    except TypeError:
        return False


def verify_inclusion(base, root, proof, index=None, size=None,
        algorithm=None, security=True):
    """
    Verifies the provided Merkle-proof of inclusion against the provided leaf
    hash and tree state.

    .. note:: Equivalent to ``proof.verify(base, root, ...)`` after ensuring
        that the provided proof is an inclusion proof. See
        ``InclusionProof.verify`` for the parameters.

    :type proof: InclusionProof
    :raises InvalidProof: if the proof is found invalid
    """
    if not isinstance(proof, InclusionProof):
        raise InvalidProof('Not an inclusion proof')

    proof.verify(base, root, index=index, size=size, algorithm=algorithm,
        security=security)


def verify_consistency(prior_state, later_state, proof, prior_size=None,
        later_size=None, algorithm=None, security=True):
    """
    Verifies the provided Merkle-proof of consistency against the given states.

    .. note:: Equivalent to ``proof.verify(prior_state, later_state, ...)``
        after ensuring that the provided proof is a consistency proof. See
        ``ConsistencyProof.verify`` for the parameters.

    :type proof: ConsistencyProof
    :raises InvalidProof: if the proof is found invalid
    """
    if not isinstance(proof, ConsistencyProof):
        raise InvalidProof('Not a consistency proof')

    proof.verify(prior_state, later_state, prior_size=prior_size,
        later_size=later_size, algorithm=algorithm, security=security)


class MerkleProof:
    """
    Base class of verifiable Merkle-proofs.

    :param algorithm: hash algorithm to be applied during state resolution
    :type algorithm: str
    :param security: resistance against 2-nd preimage attack indicator
    :type security: bool
    :param size: tree size corresponding to requested state
    :type size: int
    :param rule: specifies parenthetization of hashes during state
        resolution
    :type rule: list[int]
    :param path: path of hashes
    :type path: list[bytes]
    """

    kind = None

    def __init__(self, algorithm, security, size, rule, path):
        self.algorithm = algorithm
        self.security = security
        self.size = size
        self.rule = rule
        self.path = path
        self.hasher = MerkleHasher(algorithm, security)


    def get_metadata(self):
        """
        Returns the parameters of the proof.

        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'security': self.security,
                'size': self.size}


    def serialize(self):
        """
        Returns the JSON representation of the verifiable object.

        :rtype: dict
        """
        return {
            'type': self.kind,
            'metadata': self.get_metadata(),
            'rule': self.rule,
            'path': [digest.hex() for digest in self.path]
        }


    @classmethod
    def deserialize(cls, data):
        """
        Retrieves the proof from its JSON representation. Called on the base
        class, returns a proof of the serialized type; called on a subclass,
        additionally ensures that the serialized proof is of that type.

        :param data:
        :type data: dict
        :rtype: MerkleProof
        :raises InvalidProof: if the provided data are malformed or of
            unexpected type
        """
        try:
            proof_cls = _PROOF_TYPES[data['type']]
            if not issubclass(proof_cls, cls):
                raise InvalidProof('Unexpected proof type')

            if len(data['path']) > MAX_PATH:
                raise InvalidProof('Path too long')
            path = [bytes.fromhex(hexdigest) for hexdigest in data['path']]

            return proof_cls._from_data(data, path)
        except (KeyError, TypeError, ValueError, AttributeError) as err:
            raise InvalidProof('Malformed proof') from err


    def compute_root(self):
        """
        Computes the target hash of the included path of hashes.

        :rtype: bytes
        """
        if not self.rule or not self.path:
            return self.hasher.hash_empty()

        hash_pair = self.hasher.hash_pair

        result = self.path[0]
        for (bit, digest) in zip(self.rule, self.path[1:]):
            if bit == 0:
                result = hash_pair(result, digest)
            elif bit == 1:
                result = hash_pair(digest, result)
            else:
                raise ValueError('Invalid bit found')

        return result


    def _check_rule(self, rule):
        """
        Ensures that the proof has the provided rule and a path of matching
        length.

        :raises InvalidProof: if the proof does not comply
        """
        if self.rule != rule or not isinstance(self.path, list) or \
                len(self.path) != len(rule):
            raise InvalidProof('Invalid proof structure')


    def _check_hashing(self, algorithm, security):
        """
        Ensures that the proof is resolved with the hashing configuration
        expected by the verifier and that its path consists of digests of
        proper length.

        :param algorithm: expected hash algorithm, or *None* to accept the
            one specified by the proof
        :type algorithm: str
        :param security: expected resistance against second-preimage attack
        :type security: bool
        :raises InvalidProof: if the proof does not comply
        """
        if bool(self.security) != bool(security):
            raise InvalidProof('Security mode does not match')

        if algorithm is not None and \
                algorithm.lower().replace('-', '_') != self.hasher.algorithm:
            raise InvalidProof('Hash algorithm does not match')

        digest_size = self.hasher.hashfunc().digest_size
        for digest in self.path:
            if not isinstance(digest, bytes) or len(digest) != digest_size:
                raise InvalidProof('Invalid digest found in path')


class InclusionProof(MerkleProof):
    """
    Verifiable proof of inclusion of a leaf in some tree state.

    :param index: leaf index counting from one
    :type index: int

    The remaining parameters are those of ``MerkleProof``.
    """

    kind = 'inclusion'

    def __init__(self, algorithm, security, size, index, rule, path):
        super().__init__(algorithm, security, size, rule, path)
        self.index = index


    def get_metadata(self):
        return {**super().get_metadata(), 'index': self.index}


    @classmethod
    def _from_data(cls, data, path):
        return cls(**data['metadata'], rule=data['rule'], path=path)


    def verify(self, base, root, index=None, size=None, algorithm=None,
            security=True):
        """
        Verifies the proof against the provided leaf hash and tree state.

        .. note:: The structure of the proof is recomputed from the leaf index
            and size it claims and must match exactly. Pass *index* and
            *size* to also ensure that these are the position of the leaf and
            the size of the state under consideration.

        :param base: acclaimed leaf hash
        :type base: bytes
        :param root: acclaimed root hash
        :type root: bytes
        :param index: [optional] expected leaf index counting from one
        :type index: int
        :param size: [optional] expected number of leaves
        :type size: int
        :param algorithm: [optional] expected hash algorithm. Defaults to the
            one specified by the proof.
        :type algorithm: str
        :param security: [optional] expected resistance against
            second-preimage attack. Defaults to *True*.
        :type security: bool
        :raises InvalidProof: if the proof is found invalid
        """
        if not (isinstance(self.index, int) and isinstance(self.size, int)
                and 0 < self.index <= self.size < MAX_SIZE):
            raise InvalidProof('Invalid index or size')

        if index is not None and self.index != index:
            raise InvalidProof('Index does not match')

        if size is not None and self.size != size:
            raise InvalidProof('Size does not match')

        # Imported here, since the core module depends on this one
        from pymerkle.core import _inclusion_path_layout

        rule, _ = _inclusion_path_layout(self.index, self.size)
        self._check_rule(rule)
        self._check_hashing(algorithm, security)

        if not _digests_match(self.path[0], base):
            raise InvalidProof('Base hash does not match')

        if not _digests_match(self.compute_root(), root):
            raise InvalidProof('State does not match')


class ConsistencyProof(MerkleProof):
    """
    Verifiable proof of consistency between two tree states.

    :param prior_size: tree size corresponding to prior state
    :type prior_size: int
    :param subset: indicates subset of hashes resolving to the prior state
    :type subset: list[int]

    The remaining parameters are those of ``MerkleProof``, *size*
    corresponding to the later state.
    """

    kind = 'consistency'

    def __init__(self, algorithm, security, size, prior_size, rule, subset,
            path):
        super().__init__(algorithm, security, size, rule, path)
        self.prior_size = prior_size
        self.subset = subset


    def get_metadata(self):
        return {**super().get_metadata(), 'prior_size': self.prior_size}


    def serialize(self):
        return {**super().serialize(), 'subset': self.subset}


    @classmethod
    def _from_data(cls, data, path):
        return cls(**data['metadata'], rule=data['rule'],
            subset=data['subset'], path=path)


    def retrieve_prior_state(self):
        """
        Computes the acclaimed prior state as specified by the included path of
        hashes.

        :rtype: bytes
        """
        subpath = [digest for (mask, digest) in zip(self.subset, self.path)
                   if mask]

        if not subpath:
            return self.hasher.hash_empty()

        return self.hasher.hash_fold(subpath)


    def verify(self, prior_state, later_state, prior_size=None,
            later_size=None, algorithm=None, security=True):
        """
        Verifies the proof against the provided states.

        .. note:: The structure of the proof is recomputed from the sizes it
            claims and must match exactly. Pass *prior_size* and *later_size*
            to also ensure that these are the sizes of the states under
            consideration.

        :param prior_state: acclaimed prior state
        :type prior_state: bytes
        :param later_state: acclaimed later state
        :type later_state: bytes
        :param prior_size: [optional] expected number of leaves for prior state
        :type prior_size: int
        :param later_size: [optional] expected number of leaves for later state
        :type later_size: int
        :param algorithm: [optional] expected hash algorithm. Defaults to the
            one specified by the proof.
        :type algorithm: str
        :param security: [optional] expected resistance against
            second-preimage attack. Defaults to *True*.
        :type security: bool
        :raises InvalidProof: if the proof is found invalid
        """
        if not (isinstance(self.prior_size, int) and
                isinstance(self.size, int) and
                0 < self.prior_size <= self.size < MAX_SIZE):
            raise InvalidProof('Invalid sizes')

        if prior_size is not None and self.prior_size != prior_size:
            raise InvalidProof('Prior size does not match')

        if later_size is not None and self.size != later_size:
            raise InvalidProof('Later size does not match')

        # Imported here, since the core module depends on this one
        from pymerkle.core import _consistency_path_layout

        rule, subset, _ = _consistency_path_layout(self.prior_size, self.size)
        self._check_rule(rule)
        if self.subset != subset:
            raise InvalidProof('Invalid proof structure')
        self._check_hashing(algorithm, security)

        if not _digests_match(self.retrieve_prior_state(), prior_state):
            raise InvalidProof('Prior state does not match')

        if not _digests_match(self.compute_root(), later_state):
            raise InvalidProof('Later state does not match')


_PROOF_TYPES = {cls.kind: cls for cls in (InclusionProof, ConsistencyProof)}

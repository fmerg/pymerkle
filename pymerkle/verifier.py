"""Utilities for Merkle-proof verification
"""

from pymerkle.hashing import HashEngine
from pymerkle.prover import MerkleProof
from pymerkle.exceptions import InvalidProof


class MerkleVerifier:
    """Encapsulates functionality for verification of Merkle-proofs
    """
    def __init__(self):
        self.engine = None

    def verify_proof(self, proof, target=None):
        """Core utility for Merkle-proof verification.

        Verifies the provided proof, modifies the proof's status as *True* or
        *False* accordingly and returns boolean.

        :param proof: the Merkle-proof under verification
        :type proof: MerkleProof
        :param target: [optional] the hash to be be presumably attained at the
            end of the verification process (i.e., acclaimed current root-hash of
            the Merkle-tree having provided the proof). If not explicitly provided,
            should be included in the given proof as the value of the *commitment*
            field
        :type target: bytes
        :returns: Verification result
        """
        if target is None:
            commitment = proof.get_root_hash()
            if not commitment:
                err = 'No acclaimed root-hash provided'
                raise AssertionError(err)
            target = commitment
        offset = proof.body['offset']
        path = proof.body['path']
        if offset == -1 and path == ():
            # raise InvalidProof      # TODO
            return False
        config = proof.get_verification_params()
        self.engine = HashEngine(**config)
        if target != self.engine.multi_hash(path, offset):
            # raise InvalidProof      # TODO
            return False
        return True

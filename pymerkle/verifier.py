"""Provides utilities for Merkle-proof verification
"""

from pymerkle.hashing import HashMachine
from pymerkle.core.prover import MerkleProof
from pymerkle.exceptions import InvalidMerkleProof
import uuid
from time import time, ctime
import json
import os


class MerkleVerifier(HashMachine):
    """Encapsulates the low-level utility for Merkle-proof verification

    :param input: [optional] a Merkle-proof or its header
    :type: MerkleProof or dict
    """

    def __init__(self, input=None):
        if input is not None:
            if isinstance(input, MerkleProof):
                self.proof = input
                input = input.get_verification_params()
            self.update(input)

    def update(self, input):
        """
        :param input: a Merkle-proof or its header
        :type input: MerkleProof or dict
        """
        if isinstance(input, MerkleProof):
            config = input.get_verification_params()
            self.proof = input
        else:
            config = input
        try:
            hash_type = config['hash_type']
            encoding = config['encoding']
            raw_bytes = config['raw_bytes']
            security = config['security']
        except KeyError as err:
            err = f'Hash-machine could not be configured: Missing parameter: {err}'
            raise KeyError(err)
        super().__init__(hash_type=hash_type, encoding=encoding,
                         raw_bytes=raw_bytes, security=security)

    def run(self, proof=None, target=None):
        """Performs Merkle-proof verification

        :raises InvalidMerkleProof: if the proof is found to be invalid

        :param proof: the Merkle-proof under verification
        :type proof: MerkleProof
        :param target: [optional] the hash to be be presumably attained at the
            end of the verification process (i.e., acclaimed current root-hash of
            the Merkle-tree having provided the proof). If not explicitly provided,
            should be included in the given proof as the value of the *commitment*
            field
        :type target: bytes
        """
        if proof is None:
            try:
                proof = self.proof
            except AttributeError:
                err = 'No proof provided for verification'
                raise AssertionError(err)
        if target is None:
            try:
                target = proof.header['commitment']
            except KeyError:
                err = 'No acclaimed root-hash provided'
                raise AssertionError(err)
        proof_index = proof.body['proof_index']
        proof_path = proof.body['proof_path']
        if proof_index == -1 and proof_path == ():
            raise InvalidMerkleProof
        if target != self.multi_hash(proof_path, proof_index):
            raise InvalidMerkleProof

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
        self.update(input=proof.get_verification_params())
        if target is None:
            target = proof.header['commitment']
        try:
            self.run(proof, target)
        except InvalidMerkleProof:
            return False
        return True

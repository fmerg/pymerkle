"""Cryptographic library for Merkle-proofs
"""

from .core import MerkleTree, MerkleProof
from .validations import MerkleVerifier, verify_proof


__version__ = "2.0.2"

__all__ = (
    'MerkleTree',
    'MerkleProof',
    'MerkleVerifier',
    'verify_proof',
)

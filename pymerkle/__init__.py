"""Cryptographic library for Merkle-proofs
"""

from .core import MerkleTree, MerkleProof
from .validations import MerkleVerifier, validateProof


__version__ = "2.0.2"

__all__ = (
    'MerkleTree',
    'MerkleProof',
    'MerkleVerifier',
    'validateProof',
)

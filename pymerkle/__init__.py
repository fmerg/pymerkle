"""
Cryptographic library for Merkle-proofs
"""

from .tree import MerkleTree
from .prover import MerkleProof


__version__ = '2.0.2'

__all__ = (
    'MerkleTree',
    'MerkleProof',
)

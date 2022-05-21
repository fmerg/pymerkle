"""
Cryptographic library for Merkle-proofs
"""

from .tree import MerkleTree
from .prover import Proof


__version__ = '3.0.0'

__all__ = (
    'MerkleTree',
    'Proof',
)

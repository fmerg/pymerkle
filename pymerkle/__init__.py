"""
Cryptographic library for Merkle-proofs
"""

from .tree import MerkleTree
from .prover import Proof


__version__ = '2.0.2'

__all__ = (
    'MerkleTree',
    'Proof',
)

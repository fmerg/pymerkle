"""
Merkle-tree cryptography
"""

from .tree import MerkleTree
from .proof import MerkleProof, verify_inclusion, verify_consistency


__version__ = '3.0.0'

__all__ = (
    'MerkleTree',
    'MerkleProof',
    'verify_inclusion',
    'verify_consistency',
)

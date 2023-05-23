"""
merkle-tree cryptography
"""

from .tree import BaseMerkleTree, InmemoryTree, InvalidChallenge
from .proof import (
    MerkleProof,
    verify_inclusion,
    verify_consistency,
    InvalidProof
)


__version__ = '4.0.0'

__all__ = (
    'BaseMerkleTree',
    'InmemoryTree',
    'MerkleProof',
    'verify_inclusion',
    'verify_consistency',
    'InvalidProof',
)

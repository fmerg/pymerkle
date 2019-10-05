"""
A Python library for constructing Merkle-trees and validating Proofs
"""

from .tree import MerkleTree
from .validations import validateProof, getValidationReceipt

__version__ = "4.0.0b3"

__all__ = (
    'MerkleTree',
    'validateProof',
    'getValidationReceipt'
)

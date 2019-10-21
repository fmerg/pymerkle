"""
A Python library for constructing Merkle-trees and validating Proofs
"""

from .core import MerkleTree
from .validations import Validator, validateProof, validationReceipt

__version__ = "5.0.0b3"

__all__ = ('MerkleTree', 'Validator', 'validateProof', 'validationReceipt,')

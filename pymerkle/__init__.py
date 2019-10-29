"""
A Python library for constructing Merkle-trees and validating Proofs
"""

from .core import MerkleTree, Proof
from .validations import Validator, validateProof

__version__ = "5.0.0b3"

__all__ = ('MerkleTree', 'Proof', 'Validator', 'validateProof',)

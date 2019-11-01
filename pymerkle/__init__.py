"""
Merkle-tree cryptographic library for generation and validation of Proofs
"""

from .core import MerkleTree, Proof
from .validations import Validator, validateProof

__version__ = "5.0.0b"

__all__ = ('MerkleTree', 'Proof', 'Validator', 'validateProof',)

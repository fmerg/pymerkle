"""A Python library for constructing Merkle Trees and validating Proofs
"""

from .tree import MerkleTree
from .validations import validateProof, validationReceipt

__version__ = "4.0.0b3"

__all__ = (
    'MerkleTree',
    'validateProof',
    'validationReceipt'
)

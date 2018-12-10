from .tree_tools import merkle_tree
from .validation_tools import validate_proof, proof_validator

name = "pymerkle"  # Just for verifying correct installation

__version__ = "0.0.3"
__all__ = (
    'merkle_tree',
    'validate_proof',
    'proof_validator')

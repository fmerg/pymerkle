"""
List of supported hash functions.
"""

SHA2_ALGORITHMS = ['sha224', 'sha256', 'sha384', 'sha512']
SHA3_ALGORITHMS = ['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512']
KECCAK_ALGORITHMS = ['keccak_224', 'keccak_256', 'keccak_384', 'keccak_512']
BLAKE2_ALGORITHMS = ['blake2b', 'blake2s']


ALGORITHMS = SHA2_ALGORITHMS + SHA3_ALGORITHMS + BLAKE2_ALGORITHMS
try:
    import sha3
except ImportError:
    pass
else:
    ALGORITHMS += KECCAK_ALGORITHMS

try:
    import blake3  # noqa: F401
except ImportError:
    pass
else:
    ALGORITHMS += ['blake3']

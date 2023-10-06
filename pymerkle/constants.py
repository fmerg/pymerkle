"""
List of supported hash functions.
"""

SHA2_ALGORITHMS: list[str] = ['sha224', 'sha256', 'sha384', 'sha512']
SHA3_ALGORITHMS: list[str] = ['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512']
KECCAK_ALGORITHMS: list[str] = ['keccak_224',
                                'keccak_256', 'keccak_384', 'keccak_512']


ALGORITHMS: list[str] = SHA2_ALGORITHMS + SHA3_ALGORITHMS
try:
    import sha3
except ImportError:
    pass
else:
    ALGORITHMS += KECCAK_ALGORITHMS

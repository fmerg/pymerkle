import pytest
from pymerkle.proof import MerkleProof


path = [
    (+1, b'3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8'),
    (+1, b'4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992'),
    (+1, b'35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52'),
    (-1, b'73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020'),
    (+1, b'cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3'),
    (+1, b'4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e'),
    (-1, b'db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3'),
    (-1, b'f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe'),
    (+1, b'e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8'),
    (-1, b'6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2'),
    (-1, b'2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8')]

proof = MerkleProof(algorithm='sha_256', encoding='utf_8', security=True,
                    offset=5, path=path)


def test_serialization():
    serialized = proof.serialize()

    assert proof.serialize() == {
        'metadata': {
            'timestamp': proof.timestamp,
            'algorithm': 'sha_256',
            'encoding': 'utf_8',
            'security': True,
        },
        'offset': 5,
        'path': [[sign, hash.decode('utf_8')] for (sign, hash) in path]
    }


def test_deserialization():
    deserialized = MerkleProof.deserialize(proof.serialize())

    assert deserialized.timestamp == proof.timestamp
    assert deserialized.algorithm == proof.algorithm
    assert deserialized.encoding == proof.encoding
    assert deserialized.security == proof.security
    assert deserialized.offset == proof.offset
    assert deserialized.path == proof.path

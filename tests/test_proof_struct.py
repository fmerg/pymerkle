"""
Tests formal construction, serialization and representation of Merkle-proofs
"""

import pytest
import json

from pymerkle import MerkleTree, validateProof
from pymerkle.core.prover import Proof
from pymerkle.utils import stringify_path


provider = '1a0894bc-9755-11e9-a651-70c94e89b637'
proof_path = (
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
    (-1, b'2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8'))

proof_11 = Proof(
    provider=provider,
    hash_type='sha_256',
    encoding='utf_8',
    security=True,
    raw_bytes=True,
    proof_index=5,
    proof_path=proof_path)

proof_21 = Proof(
    provider=provider,
    hash_type='sha_256',
    encoding='utf_8',
    security=True,
    raw_bytes=True,
    proof_index=-1,
    proof_path=())

proof_12 = Proof(
    provider=provider,
    hash_type='sha_256',
    encoding='utf_8',
    raw_bytes=True,
    security=True,
    proof_index=5,
    proof_path=proof_path
)

proof_22 = Proof(
    provider=provider,
    hash_type='sha_256',
    encoding='utf_8',
    raw_bytes=True,
    security=True,
    proof_index=-1,
    proof_path=()
)

proof_31 = Proof(
    provider=provider,
    hash_type='sha_256',
    encoding='utf_8',
    raw_bytes=True,
    security=True,
    commitment=b'd079da3aee8025dbffee11b434f1abd52e97caa1d7693a441f196093abc64993',
    proof_index=5,
    proof_path=proof_path
)


@pytest.mark.parametrize('proof, proof_index, proof_path',
    ((proof_12, 5, proof_path), (proof_22, -1, ())))
def test_Proof_construction_with_keyword_arguments(proof, proof_index, proof_path):
    assert proof.__dict__ == {
        'header': {
            'uuid': proof.header['uuid'],
            'timestamp': proof.header['timestamp'],
            'creation_moment': proof.header['creation_moment'],
            'provider': provider,
            'hash_type': 'sha_256',
            'encoding': 'utf_8',
            'raw_bytes': True,
            'security': True,
            'commitment': None,
            'status': None
        },
        'body': {
            'proof_index': proof_index,
            'proof_path': proof_path
        }
    }

@pytest.mark.parametrize('proof', (proof_11, proof_31))
def test_Proof_deserialization_from_dict(proof):
    json_proof = proof.serialize()
    deserialized = Proof.deserialize(json_proof)
    assert proof.__dict__ == deserialized.__dict__

@pytest.mark.parametrize('proof', (proof_11, proof_31))
def test_Proof_deserialization_from_text(proof):
    json_proof = proof.toJSONString()
    deserialized = Proof.deserialize(json_proof)
    assert proof.__dict__ == deserialized.__dict__


serializations = [
    (
        proof_11,
        {
            'header': {
                'uuid': proof_11.header['uuid'],
                'timestamp': proof_11.header['timestamp'],
                'creation_moment': proof_11.header['creation_moment'],
                'provider': provider,
                'hash_type': 'sha_256',
                'encoding': 'utf_8',
                'raw_bytes': True,
                'security': True,
                'commitment': None,
                'status': None
            },
             'body': {
                'proof_index': 5,
                'proof_path': [
                     [+1, '3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8'],
                     [+1, '4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992'],
                     [+1, '35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52'],
                     [-1, '73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020'],
                     [+1, 'cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3'],
                     [+1, '4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e'],
                     [-1, 'db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3'],
                     [-1, 'f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe'],
                     [+1, 'e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8'],
                     [-1, '6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2'],
                     [-1, '2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8']
                 ]
             }
        }
    ),
    (
        proof_21,
        {
            'header': {
                'uuid': proof_21.header['uuid'],
                'timestamp': proof_21.header['timestamp'],
                'creation_moment': proof_21.header['creation_moment'],
                'provider': provider,
                'hash_type': 'sha_256',
                'encoding': 'utf_8',
                'raw_bytes': True,
                'security': True,
                'commitment': None,
                'status': None
            },
             'body': {
                'proof_index': -1,
                'proof_path': []
             }
        }
    )
]

@pytest.mark.parametrize('proof, _serialization', serializations)
def test_serialization(proof, _serialization):
    assert proof.serialize() == _serialization

toJSONStrings = [
    (
        proof_11,
        '{\n    "body": {\n        "proof_index": 5,\n        "proof_path": [\n            [\n                1,\n                "3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8"\n            ],\n            [\n                1,\n                "4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992"\n            ],\n            [\n                1,\n                "35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52"\n            ],\n            [\n                -1,\n                "73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020"\n            ],\n            [\n                1,\n                "cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3"\n            ],\n            [\n                1,\n                "4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e"\n            ],\n            [\n                -1,\n                "db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3"\n            ],\n            [\n                -1,\n                "f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe"\n            ],\n            [\n                1,\n                "e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8"\n            ],\n            [\n                -1,\n                "6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2"\n            ],\n            [\n                -1,\n                "2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8"\n            ]\n        ]\n    },\n    "header": {\n        "commitment": %s,\n        "creation_moment": "%s",\n        "encoding": "utf_8",\n        "hash_type": "sha_256",\n        "provider": "%s",\n        "raw_bytes": true,\n        "security": true,\n        "status": null,\n        "timestamp": %d,\n        "uuid": "%s"\n    }\n}' %
            ('null', proof_11.header['creation_moment'], provider, proof_11.header['timestamp'], proof_11.header['uuid'])
    ),
    (
        proof_21,
        '{\n    "body": {\n        "proof_index": -1,\n        "proof_path": []\n    },\n    "header": {\n        "commitment": %s,\n        "creation_moment": "%s",\n        "encoding": "utf_8",\n        "hash_type": "sha_256",\n        "provider": "%s",\n        "raw_bytes": true,\n        "security": true,\n        "status": null,\n        "timestamp": %d,\n        "uuid": "%s"\n    }\n}' % ('null', proof_21.header['creation_moment'], provider, proof_21.header['timestamp'], proof_21.header['uuid'])
    )
]


@pytest.mark.parametrize('proof, _json_string', toJSONStrings)
def test_toJSONString(proof, _json_string):
    assert proof.toJSONString() == _json_string

proof_13 = Proof(from_json=proof_11.toJSONString())
proof_23 = Proof(from_json=proof_21.toJSONString())

@pytest.mark.parametrize('proof, proof_index, proof_path',
    ((proof_13, 5, proof_path), (proof_23, -1, ())))
def test_Proof_construction_from_json(proof, proof_index, proof_path):
    assert proof.__dict__ == {
        'header': {
            'uuid': proof.header['uuid'],
            'timestamp': proof.header['timestamp'],
            'creation_moment': proof.header['creation_moment'],
            'provider': provider,
            'hash_type': 'sha_256',
            'encoding': 'utf_8',
            'raw_bytes': True,
            'security': True,
            'commitment': None,
            'status': None
        },
        'body': {
            'proof_index': proof_index,
            'proof_path': proof_path
        }
    }

proof_14 = Proof(from_dict=json.loads(proof_11.toJSONString()))
proof_24 = Proof(from_dict=json.loads(proof_21.toJSONString()))

@pytest.mark.parametrize('proof, proof_index, proof_path',
    ((proof_14, 5, proof_path), (proof_24, -1, ())))
def test_Proof_construction_from_dict(proof, proof_index, proof_path):
    assert proof.__dict__ == {
        'header': {
            'uuid': proof.header['uuid'],
            'timestamp': proof.header['timestamp'],
            'creation_moment': proof.header['creation_moment'],
            'provider': provider,
            'hash_type': 'sha_256',
            'encoding': 'utf_8',
            'raw_bytes': True,
            'security': True,
            'commitment': None,
            'status': None
        },
        'body': {
            'proof_index': proof_index,
            'proof_path': proof_path
        }
    }

@pytest.mark.parametrize('proof, generation',
    ((proof_11, True), (proof_12, True), (proof_13, True), (proof_14, True),
    (proof_21, False), (proof_22, False), (proof_23, False), (proof_24, False)))
def test___repr__(proof, generation):
    assert proof.__repr__() == '\n    ----------------------------------- PROOF ------------------------------------\
                \n\
                \n    uuid        : %s\
                \n\
                \n    timestamp   : %d (%s)\
                \n    provider    : %s\
                \n\
                \n    hash-type   : SHA-256\
                \n    encoding    : UTF-8\
                \n    raw_bytes   : TRUE\
                \n    security    : ACTIVATED\
                \n\
                \n    proof-index : %d\
                \n    proof-path  :\
                \n    %s\
                \n\
                \n    commitment  : %s\
                \n\
                \n    status      : UNVALIDATED\
                \n\
                \n    -------------------------------- END OF PROOF --------------------------------\
                \n' % (
                    proof.header['uuid'],
                    proof.header['timestamp'],
                    proof.header['creation_moment'],
                    provider,
                    5 if generation else -1,
                    stringify_path(proof_path, 'utf_8') if generation else '',
                    proof.header['commitment'],
                )

import pytest
from pymerkle import MerkleTree, validateProof
from pymerkle.proof import Proof
from pymerkle.utils import stringify_path
import json


provider = '1a0894bc-9755-11e9-a651-70c94e89b637'
proof_path = (
    (+1, '3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8'),
    (+1, '4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992'),
    (+1, '35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52'),
    (-1, '73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020'),
    (+1, 'cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3'),
    (+1, '4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e'),
    (-1, 'db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3'),
    (-1, 'f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe'),
    (+1, 'e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8'),
    (-1, '6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2'),
    (-1, '2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8'))

proof_11 = Proof(provider, 'sha_256', 'utf_8', True, 5, proof_path)
proof_21 = Proof(provider, 'sha_256', 'utf_8', True, None, None)

@pytest.mark.parametrize('_proof, _generation, _proof_index, _proof_path', ((proof_11, True, 5, proof_path),
                                                                            (proof_21, False, None, None)))
def test_Proof_construction_with_positional_arguments(_proof, _generation, _proof_index, _proof_path):
    assert _proof.__dict__ == {
        'header': {
            'uuid': _proof.header['uuid'],
            'timestamp': _proof.header['timestamp'],
            'creation_moment': _proof.header['creation_moment'],
            'generation': _generation,
            'provider': provider,
            'hash_type': 'sha_256',
            'encoding': 'utf_8',
            'security': True,
            'status': None
        },
        'body': {
            'proof_index': _proof_index,
            'proof_path': _proof_path
        }
    }

proof_12 = Proof(provider=provider, hash_type='sha_256', encoding='utf_8', security=True, proof_index=5, proof_path=proof_path)
proof_22 = Proof(provider=provider, hash_type='sha_256', encoding='utf_8', security=True, proof_index=None, proof_path=None)

@pytest.mark.parametrize('_proof, _generation, _proof_index, _proof_path', ((proof_12, True, 5, proof_path),
                                                                            (proof_22, False, None, None)))
def test_Proof_construction_with_keyword_arguments(_proof, _generation, _proof_index, _proof_path):
    assert _proof.__dict__ == {
        'header': {
            'uuid': _proof.header['uuid'],
            'timestamp': _proof.header['timestamp'],
            'creation_moment': _proof.header['creation_moment'],
            'generation': _generation,
            'provider': provider,
            'hash_type': 'sha_256',
            'encoding': 'utf_8',
            'security': True,
            'status': None
        },
        'body': {
            'proof_index': _proof_index,
            'proof_path': _proof_path
        }
    }


serializations = [
    (
        proof_11,
        {
            'header': {
                'uuid': proof_11.header['uuid'],
                'generation': True,
                'timestamp': proof_11.header['timestamp'],
                'creation_moment': proof_11.header['creation_moment'],
                'provider': provider,
                'hash_type': 'sha_256',
                'encoding': 'utf_8',
                'security': True,
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
                'generation': False,
                'timestamp': proof_21.header['timestamp'],
                'creation_moment': proof_21.header['creation_moment'],
                'provider': provider,
                'hash_type': 'sha_256',
                'encoding': 'utf_8',
                'security': True,
                'status': None
            },
             'body': {
                'proof_index': None,
                'proof_path': []
             }
        }
    )
]
@pytest.mark.parametrize('_proof, _serialization', serializations)
def test_serialization(_proof, _serialization):
    assert _proof.serialize() == _serialization

JSONstrings = [
    (
        proof_11,
        '{\n    "body": {\n        "proof_index": 5,\n        "proof_path": [\n            [\n                1,\n                "3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8"\n            ],\n            [\n                1,\n                "4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992"\n            ],\n            [\n                1,\n                "35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52"\n            ],\n            [\n                -1,\n                "73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020"\n            ],\n            [\n                1,\n                "cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3"\n            ],\n            [\n                1,\n                "4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e"\n            ],\n            [\n                -1,\n                "db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3"\n            ],\n            [\n                -1,\n                "f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe"\n            ],\n            [\n                1,\n                "e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8"\n            ],\n            [\n                -1,\n                "6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2"\n            ],\n            [\n                -1,\n                "2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8"\n            ]\n        ]\n    },\n    "header": {\n        "creation_moment": "%s",\n        "encoding": "utf_8",\n        "generation": true,\n        "hash_type": "sha_256",\n        "provider": "%s",\n        "security": true,\n        "status": null,\n        "timestamp": %d,\n        "uuid": "%s"\n    }\n}' % (proof_11.header['creation_moment'], provider, proof_11.header['timestamp'], proof_11.header['uuid'])
    ),
    (
        proof_21,
        '{\n    "body": {\n        "proof_index": null,\n        "proof_path": []\n    },\n    "header": {\n        "creation_moment": "%s",\n        "encoding": "utf_8",\n        "generation": false,\n        "hash_type": "sha_256",\n        "provider": "%s",\n        "security": true,\n        "status": null,\n        "timestamp": %d,\n        "uuid": "%s"\n    }\n}' % (proof_21.header['creation_moment'], provider, proof_21.header['timestamp'], proof_21.header['uuid'])
    )
]


@pytest.mark.parametrize('_proof, _json_string', JSONstrings)
def test_JSONstring(_proof, _json_string):
    assert _proof.JSONstring() == _json_string

proof_13 = Proof(from_json=proof_11.JSONstring())
proof_23 = Proof(from_json=proof_21.JSONstring())

@pytest.mark.parametrize('_proof, _generation, _proof_index, _proof_path', ((proof_13, True, 5, proof_path),
                                                                            (proof_23, False, None, None)))
def test_Proof_construction_from_json(_proof, _generation, _proof_index, _proof_path):
    assert _proof.__dict__ == {
        'header': {
            'uuid': _proof.header['uuid'],
            'timestamp': _proof.header['timestamp'],
            'creation_moment': _proof.header['creation_moment'],
            'generation': _generation,
            'provider': provider,
            'hash_type': 'sha_256',
            'encoding': 'utf_8',
            'security': True,
            'status': None
        },
        'body': {
            'proof_index': _proof_index,
            'proof_path': _proof_path
        }
    }

proof_14 = Proof(from_dict=json.loads(proof_11.JSONstring()))
proof_24 = Proof(from_dict=json.loads(proof_21.JSONstring()))

@pytest.mark.parametrize('_proof, _generation, _proof_index, _proof_path', ((proof_14, True, 5, proof_path),
                                                                            (proof_24, False, None, None)))
def test_Proof_construction_from_dict(_proof, _generation, _proof_index, _proof_path):
    assert _proof.__dict__ == {
        'header': {
            'uuid': _proof.header['uuid'],
            'timestamp': _proof.header['timestamp'],
            'creation_moment': _proof.header['creation_moment'],
            'generation': _generation,
            'provider': provider,
            'hash_type': 'sha_256',
            'encoding': 'utf_8',
            'security': True,
            'status': None
        },
        'body': {
            'proof_index': _proof_index,
            'proof_path': _proof_path
        }
    }

SUCCESS = 'SUCCESS'
FAILURE = 'FAILURE'
@pytest.mark.parametrize('_proof, _generation', ((proof_11, SUCCESS), (proof_12, SUCCESS), (proof_13, SUCCESS), (proof_14, SUCCESS),
                                                 (proof_21, FAILURE), (proof_22, FAILURE), (proof_23, FAILURE), (proof_24, FAILURE)))
def test___repr__(_proof, _generation):
    assert _proof.__repr__() == '\n    ----------------------------------- PROOF ------------------------------------\
                \n\
                \n    uuid        : %s\
                \n\
                \n    generation  : %s\
                \n    timestamp   : %d (%s)\
                \n    provider    : %s\
                \n\
                \n    hash-type   : SHA-256\
                \n    encoding    : UTF-8\
                \n    security    : ACTIVATED\
                \n\
                \n    proof-index : %s\
                \n    proof-path  :\
                \n    %s\
                \n\
                \n    status      : UNVALIDATED\
                \n\
                \n    -------------------------------- END OF PROOF --------------------------------\
                \n' % (
                    _proof.header['uuid'],
                    _generation,
                    _proof.header['timestamp'],
                    _proof.header['creation_moment'],
                    provider,
                    5 if _generation==SUCCESS else '[None]',
                    stringify_path(proof_path, 'urf_8') if _generation==SUCCESS else '',
                )

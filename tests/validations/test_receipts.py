import pytest
import json
import os

from pymerkle import MerkleTree, validateProof
from pymerkle.validations.mechanisms import Receipt


# Empty receipt directory first
receipt_dir = os.path.join(os.path.dirname(__file__), 'receipts')
for file in os.listdir(receipt_dir):
    path = os.path.join(receipt_dir, file)
    try:
        if os.path.isfile(path):
            os.unlink(path)
    except:
        pass

def test_validation_get_receipt():
    tree = MerkleTree(*['%d-th record' % _ for _ in range(5)])

    audit_proof = tree.auditProof(b'2-th record')
    receipt = validateProof(
        target=tree.rootHash,
        proof=audit_proof,
        get_receipt=True,
        dirpath=os.path.join(os.path.dirname(__file__), 'receipts')
    )

    receipt_path = os.path.join(
        os.path.dirname(__file__),
        'receipts',
        '%s.json' % receipt.header['uuid']
    )

    with open(receipt_path) as __file:
        clone = json.load(__file)
        assert receipt.serialize() == clone

# Internals

proof_provider = '1a0894bc-9755-11e9-a651-70c94e89b637'
proof_uuid     = 'e60394c2-98c7-11e9-ac41-70c94e89b637'

receipt_11 = Receipt(
    proof_uuid=proof_uuid,
    proof_provider=proof_provider,
    result=True)
receipt_12 = Receipt(
    proof_uuid=proof_uuid,
    proof_provider=proof_provider,
    result=False)


@pytest.mark.parametrize('receipt, result', ((receipt_11, True), (receipt_12, False)))
def test_Receipt_construction_with_positional_arguments(receipt, result):
    assert receipt.__dict__ == {
        'header': {
            'uuid': receipt.header['uuid'],
            'timestamp': receipt.header['timestamp'],
            'validation_moment': receipt.header['validation_moment']
        },
        'body': {
            'proof_uuid': proof_uuid,
            'proof_provider': proof_provider,
            'result': result
        }
    }


receipt_21 = Receipt(proof_uuid=proof_uuid, proof_provider=proof_provider, result=True)
receipt_22 = Receipt(proof_uuid=proof_uuid, proof_provider=proof_provider, result=False)

@pytest.mark.parametrize('receipt, result', ((receipt_21, True), (receipt_22, False)))
def test_Receipt_construction_with_kwargs(receipt, result):
    assert receipt.__dict__ == {
        'header': {
            'uuid': receipt.header['uuid'],
            'timestamp': receipt.header['timestamp'],
            'validation_moment': receipt.header['validation_moment']
        },
        'body': {
            'proof_uuid': proof_uuid,
            'proof_provider': proof_provider,
            'result': result
        }
    }


serializations = [
    (
        receipt_11,
        {
            'header': {
                'uuid': receipt_11.header['uuid'],
                'timestamp': receipt_11.header['timestamp'],
                'validation_moment': receipt_11.header['validation_moment']
            },
            'body': {
                'proof_uuid': proof_uuid,
                'proof_provider': proof_provider,
                'result': True
            }
        }
    ),
    (
        receipt_12,
        {
            'header': {
                'uuid': receipt_12.header['uuid'],
                'timestamp': receipt_12.header['timestamp'],
                'validation_moment': receipt_12.header['validation_moment']
            },
            'body': {
                'proof_uuid': proof_uuid,
                'proof_provider': proof_provider,
                'result': False
            }
        }
    )
]


@pytest.mark.parametrize('receipt, serialization', serializations)
def test_serialization(receipt, serialization):
    assert receipt.serialize() == serialization


toJSONStrings = [
    (
        receipt_11,
        '{\n    "body": {\n        "proof_provider": "%s",\n        "proof_uuid": "%s",\n        "result": true\n    },\n    "header": {\n        "timestamp": %d,\n        "uuid": "%s",\n        "validation_moment": "%s"\n    }\n}'
        % (proof_provider, proof_uuid, receipt_11.header['timestamp'], receipt_11.header['uuid'], receipt_11.header['validation_moment'])
    ),
    (
        receipt_12,
        '{\n    "body": {\n        "proof_provider": "%s",\n        "proof_uuid": "%s",\n        "result": false\n    },\n    "header": {\n        "timestamp": %d,\n        "uuid": "%s",\n        "validation_moment": "%s"\n    }\n}'
        % (proof_provider, proof_uuid, receipt_12.header['timestamp'], receipt_12.header['uuid'], receipt_12.header['validation_moment'])
    )
]

@pytest.mark.parametrize('receipt, _json_string', toJSONStrings)
def test_toJSONString(receipt, _json_string):
    assert receipt.toJSONString() == _json_string


receipt_31 = Receipt(from_json=receipt_11.toJSONString())
receipt_32 = Receipt(from_json=receipt_12.toJSONString())

@pytest.mark.parametrize('receipt, result', ((receipt_31, True), (receipt_32, False)))
def test_Receipt_construction_from_json(receipt, result):
    assert receipt.__dict__ == {
        'header': {
            'uuid': receipt.header['uuid'],
            'timestamp': receipt.header['timestamp'],
            'validation_moment': receipt.header['validation_moment']
        },
        'body': {
            'proof_uuid': proof_uuid,
            'proof_provider': proof_provider,
            'result': result
        }
    }


receipt_41 = Receipt(from_dict=json.loads(receipt_11.toJSONString()))
receipt_42 = Receipt(from_dict=json.loads(receipt_12.toJSONString()))

@pytest.mark.parametrize('receipt, result', ((receipt_41, True), (receipt_42, False)))
def test_Receipt_construction_from_dict(receipt, result):
    assert receipt.__dict__ == {
        'header': {
            'uuid': receipt.header['uuid'],
            'timestamp': receipt.header['timestamp'],
            'validation_moment': receipt.header['validation_moment']
        },
        'body': {
            'proof_uuid': proof_uuid,
            'proof_provider': proof_provider,
            'result': result
        }
    }

@pytest.mark.parametrize('receipt', (receipt_11, receipt_31))
def test_Receipt_deserialization_from_dict(receipt):
    json_receipt = receipt.serialize()
    deserialized = Receipt.deserialize(json_receipt)
    assert receipt.__dict__ == deserialized.__dict__

@pytest.mark.parametrize('receipt', (receipt_11, receipt_31))
def test_Receipt_deserialization_from_text(receipt):
    json_receipt = receipt.toJSONString()
    deserialized = Receipt.deserialize(json_receipt)
    assert receipt.__dict__ == deserialized.__dict__


@pytest.mark.parametrize('receipt, result', (
    (receipt_11, 'VALID'), (receipt_21, 'VALID'), (receipt_31, 'VALID'),
    (receipt_41, 'VALID'), (receipt_12, 'NON VALID'), (receipt_22, 'NON VALID'),
    (receipt_32, 'NON VALID'), (receipt_42, 'NON VALID')
))
def test___repr__(receipt, result):
    assert receipt.__repr__() == '\n    ----------------------------- ' + 'VALIDATION RECEIPT -----------------------------\
                \n\
                \n    uuid           : %s\
                \n\
                \n    timestamp      : %d (%s)\
                \n\
                \n    proof-uuid     : %s\
                \n    proof-provider : %s\
                \n\
                \n    result         : %s\
                \n\
                \n    ------------------------------- END OF RECEIPT -------------------------------\
                \n' % (
                    receipt.header['uuid'],
                    receipt.header['timestamp'],
                    receipt.header['validation_moment'],
                    proof_uuid,
                    proof_provider,
                    result,
                )

import pytest
import json
from pymerkle.validations import Receipt


proof_provider = '1a0894bc-9755-11e9-a651-70c94e89b637'
proof_uuid     = 'e60394c2-98c7-11e9-ac41-70c94e89b637'


receipt_11 = Receipt(proof_uuid, proof_provider, True)
receipt_12 = Receipt(proof_uuid, proof_provider, False)

@pytest.mark.parametrize('_receipt, _result', ((receipt_11, True), (receipt_12, False)))
def test_Receipt_construction_with_positional_arguments(_receipt, _result):
    assert _receipt.__dict__ == {
        'header': {
            'uuid': _receipt.header['uuid'],
            'timestamp': _receipt.header['timestamp'],
            'validation_moment': _receipt.header['validation_moment']
        },
        'body': {
            'proof_uuid': proof_uuid,
            'proof_provider': proof_provider,
            'result': _result
        }
    }


receipt_21 = Receipt(proof_uuid=proof_uuid, proof_provider=proof_provider, result=True)
receipt_22 = Receipt(proof_uuid=proof_uuid, proof_provider=proof_provider, result=False)

@pytest.mark.parametrize('_receipt, _result', ((receipt_21, True), (receipt_22, False)))
def test_Receipt_construction_with_keyword_arguments(_receipt, _result):
    assert _receipt.__dict__ == {
        'header': {
            'uuid': _receipt.header['uuid'],
            'timestamp': _receipt.header['timestamp'],
            'validation_moment': _receipt.header['validation_moment']
        },
        'body': {
            'proof_uuid': proof_uuid,
            'proof_provider': proof_provider,
            'result': _result
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


@pytest.mark.parametrize('_receipt, _serialization', serializations)
def test_serialization(_receipt, _serialization):
    assert _receipt.serialize() == _serialization


JSONstrings = [
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

@pytest.mark.parametrize('_receipt, _json_string', JSONstrings)
def test_JSONstring(_receipt, _json_string):
    assert _receipt.JSONstring() == _json_string


receipt_31 = Receipt(from_json=receipt_11.JSONstring())
receipt_32 = Receipt(from_json=receipt_12.JSONstring())

@pytest.mark.parametrize('_receipt, _result', ((receipt_31, True), (receipt_32, False)))
def test_Receipt_construction_from_json(_receipt, _result):
    assert _receipt.__dict__ == {
        'header': {
            'uuid': _receipt.header['uuid'],
            'timestamp': _receipt.header['timestamp'],
            'validation_moment': _receipt.header['validation_moment']
        },
        'body': {
            'proof_uuid': proof_uuid,
            'proof_provider': proof_provider,
            'result': _result
        }
    }


receipt_41 = Receipt(from_dict=json.loads(receipt_11.JSONstring()))
receipt_42 = Receipt(from_dict=json.loads(receipt_12.JSONstring()))

@pytest.mark.parametrize('_receipt, _result', ((receipt_41, True), (receipt_42, False)))
def test_Receipt_construction_from_dict(_receipt, _result):
    assert _receipt.__dict__ == {
        'header': {
            'uuid': _receipt.header['uuid'],
            'timestamp': _receipt.header['timestamp'],
            'validation_moment': _receipt.header['validation_moment']
        },
        'body': {
            'proof_uuid': proof_uuid,
            'proof_provider': proof_provider,
            'result': _result
        }
    }


@pytest.mark.parametrize('_receipt, _result', (
    (receipt_11, 'VALID'), (receipt_21, 'VALID'), (receipt_31, 'VALID'), (receipt_41, 'VALID'),
    (receipt_12, 'NON VALID'), (receipt_22, 'NON VALID'), (receipt_32, 'NON VALID'), (receipt_42, 'NON VALID')
))
def test___repr__(_receipt, _result):
    assert _receipt.__repr__() == '\n    ----------------------------- VALIDATION RECEIPT -----------------------------\
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
                    _receipt.header['uuid'],
                    _receipt.header['timestamp'],
                    _receipt.header['validation_moment'],
                    proof_uuid,
                    proof_provider,
                    _result,
                )

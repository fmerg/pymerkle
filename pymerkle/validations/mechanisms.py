"""
Provides utilities for Merkle-proof validation
"""

from pymerkle.hashing import HashMachine
from pymerkle.core.prover import Proof
from pymerkle.exceptions import InvalidMerkleProof
from pymerkle.serializers import ReceiptSerializer
import uuid
from time import time, ctime
import json
import os


class Validator(HashMachine):
    """
    Encapsulates the low-level utility for Merkle-proof validation

    :param input: [optional] a Merkle-proof or its header
    :type: Proof or dict
    """
    def __init__(self, input=None):
        if input is not None:
            if isinstance(input, Proof):
                self.proof = input
                input = input.get_validation_params()
            self.update(input)


    def update(self, input):
        """
        :param input: a Merkle-proof or its header
        :type input: Proof or dict
        """
        if isinstance(input, Proof):
            config = input.get_validation_params()
            self.proof = input
        else:
            config = input
        try:
            hash_type = config['hash_type']
            encoding = config['encoding']
            raw_bytes = config['raw_bytes']
            security = config['security']
        except KeyError as err:
            err = f'Hash-machine could not be configured: Missing parameter: {err}'
            raise KeyError(err)
        super().__init__(hash_type=hash_type, encoding=encoding,
            raw_bytes=raw_bytes, security=security)


    def run(self, proof=None, target=None):
        """
        Runs Merkle-proof validation

        :raises InvalidMerkleProof: if the proof is found to be invalid

        :param proof: the Merkle-proof under validation
        :type proof: Proof
        :param target: [optional] the hash to be be presumably attained at the
            end of the validation process (i.e., acclaimed current root-hash of
            the Merkle-tree having provided the proof). If not explicitly provided,
            should be included in the given proof as the value of the *commitment*
            field
        :type target: bytes
        """
        if proof is None:
            try:
                proof = self.proof
            except AttributeError:
                err = 'No proof provided for validation'
                raise AssertionError(err)
        if target is None:
            try:
                target = proof.header['commitment']
            except KeyError:
                err = 'No acclaimed root-hash provided'
                raise AssertionError(err)
        proof_index = proof.body['proof_index']
        proof_path  = proof.body['proof_path']
        if proof_index == -1 and proof_path == ():
            raise InvalidMerkleProof
        if target != self.multi_hash(proof_path, proof_index):
            raise InvalidMerkleProof


def validateProof(proof, target=None, get_receipt=False, dirpath=None):
    """
    Core utility for Merkle-proof validation

    Validates the provided proof, modifies the proof's status as *True* or
    *False* accordingly and returns result in the form of a boolean or a
    receipt.

    :param proof: the Merkle-proof under validation
    :type proof: Proof
    :param target: [optional] the hash to be be presumably attained at the
        end of the validation process (i.e., acclaimed current root-hash of
        the Merkle-tree having provided the proof). If not explicitly provided,
        should be included in the given proof as the value of the *commitment*
        field
    :type target: bytes
    :param get_receipt: [optional] Specifies whether a receipt will be
        generated for the performed validation instead of a boolean
    :type get_receipt: bool
    :type dirpath: [optional] Relative path with respect to the current working
        directory of the place where the generated receipt is to be saved (as a
        *.json* file named with the receipt's uuid). If not provided, then the
        receipt will not be automatically saved.
    :param dirpath: str
    :returns: Validation result or receipt
    :rtype: bool or Receipt
    """
    validator = Validator(input=proof.get_validation_params())
    if target is None:
        target = proof.header['commitment']
    try:
        validator.run(proof, target)
    except InvalidMerkleProof:
        result = False
    else:
        result = True
    proof_header = proof.header
    proof_header['status'] = result
    receipt = None
    if get_receipt:
        receipt = Receipt(
            proof_uuid=proof_header['uuid'],
            proof_provider=proof_header['provider'],
            result=result)
        if dirpath:
            receipt_header = receipt.header
            with open(
                os.path.join(dirpath, f"{receipt_header['uuid']}.json"),
                'w'
            ) as __file:
                json.dump(receipt.serialize(), __file, sort_keys=True, indent=4)
    return result if not receipt else receipt


class Receipt(object):
    """
    Receipt for Merkle-proof validations

    :param proof_uuid: uuid of the validated proof
    :type proof_uuid: str
    :param proof_provider: uuid of the tree having provided the proof
    :type proof_provider: str
    :param result: result of validation
    :type result: bool

    Receipts are meant to be output of validation mechanisms and not manually
    constructed. Receipt construction via deserialization might though have
    practical importance, so that given a receipt *r* the following
    constructions are possible:

    >>> from pymerkle.validations import Receipt
    >>>
    >>> s = Receipt(from_dict=r.serialize())
    >>> t = Receipt(from_json=r.toJSONString())

    or, more uniformly,

    >>> s = Receipt.deserialize(r.serialize())
    >>> t = Receipt.deserialize(r.toJSONString())

    .. note:: This is a genuine replication, since deserializations will have
        the same uuid and timestamp as the original.

    :ivar header: (*dict*) contains the keys *uuid*, *timestamp*, *validation_moment*
    :ivar body: (*dict*) contains the keys *proof_uuid*, *proof_provider*, *result*
    """

    def __init__(self, *args, **kwargs):
        """
        """
        header = {}
        body = {}
        if kwargs.get('from_dict'):                             # from json dict
            input = kwargs['from_dict']
            header.update(input['header'])
            body.update(input['body'])
        elif kwargs.get('from_json'):                           # from json text
            input = json.loads(kwargs['from_json'])
            header.update(input['header'])
            body.update(input['body'])
        else:                                                  # multiple kwargs
            header.update({
                'uuid': str(uuid.uuid1()),
                'timestamp': int(time()),
                'validation_moment': ctime(),
            })
            body.update({
                'proof_uuid': kwargs['proof_uuid'],
                'proof_provider': kwargs['proof_provider'],
                'result': kwargs['result'],
            })
        self.header = header
        self.body = body

    def __repr__(self):
        header = self.header
        body = self.body

        return '\n    ----------------------------- VALIDATION RECEIPT -----------------------------\
                \n\
                \n    uuid           : {uuid}\
                \n\
                \n    timestamp      : {timestamp} ({validation_moment})\
                \n\
                \n    proof-uuid     : {proof_uuid}\
                \n    proof-provider : {proof_provider}\
                \n\
                \n    result         : {result}\
                \n\
                \n    ------------------------------- END OF RECEIPT -------------------------------\
                \n'.format(
                    uuid=header['uuid'],
                    timestamp=header['timestamp'],
                    validation_moment=header['validation_moment'],
                    proof_uuid=body['proof_uuid'],
                    proof_provider=body['proof_provider'],
                    result='VALID' if body['result'] else 'NON VALID')

    @classmethod
    def deserialize(cls, serialized):
        """
        Deserializes the provided JSON entity

        :params serialized: a Python dict or JSON text, assumed to be the
            serialization of a *Receipt* object
        :type: dict or str
        :rtype: Receipt
        """
        kwargs = {}
        if isinstance(serialized, dict):
            kwargs.update({'from_dict': serialized})
        elif isinstance(serialized, str):
            kwargs.update({'from_json': serialized})
        return cls(**kwargs)


# Serialization

    def serialize(self):
        """
        Returns a JSON entity with the receipt's characteristics
        as key-value pairs

        :rtype: dict
        """
        return ReceiptSerializer().default(self)

    def toJSONString(self):
        """
        Returns a JSON text with the receipt's characteristics
        as key-value pairs

        :rtype: str
        """
        return json.dumps(self, cls=ReceiptSerializer, sort_keys=True, indent=4)

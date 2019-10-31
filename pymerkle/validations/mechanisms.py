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
    Encapsulates the core utility for validating Merkle-proofs

    Provided ``config`` should be a dictionary containing the keys ``hash_type``,
    ``encoding``, ``raw_bytes`` and ``security``, necessary for configuring the
    underlying hash-machine

    .. note:: Values to the above keys are meant to be the validation parameters
    extracted from the header of the proof to be validated
    """
    def __init__(self, input=None):
        if input is not None:
            if isinstance(input, Proof):
                self.proof = input
                input = input.get_validation_params()
            self.update(input)


    def update(self, input):
        """
        :param input: proof or validation parameters
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
        Runs validation of the given ``proof`` against the provided ``target``,
        returning appropriate exception in case of failure

        :param target: the hash to be presumably attained at the end of the
            validation procedure (that is, acclaimed current root-hash of
            the Merkle-tree having provided the proof)
        :type target: bytes
        :param proof: the Merkle-proof to be validated
        :type proof: Proof
        :raises InvalidMerkleProof: if the provided proof was found to be
            invalid
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
    Core utility for validating proofs

    Validates the provided proof by comparing to the accopmanying target hash,
    modifies the proof's status as ``True`` or ``False`` according to the
    result and returns this result

    :param target: the hash to be presumably attained at the end of the
        validation procedure (that is, acclaimed current root-hash of
        the Merkle-tree having provided the proof)
    :type target: bytes
    :param proof: the Merkle-proof to be validated
    :type proof: Proof
    :param get_receipt: [optional] Specifies whether a receipt will be
        generated for the performed validation
    :type get_receipt: bool
    :type dirpath: [optional] Relative path with respect to the current working
        directory of the directory where the the generated receipt is to be
        saved (as a ``.json`` file named with the receipt's uuid). If
        unspecified, then the generated receipt will *not* be
        automatically saved.
    :param dirpath: str
    :returns: result or receipt of validation
    :rtype: bool or validations.Receipt
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
    Provides info about validation of Merkle-proof

    :param proof_uuid: uuid of the validated proof
    :type proof_uuid: str
    :param proof_provider: uuid of the Merkle-tree having provided the proof
    :type proof_provider: str
    :param result: result of validation
    :type result: bool

    Instead of providing the above arguments corresponding to `*args`, a
    ``Receipt`` object may also be constructed in the following ways given
    validation-receipt ``r``:

    >>> from pymerkle.valiation_receipts import Receipt
    >>> s = Receipt(from_json=r.toJSONString())
    >>> t = Receipt(from_dict=json.loads(r.toJSONString()))

    .. note:: Constructing receipts in the above ways is a genuine *replication*,
        since ``s`` and ``t`` will have the same *uuid* and *timestamp* as the
        original receipt ``r``

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
        :params serialized:
        :type: dict or str
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
        Returns a JSON entity with the receipt's attributes as key-value pairs

        :rtype: dict
        """
        return ReceiptSerializer().default(self)

    def toJSONString(self):
        """
        Returns a stringification of the receipt's JSON serialization

        :rtype: str
        """
        return json.dumps(self, cls=ReceiptSerializer, sort_keys=True, indent=4)

"""
Provides utilities for Merkle-proof validation
"""

from pymerkle.hashing import HashMachine
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
    def __init__(self, config):
        try:
            hash_type = config['hash_type']
            encoding = config['encoding']
            raw_bytes = config['raw_bytes']
            security = config['security']
        except KeyError as err:
            err = f'Hash-machine could not be configured: missing parameter: {err}'
            raise KeyError(err)

        super().__init__(hash_type=hash_type, encoding=encoding,
            raw_bytes=raw_bytes, security=security)

    def run(self, target, proof):
        """
        Runs validation of the given ``proof`` against the provided ``target``,
        returning appropriate exception in case of failure

        :param target: the hash to be presumably attained at the end of the
            validation procedure (that is, acclaimed current root-hash of
            the Merkle-tree having provided the proof)
        :type target: bytes
        :param proof: the Merkle-proof to be validated
        :type proof: proof.Proof
        :raises InvalidMerkleProof: if the provided proof was found to be
            invalid
        """
        if not proof.header['generation']:
            raise InvalidMerkleProof
        signed_hashes = proof.body['proof_path']
        start = proof.body['proof_index']
        if target != self.multi_hash(signed_hashes, start):
            raise InvalidMerkleProof


def validateProof(target, proof, with_receipt=False, dirpath=None):
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
    :type proof: proof.Proof
    :param with_receipt: [optional] Specifies whether a receipt will be
        generated for the performed validation
    :type with_receipt: bool
    :type dirpath: [optional] Relative path with respect to the current working
        directory of the directory where the the generated receipt is to be
        saved (as a ``.json`` file named with the receipt's uuid). If
        unspecified, then the generated receipt will *not* be
        automatically saved.
    :param dirpath: str
    :returns: result or receipt of validation
    :rtype: bool or validations.Receipt
    """
    validator = Validator(config=proof.get_validation_params())
    try:
        validator.run(target, proof)
    except InvalidMerkleProof:
        result = False
    else:
        result = True
    proof_header = proof.header
    proof_header['status'] = result
    receipt = None
    if with_receipt:
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


def validateResponse(response, with_receipt=False, dirpath=None):
    """
    :param response:
    :type response:
    """
    commitment = response['commitment']
    proof = response['proof']
    output = validateProof(target=commitment, proof=proof,
        with_receipt=with_receipt, dirpath=dirpath)
    return output


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
    >>> s = Receipt(from_json=r.toJsonString())
    >>> t = Receipt(from_dict=json.loads(r.toJsonString()))

    .. note:: Constructing receipts in the above ways is a genuine *replication*,
        since ``s`` and ``t`` will have the same *uuid* and *timestamp* as the
        original receipt ``r``

    :ivar header: (*dict*) contains the keys *uuid*, *timestamp*, *validation_moment*
    :ivar body: (*dict*) contains the keys *proof_uuid*, *proof_provider*, *result*
    """

    def __init__(self, *args, **kwargs):

        # if args:                      # Assuming positional arguments by default
        #     self.header = {
        #         'uuid': str(uuid.uuid1()),
        #         'timestamp': int(time()),
        #         'validation_moment': ctime(),
        #     }
        #     self.body = {
        #         'proof_uuid': args[0],
        #         'proof_provider': args[1],
        #         'result': args[2],
        #     }
        # else:
        if kwargs.get('from_dict'):            # Importing receipt from dict
            self.header = kwargs['from_dict']['header']
            self.body = kwargs['from_dict']['body']
        elif kwargs.get('from_json'):     # Importing receipt form JSON text
            _dict = json.loads(kwargs['from_json'])
            self.header = _dict['header']
            self.body = _dict['body']
        else:                                   # Assuming keyword arguments
            self.header = {
                'uuid': str(uuid.uuid1()),
                'timestamp': int(time()),
                'validation_moment': ctime(),
            }
            self.body = {
                'proof_uuid': kwargs['proof_uuid'],
                'proof_provider': kwargs['proof_provider'],
                'result': kwargs['result'],
            }

    def __repr__(self):

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
                    uuid=self.header['uuid'],
                    timestamp=self.header['timestamp'],
                    validation_moment=self.header['validation_moment'],
                    proof_uuid=self.body['proof_uuid'],
                    proof_provider=self.body['proof_provider'],
                    result='VALID' if self.body['result'] else 'NON VALID')


# Serialization

    def serialize(self):
        """
        Returns a JSON entity with the receipt's attributes as key-value pairs

        :rtype: dict
        """
        return ReceiptSerializer().default(self)

    def toJsonString(self):
        """
        Returns a stringification of the receipt's JSON serialization

        :rtype: str
        """
        return json.dumps(self, cls=ReceiptSerializer, sort_keys=True, indent=4)

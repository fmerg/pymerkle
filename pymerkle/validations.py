"""
Provides a core function for validating proof and a related wrapper
"""

import uuid
import time
import json
import os
from .hashing import hash_machine

# -------------------------------- Validation ---------------------------------


def validate_proof(target_hash, proof):
    """Core validation function

    Validates the inserted proof by comparing to the provided target hash, modifies the proof's
    status as ``True`` or ``False`` according to validation result and returns this result.

    :param target_hash: hash (hexadecimal form) to be presumably attained at the end of the
                        validation procedure (i.e., acclaimed top-hash of the Merkle-tree
                        having provided the proof)
    :type target_hash:  str
    :param proof:       the proof to be validated
    :type proof:        proof.proof
    :returns:           validation result
    :rtype:             bool
    """
    if proof.header['generation'][:7] == 'SUCCESS':

        # Configure hashing parameters
        machine = hash_machine(
            hash_type=proof.header['hash_type'],
            encoding=proof.header['encoding'],
            security=proof.header['security'])

        # Perform calculation
        validated = target_hash == machine.multi_hash(
            proof.body['proof_path'], proof.body['proof_index'])

        # Inscribe new proof status according to the above calculation
        proof.header['status'] = validated

        # Print and return result
        return validated

    # generation FAILURE
    proof.header['status'] = False
    return False

# ---------------------------------- Classes ----------------------------------


class proof_validator(object):
    """Wrapper of the ``validate_proof`` function.

    Employs the ``validation_receipt`` class in order to organize validation results
    in an easy storable way.

    :param validations_dir: [optional] absolute path of the directory where validation
                            receipts will be stored as `.json` files. Defaults to ``None``,
                            in which case validation receipts will not be automatically
                            stored.
    :type validations_dir: str
    """

    def __init__(self, validations_dir=None):
        self.validations_dir = validations_dir

    def validate(self, target_hash, proof):
        """Wraps ``validate_proof``, returning a validation receipt instead of a boolean.

        If a ``validations_dir`` has been specified at construction, then the produced validation receipt
        is automatically stored in that directory as a ``.json`` file named with the receipt's uuid.

        :param target_hash: hash (hexadecimal form) to be presumably attained at the end of the
                            validation procedure (i.e., acclaimed top-hash of the Merkle-tree
                            having provided the proof)
        :type target_hash:  str
        :param proof:       the proof to be validated
        :type proof:        proof.proof
        :rtype:             validations.validation_receipt
        """
        validated = validate_proof(target_hash=target_hash, proof=proof)

        receipt = validation_receipt(
            proof_uuid=proof.header['uuid'],
            proof_provider=proof.header['provider'],
            result=validated
        )

        if self.validations_dir:
            with open(
                os.path.join(
                    self.validations_dir,
                    '{}.json'.format(receipt.header['uuid'])
                ),
                'w'
            ) as output_file:
                json.dump(
                    receipt.serialize(),
                    output_file,
                    sort_keys=True,
                    indent=4)

        return receipt


class validation_receipt(object):
    """Encapsulates the result of proof validation

    :param proof_uuid:     uuid of the validated proof (time-based)
    :type proof_uuid:      str
    :param proof_provider: uuid of the Merkle-tree having provided the proof
    :type proof_provider:  str
    :param result:         Validation result (``True`` iff the proof was found to be valid)
    :type result:          bool

    :ivar header:                   (*dict*) Contains the keys *uuid*, *timestamo*, *validation_moment*
    :ivar header.uuid:              (*str*) uuid of the proof (time-based)
    :ivar header.timestamp:         (*str*) Validation moment (msecs) from the start of time
    :ivar header.validation_moment: (*str*) Validation moment in human readable form
    :ivar body:                     (*dict*) Contains the keys *proof_uuid*, *proof_provider*, *result*
    :ivar body.proof_uuid:          (*str*) See the homonymous argument of the constructor
    :ivar body.proof_provider:      (*str*) See the homonymous argument of the constructor
    :ivar body.result:              (*bool*) See the homonymous argument of the constructor
    """

    def __init__(self, proof_uuid, proof_provider, result):
        self.header = {
            'uuid': str(uuid.uuid1()),  # Time based
            'timestamp': int(time.time()),
            'validation_moment': time.ctime(),
        }

        self.body = {
            'proof_uuid': proof_uuid,
            'proof_provider': proof_provider,
            'result': result
        }

    def __repr__(self):

        return '\n    ----------------------------- VALIDATION RECEIPT -----------------------------\
                \n\
                \n    id             : {id}\
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

# ------------------------------ JSON formatting -------------------------

    def serialize(self):
        """ Returns a JSON structure with the receipt's attributes as key-value pairs

        :rtype: dict
        """
        encoder = validationReceiptEncoder()
        return encoder.default(self)

    def JSONstring(self):
        """Returns a nicely stringified version of the receipt's JSON serialized form

        .. note:: The output of this function is to be passed into the ``print`` function

        :rtype: str
        """
        return json.dumps(
            self,
            cls=validationReceiptEncoder,
            sort_keys=True,
            indent=4)

# ------------------------------- JSON encoders --------------------------


class validationReceiptEncoder(json.JSONEncoder):
    """Used implicitly in the JSON serialization of proof receipts. Extends the built-in
    JSON encoder for data structures.
    """

    def default(self, obj):
        """ Overrides the built-in method of JSON encoders according to the needs of this library
        """
        try:
            uuid = obj.header['uuid']
            timestamp = obj.header['timestamp']
            validation_moment = obj.header['validation_moment']
            proof_uuid = obj.body['proof_uuid']
            proof_provider = obj.body['proof_provider']
            result = obj.body['result']
        except TypeError:
            return json.JSONEncoder.default(self, obj)
        else:
            return {
                'header': {
                    'uuid': uuid,
                    'timestamp': timestamp,
                    'validation_moment': validation_moment
                },
                'body': {
                    'proof_uuid': proof_uuid,
                    'proof_provider': proof_provider,
                    'result': result
                }
            }

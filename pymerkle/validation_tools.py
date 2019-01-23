import uuid
import time
import json
import os
from .hash_tools import hash_machine

# -------------------------------- Validation ---------------------------------


def validate_proof(target_hash, proof):
    """
    Validates the inserted `proof` by comparing to `target_hash`, modifies the proof's `status` as

    True or False

    according to validation result and returns this result

    :param target_hash : <str>   hash to be presumably attained at the end of the validation procedure
                                 (i.e., acclaimed top-hash of the merkle-tree providing the proof)
    :param proof       : <proof> the proof to be validated
    :returns           : <bool>  validation result
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

# -------------------------------- Classes --------------------------------


class proof_validator(object):
    def __init__(self, validations_dir=None):
        """
        Enhances the validate_proof() functionality by employing the <validation_receipt> object in order
        to organize its result (see the valdiate() function below). If a `validations_dir` is
        specified, validated receipts are stored in .json files inside this directory.

        :param validations_dir : <str> absolute path of the directory where validation receipts will
                                       be stored as .json files (cf. the validate() function below);
                                       defaults to `None`, in which case validation receipts are
                                       not to be automatically stored
        """
        self.validations_dir = validations_dir

    def validate(self, target_hash, proof):
        """
        Validates the inserted `proof` by comparing to `target_hash`, modifies the proof's `status` as

        True or False

        according to validation result and returns corresponding <validation_receipt> object. If a
        `validations_dir` has been specified at construction, then each validation receipt is
        automatically stored in that directory as a .json file named with the receipt's id

        :param target_hash : <str>                 hash to be presumably attained at the end of the validation
                                                   procedure (i.e., acclaimed top-hash of the merkle-tree
                                                   providing the proof)
        :param proof       : <proof>               the proof to be validated
        :returns           : <validation_receipt>  validation result
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
    def __init__(self, proof_uuid, proof_provider, result):
        """
        Encapsulates the output of the proof validation procedure for nice printing and easy saving

        :param proof_uuid       : <str>  id of the validated proof
        :param proof_provider : <str>  id of the merkle-tree which provided the proof
        :param result         : <bool> validation output; True iff proof was found to be valid
        """
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
        """
        :returns : <dict>
        """
        encoder = validationReceiptEncoder()
        return encoder.default(self)

    def JSONstring(self):
        """
        :returns : <str>
        """
        return json.dumps(
            self,
            cls=validationReceiptEncoder,
            sort_keys=True,
            indent=4)

# ------------------------------- JSON encoders --------------------------


class validationReceiptEncoder(json.JSONEncoder):

    def default(self, obj):
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

import uuid
import time
import json
import os
from .hash_tools import hash_machine

# -------------------------------- Validation ---------------------------------


def validate_proof(target_hash, proof):
    """
    Performs proof validation, modifies the proof's `status` as

    True or False

    according to validation result and returns this result

    :param target_hash : <str>   hash to be presumably attained at the end of the validation procedure
                                 (i.e., acclaimed top-hash of the tree providing the proof)
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
        print('\n * Validated: {}\n'.format(validated))
        return validated

    # generation FAILURE
    proof.header['status'] = False
    print('\n * {}\n'.format(proof.header['generation']))
    return False

# -------------------------------- Classes --------------------------------


class proof_validator(object):
    def __init__(self, validations_dir=os.path.abspath(os.sep)):
        """
        ...

        :param validations_dir : <str>
        """
        self.validations_dir = validations_dir

    def validate(self, target_hash, proof):
        """
        Performs proof validation, modifies the proof's `status` as

        True or False

        according to validation result and returns this result

        :param target_hash : <str>   hash to be presumably attained at the end of the validation procedure
                                     (i.e., acclaimed top-hash of the tree providing the proof)
        :param proof       : <proof> the proof to be validated
        :returns           : <bool>  validation result
        """
        validated = validate_proof(target_hash=target_hash, proof=proof)

        receipt = validation_receipt(
            proof_id=proof.header['id'],
            proof_provider=proof.header['provider'],
            result=validated
        )

        with open(os.path.join(self.validations_dir, 'test.json'), 'w') as output_file:
            json.dump(
                receipt.JSONserialize(),
                output_file,
                sort_keys=True,
                indent=4)

        return receipt


class validation_receipt(object):
    def __init__(self, proof_id, proof_provider, result):
        """
        Encapsulates the output of the proof validation procedure for nice printing and easy saving

        :param proof_id       : <str>  id of the validated proof
        :param proof_provider : <str>  id of the tree which provided the proof
        :param result         : <bool> validation output; True iff proof was found to be valid
        """
        self.header = {
            'id': str(uuid.uuid1()),  # Time based validation id
            'timestamp': int(time.time()),
            'validation_moment': time.ctime(),
        }

        self.body = {
            'proof_id': proof_id,
            'proof_provider': proof_provider,
            'result': result
        }

    def __repr__(self):

        return '\n    ----------------------------- VALIDATION RECEIPT -----------------------------\
                \n\
                \n    id             : {id}\
                \n    timestamp      : {timestamp} ({validation_moment})\
                \n\
                \n    proof-id       : {proof_id}\
                \n    proof-provider : {proof_provider}\
                \n    result         : {result}\
                \n\
                \n    ------------------------------- END OF RECEIPT -------------------------------\
                \n'.format(
            id=self.header['id'],
            timestamp=self.header['timestamp'],
            validation_moment=self.header['validation_moment'],
            proof_id=self.body['proof_id'],
            proof_provider=self.body['proof_provider'],
            result='VALID' if self.body['result'] else 'NON VALID')

# ------------------------------ JSON formatting -------------------------

    def JSONserialize(self):
        """
        :returns : <dict>
        """
        encoder = validation_receiptEncoder()
        return encoder.default(self)

    def JSONstring(self):
        """
        :returns : <str>
        """
        return json.dumps(
            self,
            cls=validation_receiptEncoder,
            sort_keys=True,
            indent=4)

# ------------------------------- JSON encoders --------------------------


class validation_receiptEncoder(json.JSONEncoder):

    def default(self, obj):
        try:
            id = obj.header['id']
            timestamp = obj.header['timestamp']
            validation_moment = obj.header['validation_moment']
            proof_id = obj.body['proof_id']
            proof_provider = obj.body['proof_provider']
            result = obj.body['result']
        except TypeError:
            return json.JSONEncoder.default(self, obj)
        else:
            return {
                'header': {
                    'id': id,
                    'timestamp': timestamp,
                    'validation_moment': validation_moment
                },
                'body': {
                    'proof_id': proof_id,
                    'proof_provider': proof_provider,
                    'result': result
                }
            }

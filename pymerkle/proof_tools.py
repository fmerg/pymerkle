import uuid
import time
import json
from .hash_tools import hash_machine
from .utils import get_with_sign, order_of_magnitude


# -------------------------------- Validations --------------------------------


def validate_proof(target_hash, proof):
    """
    Performs proof validation, modifies the proof's `status` as

    'VALID' or 'NON VALID'

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
        if validated:
            proof.header['status'] = 'VALID'
        else:
            proof.header['status'] = 'NON VALID'

        # Print and return result
        print('\n * Validated: {}\n'.format(validated))
        return validated

    # generation FAILURE
    proof.header['status'] = 'NON VALID'
    print('\n * {}\n'.format(proof.header['generation']))
    return False

# -------------------------------- Classes --------------------------------


class proof(object):
    def __init__(
            self,
            generation,
            provider,
            hash_type,
            security,
            encoding,
            proof_index,
            proof_path):
        """
        :param generation  : <str>  Will be `SUCCESS` or `FAILURE` (plus an explanation message), according to whether
                                    or not a proof can be provided for the parameters provided from Client Side (cf.
                                    the merkle_tools.audit_proof and merkle_tools.consistency_proof functions to
                                    failure cases)
        :param timestamp   : <int>  creation moment (msecs from the start of time)
        :provider          : <str>  id of the the merkle-tree providing the proof
        :param hash_type   : <str>  hash type of the merkle-tree providing the proof
        :param encoding    : <str>  encoding type used by the merkle-tree providing the proof
        :param security    : <bool> security mode of the merkle-tree providing the proof
        :param proof_index : <int>  position where the validation procedure should start from
        :param proof_path  : <list  [of (+1/-1, <str>)]> path of the signed hashes provided
        """
        self.header = {
            'id': str(uuid.uuid1()),
            'generation': generation,
            'timestamp': int(time.time()),
            'creation_moment': time.ctime(),
            'provider': provider,
            'hash_type': hash_type,
            'encoding': encoding,
            'security': security,
            'status': 'UNVALIDATED'
        }

        self.body = {
            'proof_index': proof_index,
            'proof_path': proof_path
        }

    def __repr__(self):

        return '\n    ----------------------------------- PROOF ------------------------------------\
                \n\
                \n    id          : {id}\
                \n\
                \n    generation  : {generation}\
                \n\
                \n    timestamp   : {timestamp} ({creation_moment})\
                \n    provider    : {provider}\
                \n\
                \n    hash-type   : {hash_type}\
                \n    encoding    : {encoding}\
                \n    security    : {security}\
                \n\
                \n    proof-index : {proof_index}\
                \n    proof-path  :\
                \n    {proof_path}\
                \n\
                \n    status      : {status}\
                \n\
                \n    -------------------------------- END OF PROOF --------------------------------\
                \n'.format(
            id=self.header['id'],
            generation=self.header['generation'],
            timestamp=self.header['timestamp'],
            creation_moment=self.header['creation_moment'],
            provider=self.header['provider'],
            hash_type=self.header['hash_type'].upper().replace('_', '-'),
            encoding=self.header['encoding'].upper().replace('_', '-'),
            security='ACTIVATED' if self.header['security'] else 'DEACTIVATED',
            proof_index=self.body['proof_index'] if self.body['proof_index'] is not None else '',
            proof_path=stringify_proof(
                signed_hashes=self.body['proof_path']),
            status=self.header['status'])

# ------------------------------ JSON formatting -------------------------

    def JSONserialize(self):
        """
        :returns : <dict>
        """
        encoder = proofEncoder()
        return encoder.default(self)

    def JSONstring(self):
        """
        :returns : <str>
        """
        return json.dumps(
            self,
            cls=proofEncoder,
            sort_keys=True,
            indent=4)


# ------------------------------- JSON encoders --------------------------


class proofEncoder(json.JSONEncoder):

    def default(self, obj):
        try:
            id = obj.header['id']
            generation = obj.header['generation']
            timestamp = obj.header['timestamp']
            creation_moment = obj.header['creation_moment']
            provider = obj.header['provider']
            hash_type = obj.header['hash_type']
            encoding = obj.header['encoding']
            security = obj.header['security']
            proof_index = obj.body['proof_index']
            proof_path = obj.body['proof_path']
            status = obj.header['status']
        except TypeError:
            return json.JSONEncoder.default(self, obj)
        else:
            return {
                'header': {
                    'id': id,
                    'generation': generation,
                    'timestamp': timestamp,
                    'creation_moment': creation_moment,
                    'provider': provider,
                    'hash_type': hash_type,
                    'encoding': encoding,
                    'security': security,
                    'status': status
                },
                'body': {
                    'proof_index': proof_index,
                    'proof_path': [[sign, hash] for (sign, hash) in proof_path] if proof_path is not None else []
                }
            }

# -------------------------------- Helpers --------------------------------


def stringify_proof(signed_hashes):
    """
    Helper function for nice printing.

    Returns a nice formatted stringified version of the inserted list of signed hashes
    (e.g., the first outpout of the merkle_tree._audit_path() function)

    :param signed_hashes : <list [of (+1/-1, <str>)]> or None
    :returns             : <str>
    """
    if signed_hashes is not None:
        stringified_elems = []
        for i in range(len(signed_hashes)):
            elem = signed_hashes[i]
            stringified_elems.append(
                ('\n' +
                 (7 - order_of_magnitude(i)) *
                 ' ' +
                 '[{i}]' +
                 3 *
                 ' ' +
                 '{sign}' +
                 2 *
                 ' ' +
                 '{hash}').format(
                    i=i,
                    sign=get_with_sign(
                        elem[0]),
                    hash=elem[1]))
        return ''.join(elem for elem in stringified_elems)
    return ''  # input was None

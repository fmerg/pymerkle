import uuid
import time
import json
from .utils import get_with_sign, order_of_magnitude


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
                                    the tree_tools.audit_proof() and tree_tools.consistency_proof() functions to
                                    understand failure cases)
        :provider          : <str>  id of the the merkle-tree providing the proof
        :param hash_type   : <str>  hash type of the merkle-tree providing the proof
        :param encoding    : <str>  encoding type of the merkle-tree providing the proof
        :param security    : <bool> security mode of the merkle-tree providing the proof
        :param proof_index : <int>  position where the validation procedure should start from
        :param proof_path  : <list  [of (+1/-1, <str>)]> path of the signed hashes provided
        """
        self.header = {
            'id': str(uuid.uuid1()),    # Time based proof id
            'generation': generation,
            'timestamp': int(time.time()),
            'creation_moment': time.ctime(),
            'provider': provider,
            'hash_type': hash_type,
            'encoding': encoding,
            'security': security,
            'status': None              # Will change to True or False after validation
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
            proof_path=stringify_path(
                signed_hashes=self.body['proof_path']),
            status='UNVALIDATED' if self.header['status'] is None
            else 'VALID' if self.header['status'] is True
            else 'NON VALID')

# ------------------------------ JSON formatting -------------------------

    def serialize(self):
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


def stringify_path(signed_hashes):
    """
    Helper function for nice printing.

    Returns a nice formatted stringified version of the inserted list of signed hashes
    (e.g., for the first outpout of the merkle_tree._audit_path() function)

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

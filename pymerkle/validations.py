"""
Provides a core function for validating proofs along with a wrapper
"""

from .hashing import hash_machine
from .serializers import ReceiptSerializer
import uuid
import time
import json
import os

# -------------------------------- Validation ---------------------------------


def validateProof(target_hash, proof):
    """Core validation utility

    Validates the inserted proof by comparing to the provided target hash, modifies the proof's
    status as ``True`` or ``False`` according to validation result and returns this result

    :param target_hash: the hash to be presumably attained at the end of the validation procedure (i.e.,
                        acclaimed current root-hash of the Merkle-tree having provided the proof)
    :type target_hash:  bytes
    :param proof:       the proof to be validated
    :type proof:        proof.Proof
    :returns:           validation result
    :rtype:             bool
    """

    _header = proof.header

    if not _header['generation']:      # Empty proof-path case

        _header['status'] = False
        return False

    else:

        # Configure hashing parameters

        machine = hash_machine(
            hash_type=_header['hash_type'],
            encoding=_header['encoding'],
            security=_header['security']
        )

        # Perform hash-comparison

        result = target_hash == machine.multi_hash(
            signed_hashes=proof.body['proof_path'],
            start=proof.body['proof_index']
        )

        # Inscribe new status according to the above calculation and return

        proof.header['status'] = result
        return result


def validationReceipt(target_hash, proof, dirpath=None):
    """Wraps the ``validateProof()`` method, returning a validation receipt instead of a boolean

    If a ``dirpath`` has been specified, then the receipt is automatically stored in the given
    directory as a ``.json`` file named with the receipt's uuid

    :param target_hash: hash to be presumably attained at the end of the validation procedure (i.e.,
                        acclaimed top-hash of the Merkle-tree having provided the proof)
    :type target_hash:  bytes
    :param proof:       the proof to be validated
    :type dirpath:     [optional] Relative path with respect to the current working directory of the
                        directory where to save the generated receipt. If specified, the generated
                        receipt will be saved within this directory as a ``.json`` file named with
                        the receipt's uuid. Otherwise, then generated receipt will *not* be
                        automatically stored in any file.
    :param dirpath:    str
    :type proof:        proof.Proof
    :rtype:             validations.Receipt
    """

    result  = validateProof(target_hash=target_hash, proof=proof)

    _header = proof.header

    receipt = Receipt(
        proof_uuid=_header['uuid'],
        proof_provider=_header['provider'],
        result=validated
    )

    if dirpath:
        with open(
            os.path.join(
                dirpath,
                '%s.json' % receipt.header['uuid']
            ),
            'w'
        ) as _file:
            json.dump(receipt.serialize(), _file, sort_keys=True, indent=4)

    return receipt


class Receipt(object):
    """Provides info about proof validation

    :param proof_uuid:     uuid of the validated proof (time-based)
    :type proof_uuid:      str
    :param proof_provider: uuid of the Merkle-tree having provided the proof
    :type proof_provider:  str
    :param result:         Validation result (``True`` iff the proof was found to be valid)
    :type result:          bool

    Instead of providing the above arguments corresponding to `*args`, a ``Receipt`` object may also
    be constructed in the following ways by employing `**kwargs` in order to load the JSON string of a
    given validation-receipt ``r``:

    >>> from pymerkle.valiation_receipts import Receipt
    >>> s = Receipt(from_json=r.JSONstring())
    >>> t = Receipt(from_dict=json.loads(r.JSONstring()))

    .. note:: Constructing receipts in the above ways is a genuine *replication*, since the constructed
              receipts ``s`` and ``t`` have the same *uuid* and *timestamps* as ``r``

    :ivar header:                   (*dict*) Contains the keys *uuid*, *timestamp*, *validation_moment*
    :ivar header.uuid:              (*str*) uuid of the validation (time-based)
    :ivar header.timestamp:         (*str*) Validation moment (msecs) from the start of time
    :ivar header.validation_moment: (*str*) Validation moment in human readable form
    :ivar body:                     (*dict*) Contains the keys *proof_uuid*, *proof_provider*, *result* (see below)
    :ivar body.proof_uuid:          (*str*) See the homonymous argument of the constructor
    :ivar body.proof_provider:      (*str*) See the homonymous argument of the constructor
    :ivar body.result:              (*bool*) See the homonymous argument of the constructor
    """

    def __init__(self, *args, **kwargs):

        if args:                                                                # Assuming positional arguments by default
            self.header = {
                'uuid': str(uuid.uuid1()),                                      # Time based receipt id
                'timestamp': int(time.time()),
                'validation_moment': time.ctime(),
            }

            self.body = {
                'proof_uuid': args[0],
                'proof_provider': args[1],
                'result': args[2]
            }

        else:

            if kwargs.get('from_dict'):                                         # Importing receipt from dict

                self.header = kwargs.get('from_dict')['header']
                self.body = kwargs.get('from_dict')['body']

            elif kwargs.get('from_json'):                                       # Importing receipt form JSON text

                _dict = json.loads(kwargs.get('from_json'))

                self.header = _dict['header']
                self.body = _dict['body']

            else:                                                               # Standard creation of a receipt
                self.header = {
                    'uuid': str(uuid.uuid1()),                                  # Time based receipt id
                    'timestamp': int(time.time()),
                    'validation_moment': time.ctime(),
                }

                self.body = {
                    'proof_uuid': kwargs.get('proof_uuid'),
                    'proof_provider': kwargs.get('proof_provider'),
                    'result': kwargs.get('result')
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

# ------------------------------- Serialization --------------------------

    def serialize(self):
        """ Returns a JSON entity with the receipt's attributes as key-value pairs

        :rtype: dict
        """
        return ReceiptSerializer().default(self)

    def JSONstring(self):
        """Returns a nicely stringified version of the receipt's JSON serialized form

        .. note:: The output of this function is to be passed into the ``print`` function

        :rtype: str
        """
        return json.dumps(
            self,
            cls=ReceiptSerializer,
            sort_keys=True,
            indent=4)

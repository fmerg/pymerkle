"""
Provides JSON encoders used for serialization accross the *pymerkle* library
"""

import json


class MerkleTreeSerializer(json.JSONEncoder):
    """
    Used implicitly in the JSON serialization of Merkle-trees.
    Extends the built-in JSON encoder for data structures.
    """

    def default(self, obj):
        """
        Overrides the built-in method of JSON encoders
        in accordance with the needs of this library
        """
        try:
            hash_type = obj.hash_type
            encoding = obj.encoding
            security = obj.security
            leaves = obj.leaves
            raw_bytes = obj.raw_bytes
        except AttributeError:
            return json.JSONEncoder.default(self, obj)        # let TypeError get raised
        return {
            'header': {
                'hash_type': hash_type,
                'encoding': encoding,
                'raw_bytes': raw_bytes,
                'security': security},
                'hashes': [leaf.digest.decode(encoding) for leaf in leaves]
        }


class NodeSerializer(json.JSONEncoder):
    """
    Used implicitly in the JSON serialization of nodes.
    Extends the built-in JSON encoder for data structures.
    """

    def default(self, obj):
        """
        Overrides the built-in method of JSON encoders
        in accordance with the needs of this library.
        """
        try:
            left = obj.left
            right = obj.right
            hash = obj.digest
        except AttributeError:
            return json.JSONEncoder.default(self, obj)        # let TypeError get raised
        return {
            'left': left.serialize(),
            'right': right.serialize(),
            'hash': hash.decode(encoding=obj.encoding)
        }


class LeafSerializer(json.JSONEncoder):
    """
    Used implicitly in the JSON serialization of leafs.
    Extends the built-in JSON encoder for data structures.
    """

    def default(self, obj):
        """
        Overrides the built-in method of JSON encoders
        in accordance with the needs of this library.
        """
        try:
            encoding = obj.encoding
            hash = obj.digest
        except AttributeError:
            return json.JSONEncoder.default(self, obj)        # let TypeError be raised
        return {
            'hash': hash.decode(encoding=obj.encoding)
        }


class ProofSerializer(json.JSONEncoder):
    """
    Used implicitly in the JSON serialization of proofs.
    Extends the built-in JSON encoder for data structures.
    """

    def default(self, obj):
        """
        Overrides the built-in method of JSON encoders
        in accordance with the needs of this library
        """
        try:
            uuid = obj.header['uuid']
            creation_moment = obj.header['creation_moment']
            timestamp = obj.header['timestamp']
            provider = obj.header['provider']
            hash_type = obj.header['hash_type']
            encoding = obj.header['encoding']
            security = obj.header['security']
            raw_bytes = obj.header['raw_bytes']
            proof_index = obj.body['proof_index']
            proof_path = obj.body['proof_path']
            commitment = obj.header['commitment']
            status = obj.header['status']
        except AttributeError:
            return json.JSONEncoder.default(self, obj)        # let TypeError be raised
        return {
            'header': {
                'uuid': uuid,
                'timestamp': timestamp,
                'creation_moment': creation_moment,
                'provider': provider,
                'hash_type': hash_type,
                'encoding': encoding,
                'security': security,
                'raw_bytes': raw_bytes,
                'commitment': commitment.decode() if commitment else None,
                'status': status
            },
            'body': {
                'proof_index': proof_index,
                'proof_path': [
                    [sign, hash if type(hash) is str else hash.decode()]
                        for (sign, hash) in proof_path
                ]
            }
        }


class ReceiptSerializer(json.JSONEncoder):
    """
    Used implicitly in the JSON serialization of validation receipts.
    Extends the built-in JSON encoder for data structures.
    """

    def default(self, obj):
        """
        Overrides the built-in method of JSON encoders
        in accordance with the needs of this library
        """
        try:
            uuid = obj.header['uuid']
            timestamp = obj.header['timestamp']
            validation_moment = obj.header['validation_moment']
            proof_uuid = obj.body['proof_uuid']
            proof_provider = obj.body['proof_provider']
            result = obj.body['result']
        except AttributeError:
            return json.JSONEncoder.default(self, obj)        # let TypeError be raised
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

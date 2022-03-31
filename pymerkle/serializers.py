"""Provides JSON encoders used for serialization accross the *pymerkle* library
"""

import json


class MerkleTreeSerializer(json.JSONEncoder):
    """Used implicitly in the JSON serialization of Merkle-trees.
    """

    def default(self, obj):
        """Overrides the built-in method of JSON encoders.
        """
        try:
            hash_type = obj.hash_type
            encoding = obj.encoding
            security = obj.security
            leaves = obj.leaves
            raw_bytes = obj.raw_bytes
        except AttributeError:
            return json.JSONEncoder.default(self, obj)
        return {
            'header': {
                'hash_type': hash_type,
                'encoding': encoding,
                'raw_bytes': raw_bytes,
                'security': security},
                'hashes': [leaf.digest.decode(encoding) for leaf in leaves]
        }


class NodeSerializer(json.JSONEncoder):
    """Used implicitly in the JSON serialization of nodes.
    """

    def default(self, obj):
        """Overrides the built-in method of JSON encoders.
        """
        try:
            left = obj.left
            right = obj.right
            digest = obj.digest
        except AttributeError:
            return json.JSONEncoder.default(self, obj)

        return {
            'left': left.serialize(),
            'right': right.serialize(),
            'hash': digest.decode(encoding=obj.encoding)
        }


class LeafSerializer(json.JSONEncoder):
    """Used implicitly in the JSON serialization of leafs.
    """

    def default(self, obj):
        """Overrides the built-in method of JSON encoders.
        """
        try:
            encoding = obj.encoding
            digest = obj.digest
        except AttributeError:
            return json.JSONEncoder.default(self, obj)

        return {
            'hash': digest.decode(encoding=obj.encoding)
        }


class ProofSerializer(json.JSONEncoder):
    """Used implicitly in the JSON serialization of proofs.
    """

    def default(self, obj):
        """Overrides the built-in method of JSON encoders.
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
            return json.JSONEncoder.default(self, obj)

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
                    [sign, digest if type(digest) is str else digest.decode()]
                        for (sign, digest) in proof_path
                ]
            }
        }


class ReceiptSerializer(json.JSONEncoder):
    """Used implicitly in the JSON serialization of validation receipts.
    """

    def default(self, obj):
        """Overrides the built-in method of JSON encoders.
        """
        try:
            uuid = obj.header['uuid']
            timestamp = obj.header['timestamp']
            validation_moment = obj.header['validation_moment']
            proof_uuid = obj.body['proof_uuid']
            proof_provider = obj.body['proof_provider']
            result = obj.body['result']
        except AttributeError:
            return json.JSONEncoder.default(self, obj)

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

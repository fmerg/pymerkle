import pytest
from pymerkle.serializers import MerkleTreeSerializer, LeafSerializer, NodeSerializer, ProofSerializer, ReceiptSerializer

_serializers = [
    MerkleTreeSerializer(),
    LeafSerializer(),
    NodeSerializer(),
    ProofSerializer(),
    ReceiptSerializer()
]

class Empty(object): pass

@pytest.mark.parametrize('_serializer', _serializers)
def test_serialization_error(_serializer):
    with pytest.raises(TypeError):
        _serializer.default(_serializer, Empty())

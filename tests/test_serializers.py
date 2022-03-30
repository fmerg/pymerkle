import pytest
import json

from pymerkle.serializers import (MerkleTreeSerializer, LeafSerializer,
    NodeSerializer, ProofSerializer, ReceiptSerializer)

__serializers = [
    MerkleTreeSerializer(),
    LeafSerializer(),
    NodeSerializer(),
    ProofSerializer(),
    ReceiptSerializer()
]

class Empty(object): pass
@pytest.mark.parametrize('serializer', __serializers)
def test_serialization_error(serializer):
    with pytest.raises(TypeError):
        serializer.default(Empty())

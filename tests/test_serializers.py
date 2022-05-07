import pytest

from pymerkle.core.tree import MerkleTreeSerializer
from pymerkle.core.prover import MerkleProofSerialilzer
from pymerkle.core.nodes import NodeSerializer, LeafSerializer


@pytest.mark.parametrize('serializer', [MerkleTreeSerializer(),
                                        LeafSerializer(),
                                        NodeSerializer(),
                                        MerkleProofSerialilzer(),
                                        ])
def test_serialization_error(serializer):
    class Empty(object):
        pass
    with pytest.raises(TypeError):
        serializer.default(Empty())

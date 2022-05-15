import pytest

from pymerkle.tree import MerkleTreeSerializer
from pymerkle.nodes import NodeSerializer


@pytest.mark.parametrize('serializer', [MerkleTreeSerializer(),
                                        NodeSerializer(),
                                        ])
def test_serialization_error(serializer):
    class Empty:
        pass
    with pytest.raises(TypeError):
        serializer.default(Empty())

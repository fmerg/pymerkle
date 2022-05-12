import pytest

from pymerkle.prover import MerkleProofSerialilzer
from pymerkle.tree import MerkleTreeSerializer
from pymerkle.core.nodes import NodeSerializer


@pytest.mark.parametrize('serializer', [MerkleTreeSerializer(),
                                        NodeSerializer(),
                                        MerkleProofSerialilzer(),
                                        ])
def test_serialization_error(serializer):
    class Empty:
        pass
    with pytest.raises(TypeError):
        serializer.default(Empty())

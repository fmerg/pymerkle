import pytest

from pymerkle.tree import MerkleTreeSerializer


@pytest.mark.parametrize('serializer', [MerkleTreeSerializer(),
                                        ])
def test_serialization_error(serializer):
    class Empty:
        pass
    with pytest.raises(TypeError):
        serializer.default(Empty())

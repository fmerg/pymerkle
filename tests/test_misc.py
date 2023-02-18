import pytest
from pymerkle.tree import MerkleTree, UnsupportedParameter, TREE_TEMPLATE
from tests.conftest import option, all_configs


def test_bool():
    tree = MerkleTree()
    assert not tree
    assert not tree.get_root_hash()

    tree = MerkleTree.init_from_entries('a')
    assert tree
    assert tree.get_root_hash()


def test_dimensions():
    tree = MerkleTree()
    assert (tree.length, tree.size, tree.height) == (0, 0, 0)

    tree = MerkleTree.init_from_entries('a', 'b', 'c')
    assert (tree.length, tree.size, tree.height) == (3, 5, 2)


def test_construction_error():
    with pytest.raises(UnsupportedParameter):
        MerkleTree(algorithm='anything_unsupported')

    with pytest.raises(UnsupportedParameter):
        MerkleTree(encoding='anything_unsupported')


@pytest.mark.parametrize('config', all_configs(option))
def test_repr(config):
    tree = MerkleTree(**config)
    assert tree.__repr__() == TREE_TEMPLATE.format(
        algorithm=config['algorithm'].upper().replace('_', ''),
        encoding=config['encoding'].upper().replace('_', '-'),
        security='DEACTIVATED' if not config['security'] else 'ACTIVATED',
        root='[None]',
        length=0,
        size=0,
        height=0
    )


@pytest.mark.parametrize('tree, stringified', [
    (
        MerkleTree(),
        '\n └─[None]\n'
    ),
    (
        MerkleTree.init_from_entries('first'),
        '\n └─a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d\n'
    ),
    (
        MerkleTree.init_from_entries('first', 'second', 'third'),
        '\n └─2427940ec5c9197add5f33423ba3971c3524f4b78f349ee45094b52d0d550fea\n\
     ├──a84762b529735022ce1d7bdc3f24e94aba96ad8b3f6e4866bca76899da094df3\n\
     │    ├──a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d\n\
     │    └──a94dd4d3c2c6d2548ca4e560d72727bab5d795500191f5b85579130dd3b14603\n\
     └──656d3e8f544238cdf6e32d640f51ba0914959b14edd7a52d0b8b99ab4c8ac6c6\n'
    )
])
def test_str(tree, stringified):
    assert tree.__str__() == stringified

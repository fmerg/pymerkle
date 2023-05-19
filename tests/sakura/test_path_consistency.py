import pytest
from pymerkle.tree import MerkleTree


tree_0 = MerkleTree.init_from_entries()
tree_1 = MerkleTree.init_from_entries('a')
tree_2 = MerkleTree.init_from_entries('a', 'b')
tree_3 = MerkleTree.init_from_entries('a', 'b', 'c')
tree_4 = MerkleTree.init_from_entries('a', 'b', 'c', 'd')
tree_5 = MerkleTree.init_from_entries('a', 'b', 'c', 'd', 'e')

no_perfect_node = [
    (tree_0, 0, 0),
    (tree_1, 1, 1),
    (tree_2, 2, 1),
    (tree_2, 0, 2),
    (tree_2, 1, 1),
    (tree_3, 3, 2),
    (tree_3, 0, 3),
    (tree_3, 1, 1),
    (tree_3, 2, 1),
    (tree_4, 4, 3),
    (tree_4, 0, 3),
    (tree_4, 1, 1),
    (tree_4, 2, 2),
    (tree_4, 3, 1),
    (tree_5, 5, 3),
    (tree_5, 0, 3),
    (tree_5, 0, 4),
    (tree_5, 1, 1),
    (tree_5, 2, 2),
    (tree_5, 3, 1),
    (tree_5, 4, 1),
]

perfect_nodes = [
    (tree_1, 0, 0, tree_1.leaf(1)),
    (tree_2, 0, 0, tree_2.leaf(1)),
    (tree_2, 0, 1, tree_2.root),
    (tree_2, 1, 0, tree_2.leaf(2)),
    (tree_3, 0, 0, tree_3.leaf(1)),
    (tree_3, 0, 1, tree_3.leaf(1).parent),
    (tree_3, 1, 0, tree_3.leaf(2)),
    (tree_3, 2, 0, tree_3.leaf(3)),
    (tree_4, 0, 0, tree_4.leaf(1)),
    (tree_4, 0, 1, tree_4.leaf(1).parent),
    (tree_4, 0, 2, tree_4.root),
    (tree_4, 1, 0, tree_4.leaf(2)),
    (tree_4, 2, 0, tree_4.leaf(3)),
    (tree_4, 2, 1, tree_4.leaf(3).parent),
    (tree_4, 3, 0, tree_4.leaf(4)),
    (tree_5, 0, 0, tree_5.leaf(1)),
    (tree_5, 0, 1, tree_5.leaf(1).parent),
    (tree_5, 0, 2, tree_5.leaf(1).parent.parent),
    (tree_5, 1, 0, tree_5.leaf(2)),
    (tree_5, 2, 0, tree_5.leaf(3)),
    (tree_5, 2, 1, tree_5.leaf(3).parent),
    (tree_5, 3, 0, tree_5.leaf(4)),
    (tree_5, 4, 0, tree_5.leaf(5)),
]

no_principal_nodes = [
    (tree_1, -1),
    (tree_1, +2),
    (tree_2, -1),
    (tree_2, +3),
    (tree_3, -1),
    (tree_3, +4),
    (tree_4, -1),
    (tree_4, +5),
    (tree_5, -1),
    (tree_5, +6),
]

principal_nodes = [
    (tree_0, 0, []),
    (tree_1, 0, []),
    (tree_1, 1, [(+1, tree_1.root)]),
    (tree_2, 0, []),
    (tree_2, 1, [(+1, tree_2.leaf(1))]),
    (tree_2, 2, [(+1, tree_2.root)]),
    (tree_3, 0, []),
    (tree_3, 1, [(+1, tree_3.leaf(1))]),
    (tree_3, 2, [(+1, tree_3.leaf(1).parent)]),
    (tree_3, 3, [
     (+1, tree_3.leaf(1).parent), (+1, tree_3.leaf(3))]),
    (tree_4, 0, []),
    (tree_4, 1, [(+1, tree_4.leaf(1))]),
    (tree_4, 2, [(+1, tree_4.leaf(1).parent)]),
    (tree_4, 3, [
     (+1, tree_4.leaf(1).parent), (+1, tree_4.leaf(3))]),
    (tree_4, 4, [(+1, tree_4.root)]),
    (tree_5, 0, []),
    (tree_5, 1, [(+1, tree_5.leaf(1))]),
    (tree_5, 2, [(+1, tree_5.leaf(1).parent)]),
    (tree_5, 3, [
     (+1, tree_5.leaf(1).parent), (+1, tree_5.leaf(3))]),
    (tree_5, 4, [(+1, tree_5.leaf(1).parent.parent)]),
    (tree_5, 5, [
     (+1, tree_5.leaf(1).parent.parent), (+1, tree_5.leaf(5))]),
]


complements = [
    (tree_0, [], []),
    (tree_1, [], [(+1, tree_1.leaf(1))]),
    (tree_1, [(+1, tree_1.root)], []),
    (tree_2, [], [(+1, tree_2.root)]),
    (tree_2, [(+1, tree_2.leaf(1))],
     [(+1, tree_2.leaf(2))]),
    (tree_2, [(+1, tree_2.root)], []),
    (tree_3, [], [(+1, tree_3.leaf(1).parent),
     (+1, tree_3.leaf(3))]),
    (tree_3, [(+1, tree_3.leaf(1))],
     [(+1, tree_3.leaf(2)), (+1, tree_3.leaf(3))]),
    (tree_3, [(+1, tree_3.leaf(1).parent)],
     [(+1, tree_3.leaf(3))]),
    (tree_3, [(+1, tree_3.leaf(1).parent),
     (+1, tree_3.leaf(3))], []),
    (tree_4, [], [(+1, tree_4.root)]),
    (tree_4, [(+1, tree_4.leaf(1))],
     [(+1, tree_4.leaf(2)), (+1, tree_4.leaf(3).parent)]),
    (tree_4, [(+1, tree_4.leaf(1).parent)],
     [(+1, tree_4.leaf(3).parent)]),
    (tree_4, [(+1, tree_4.leaf(1).parent), (+1,
     tree_4.leaf(3))], [(-1, tree_4.leaf(4))]),
    (tree_4, [(+1, tree_4.root)], []),
    (tree_5, [], [(+1, tree_5.leaf(1).parent.parent),
     (+1, tree_5.leaf(5))]),
    (tree_5, [(+1, tree_5.leaf(1))], [(+1, tree_5.leaf(2)),
     (+1, tree_5.leaf(3).parent), (+1, tree_5.leaf(5))]),
    (tree_5, [(+1, tree_5.leaf(1).parent)],
     [(+1, tree_5.leaf(3).parent), (+1, tree_5.leaf(5))]),
    (tree_5, [(+1, tree_5.leaf(1).parent), (+1, tree_5.leaf(3))],
     [(-1, tree_5.leaf(4)), (+1, tree_5.leaf(5))]),
    (tree_5, [(+1, tree_5.leaf(1).parent.parent)],
     [(+1, tree_5.leaf(5))]),
    (tree_5, [(+1, tree_5.leaf(1).parent.parent),
     (+1, tree_5.leaf(5))], []),
]


paths = [
    (
        tree_1,
        0,
        (
            +0,
            [],
            [
                (-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
            ]
        )
    ),
    (
        tree_1,
        1,
        (
            +0,
            [
                (-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
            ],
            [
                (-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
            ]
        )
    ),
    (
        tree_2,
        0,
        (
            +0,
            [],
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
            ]
        )
    ),
    (
        tree_2,
        1,
        (
            +0,
            [
                (-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
            ],
            [
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31')
            ]
        )
    ),
    (
        tree_2,
        2,
        (
            +0,
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
            ],
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
            ]
        )
    ),
    (
        tree_3,
        0,
        (
            +1,
            [],
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            ]
        )
    ),
    (
        tree_3,
        1,
        (
            +0,
            [
                (-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
            ],
            [
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            ]
        )
    ),
    (
        tree_3,
        2,
        (
            +0,
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
            ],
            [
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            ]
        )
    ),
    (
        tree_3,
        3,
        (
            +1,
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            ],
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            ]
        )
    ),
    (
        tree_4,
        0,
        (
            +0,
            [],
            [
                (-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
            ]
        )
    ),
    (
        tree_4,
        1,
        (
            +0,
            [
                (-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
            ],
            [
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138')
            ]
        )
    ),
    (
        tree_4,
        2,
        (
            +0,
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
            ],
            [
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138')
            ]
        )
    ),
    (
        tree_4,
        3,
        (
            +1,
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            ],
            [
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d')
            ]
        )
    ),
    (
        tree_4,
        4,
        (
            +0,
            [
                (-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
            ],
            [
                (-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
            ]
        )
    ),
    (
        tree_5,
        0,
        (
            +1,
            [],
            [
                (-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            ]
        )
    ),
    (
        tree_5,
        1,
        (
            +0,
            [
                (-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
            ],
            [
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'),
                (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            ]
        )
    ),
    (
        tree_5,
        2,
        (
            +0,
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
            ],
            [
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'),
                (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            ]
        )
    ),
    (
        tree_5,
        3,
        (
            +1,
            [
                (-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            ],
            [
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d'),
                (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            ]
        )
    ),
    (
        tree_5,
        4,
        (
            +0,
            [
                (-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
            ],
            [
                (+1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            ]
        )
    ),
    (
        tree_5,
        5,
        (
            +1,
            [
                (-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            ],
            [
                (-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            ]
        )
    ),
]


@pytest.mark.parametrize('tree, offset, height', no_perfect_node)
def test_no_perfect_node(tree, offset, height):
    assert not tree.get_perfect_node(offset, height)

@pytest.mark.parametrize('tree, offset, height, node', perfect_nodes)
def test_perfect_node(tree, offset, height, node):
    assert tree.get_perfect_node(offset, height) is node

@pytest.mark.parametrize('tree, subsize', no_principal_nodes)
def test_no_principal_nodes(tree, subsize):
    assert tree.get_signed_principals(subsize) == []

@pytest.mark.parametrize('tree, subsize, nodes', principal_nodes)
def test_principal_nodes(tree, subsize, nodes):
    assert tree.get_signed_principals(subsize) == nodes

@pytest.mark.parametrize('tree, principals, complement', complements)
def test_consisteny_complement(tree, principals, complement):
    assert tree.get_consistency_complement(principals) == complement

@pytest.mark.parametrize('tree, size1, path', paths)
def test_consistency_path(tree, size1, path):
    size2 = tree.get_size()
    assert tree.consistency_path(0, size1, size2, 0) == path

import pytest

from tests.conftest import option, resolve_backend

MerkleTree = resolve_backend(option)


tree_0 = MerkleTree.init_from_entries()
tree_1 = MerkleTree.init_from_entries('a')
tree_2 = MerkleTree.init_from_entries('a', 'b')
tree_3 = MerkleTree.init_from_entries('a', 'b', 'c')
tree_4 = MerkleTree.init_from_entries('a', 'b', 'c', 'd')
tree_5 = MerkleTree.init_from_entries('a', 'b', 'c', 'd', 'e')


paths = [
    (
        tree_1, 0,
        (
            [0],
            [
                b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'
            ]
        )
    ),
    (
        tree_2, 0,
        (
            [0, 0],
            [
                b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
            ]
        )
    ),
    (
        tree_2, 1,
        (
            [1, 0],
            [
                b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
            ]
        )
    ),
    (
        tree_3, 0,
        (
            [0, 0, 0],
            [
                b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
            ]
        )
    ),
    (
        tree_3, 1,
        (
            [1, 0, 0],
            [
                b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
            ]
        )
    ),
    (
        tree_3, 2,
        (
            [1, 0],
            [
                b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
                b'4c64254e6636add7f281ff49278beceb26378bd0021d1809974994e6e233ec35',
            ]
        )
    ),
    (
        tree_4, 0,
        (
            [0, 0, 0],
            [
                b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                b'40e2511a6323177e537acb2e90886e0da1f84656fd6334b89f60d742a3967f09',
            ]
        )
    ),
    (
        tree_4, 1,
        (
            [1, 0, 0],
            [
                b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                b'40e2511a6323177e537acb2e90886e0da1f84656fd6334b89f60d742a3967f09',
            ]
        )
    ),
    (
        tree_4, 2,
        (
            [0, 1, 0],
            [
                b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
                b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d',
                b'4c64254e6636add7f281ff49278beceb26378bd0021d1809974994e6e233ec35',
            ]
        )
    ),
    (
        tree_4, 3,
        (
            [1, 1, 0],
            [
                b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d',
                b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
                b'4c64254e6636add7f281ff49278beceb26378bd0021d1809974994e6e233ec35',
            ]
        )
    ),
    (
        tree_5, 0,
        (
            [0, 0, 0, 0],
            [
                b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                b'40e2511a6323177e537acb2e90886e0da1f84656fd6334b89f60d742a3967f09',
                b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4',
            ]
        )
    ),
    (
        tree_5, 1,
        (
            [1, 0, 0, 0],
            [
                b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                b'40e2511a6323177e537acb2e90886e0da1f84656fd6334b89f60d742a3967f09',
                b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4',
            ]
        )
    ),
    (
        tree_5, 2,
        (
            [0, 1, 0, 0],
            [
                b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
                b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d',
                b'4c64254e6636add7f281ff49278beceb26378bd0021d1809974994e6e233ec35',
                b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4',
            ]
        )
    ),
    (
        tree_5, 3,
        (
            [1, 1, 0, 0],
            [
                b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d',
                b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
                b'4c64254e6636add7f281ff49278beceb26378bd0021d1809974994e6e233ec35',
                b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4',
            ]
        )
    ),
    (
        tree_5, 4,
        (
            [1, 0],
            [
                b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4',
                b'9dc1674ae1ee61c90ba50b6261e8f9a47f7ea07d92612158edfe3c2a37c6d74c',
            ]
        )
    ),
]


@pytest.mark.parametrize('tree, offset, path', paths)
def test_inclusion_path(tree, offset, path):
    size = tree.get_size()
    assert tree.inclusion_path(0, offset, size, 0) == path

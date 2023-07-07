import pytest
from tests.conftest import option, resolve_backend

MerkleTree = resolve_backend(option)

entries = [b'a', b'b', b'c', b'd', b'e']

tree_1 = MerkleTree.init_from_entries(entries[:1])
tree_2 = MerkleTree.init_from_entries(entries[:2])
tree_3 = MerkleTree.init_from_entries(entries[:3])
tree_4 = MerkleTree.init_from_entries(entries[:4])
tree_5 = MerkleTree.init_from_entries(entries[:5])


fixtures = [
    (
        tree_1,
        0,
        (
            [0],
            [0],
            [
                '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
            ]
        )
    ),
    (
        tree_1,
        1,
        (
            [0],
            [1],
            [
                '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
            ]
        )
    ),
    (
        tree_2,
        0,
        (
            [0, 0],
            [0, 0],
            [
                '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
            ]
        )
    ),
    (
        tree_2,
        1,
        (
            [1, 0],
            [0, 1],
            [
                '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
            ]
        )
    ),
    (
        tree_2,
        2,
        (
            [0],
            [1],
            [
                'b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb',
            ]
        )
    ),
    (
        tree_3,
        0,
        (
            [0, 0, 0],
            [0, 0, 0],
            [
                '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
            ]
        )
    ),
    (
        tree_3,
        1,
        (
            [1, 0, 0],
            [0, 1, 0],
            [
                '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
            ]
        )
    ),
    (
        tree_3,
        2,
        (
            [1, 0],
            [0, 1],
            [
                '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
                'b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb',
            ]
        )
    ),
    (
        tree_3,
        3,
        (
            [0],
            [1],
            [
                '36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1'
            ]
        )
    ),
    (
        tree_4,
        0,
        (
            [0, 0, 0],
            [0, 0, 0],
            [
                '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                'dbbd68c325614a73dacb4e7a87a2b7b4ae9724b489e5629ee83151fe8f0eafd7',
            ]
        )
    ),
    (
        tree_4,
        1,
        (
            [1, 0, 0],
            [0, 1, 0],
            [
                '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                'dbbd68c325614a73dacb4e7a87a2b7b4ae9724b489e5629ee83151fe8f0eafd7',
            ]
        )
    ),
    (
        tree_4,
        2,
        (
            [0, 1, 0],
            [0, 0, 1],
            [
                '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
                'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d',
                'b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb',
            ]
        )
    ),
    (
        tree_4,
        3,
        (
            [1, 1, 0],
            [0, 1, 1],
            [
                'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d',
                '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
                'b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb',
            ]
        )
    ),
    (
        tree_4,
        4,
        (
            [0],
            [1],
            [
                '33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0',
            ]
        )
    ),
    (
        tree_5,
        0,
        (
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [
                '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                'dbbd68c325614a73dacb4e7a87a2b7b4ae9724b489e5629ee83151fe8f0eafd7',
                '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4',
            ]
        )
    ),
    (
        tree_5,
        1,
        (
            [1, 0, 0, 0],
            [0, 1, 0, 0],
            [
                '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31',
                '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c',
                'dbbd68c325614a73dacb4e7a87a2b7b4ae9724b489e5629ee83151fe8f0eafd7',
                '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4',
            ]
        )
    ),
    (
        tree_5,
        2,
        (
            [0, 1, 0, 0],
            [0, 0, 1, 0],
            [
                '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
                'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d',
                'b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb',
                '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4',
            ]
        )
    ),
    (
        tree_5,
        3,
        (
            [1, 1, 0, 0],
            [0, 1, 1, 0],
            [
                'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d',
                '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8',
                'b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb',
                '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4',
            ]
        )
    ),
    (
        tree_5,
        4,
        (
            [1, 0],
            [0, 1],
            [
                '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4',
                '33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0',
            ]
        )
    ),
    (
        tree_5,
        5,
        (
            [0],
            [1],
            [
                'fe14a5426fbd70c0fa73f52342afed0da0bd23c4838662ccf6b88a3070ead97b',
            ]
        )
    ),
]


@pytest.mark.parametrize('tree, lsize, expected', fixtures)
def test_consistency_path(tree, lsize, expected):
    rsize = tree.get_size()
    rule, subset, path = tree._consistency_path(0, lsize, rsize, 0)
    path = list(map(lambda _: _.hex(), path))
    assert (rule, subset, path) == expected

"""
Tests the internal functionalities of Merkle-trees invoked in the
implementation of audit- and consistency proof generation
"""

import pytest
import os
import json

from pymerkle.core import MerkleTree
from pymerkle.exceptions import (NoSubtreeException, NoPathException,
    NoPrincipalSubroots,)


# Audit proof implementation

_0_leaves_tree = MerkleTree()
_1_leaves_tree = MerkleTree('a')
_2_leaves_tree = MerkleTree('a', 'b')
_3_leaves_tree = MerkleTree('a', 'b', 'c')
_4_leaves_tree = MerkleTree('a', 'b', 'c', 'd')
_5_leaves_tree = MerkleTree('a', 'b', 'c', 'd', 'e')

__no_path_exceptions = [
    (_0_leaves_tree, +0),
    (_1_leaves_tree, -1),
    (_1_leaves_tree, +1),
    (_2_leaves_tree, -1),
    (_2_leaves_tree, +2),
    (_3_leaves_tree, -1),
    (_3_leaves_tree, +3),
    (_4_leaves_tree, -1),
    (_4_leaves_tree, +4),
    (_5_leaves_tree, -1),
    (_5_leaves_tree, +5)
]


@pytest.mark.parametrize('tree, index', __no_path_exceptions)
def test_audit_NoPathException(tree, index):
    """
    Tests NoPathException upon requesting audit-path from an empty Merkle-tree
    or based upon an index either negative or exceeding the tree's current length
    """
    with pytest.raises(NoPathException):
        tree.audit_path(index)


__audit_paths = [
    (
        _1_leaves_tree, 0,
        (
            0,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
            )

        )
    ),
    (
        _2_leaves_tree, 0,
        (
            0,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (-1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31')
            )
        )
    ),
    (
        _2_leaves_tree, 1,
        (
            1,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (-1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31')
            )
        )
    ),
    (
        _3_leaves_tree, 0,
        (
            0,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            )
        )
    ),
    (
        _3_leaves_tree, 1,
        (
            1,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (-1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            )
        )
    ),
    (
        _3_leaves_tree, 2,
        (
            1,
            (
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            )
        )
    ),
    (
        _4_leaves_tree, 0,
        (
            0,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (-1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138')
            )
        )
    ),
    (
        _4_leaves_tree, 1,
        (
            1,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (-1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (-1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138')
            )
        )
    ),
    (
        _4_leaves_tree, 2,
        (
            1,
            (
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d')
            )
        )
    ),
    (
        _4_leaves_tree, 3,
        (
            2,
            (
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d')
            )
        )
    ),
    (
        _5_leaves_tree, 0,
        (
            0,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            )
        )
    ),
    (
        _5_leaves_tree, 1,
        (
            1,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (-1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            )
        )
    ),
    (
        _5_leaves_tree, 2,
        (
            1,
            (
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            )
        )
    ),
    (
        _5_leaves_tree, 3,
        (
            2,
            (
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            )
        )
    ),
    (
        _5_leaves_tree, 4,
        (
            1,
            (
                (+1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            )
        )
    ),
]


@pytest.mark.parametrize('tree, index, path', __audit_paths)
def test_audit_path(tree, index, path):
    assert tree.audit_path(index) == path


# Consistency proof implementation

__no_subtree_exceptions = [
    (_0_leaves_tree, 0, 'anything'),
    (_1_leaves_tree, 1, 'anything'),
    (_2_leaves_tree, 2, 'anything'),
    (_2_leaves_tree, 0, 2),
    (_2_leaves_tree, 1, 1),
    (_3_leaves_tree, 3, 'anything'),
    (_3_leaves_tree, 0, 3),
    (_3_leaves_tree, 1, 1),
    (_3_leaves_tree, 2, 1),
    (_4_leaves_tree, 4, 'anything'),
    (_4_leaves_tree, 0, 3),
    (_4_leaves_tree, 1, 1),
    (_4_leaves_tree, 2, 2),
    (_4_leaves_tree, 3, 1),
    (_5_leaves_tree, 5, 'anything'),
    (_5_leaves_tree, 0, 3),
    (_5_leaves_tree, 0, 4),
    (_5_leaves_tree, 1, 1),
    (_5_leaves_tree, 2, 2),
    (_5_leaves_tree, 3, 1),
    (_5_leaves_tree, 4, 1),
]

@pytest.mark.parametrize('tree, start, height', __no_subtree_exceptions)
def test_NoSubtreeException(tree, start, height):
    with pytest.raises(NoSubtreeException):
        tree.subroot(start, height)


__subroots = [
    (_1_leaves_tree, 0, 0, _1_leaves_tree.leaves[0]),
    (_2_leaves_tree, 0, 0, _2_leaves_tree.leaves[0]),
    (_2_leaves_tree, 0, 1, _2_leaves_tree.root),
    (_2_leaves_tree, 1, 0, _2_leaves_tree.leaves[1]),
    (_3_leaves_tree, 0, 0, _3_leaves_tree.leaves[0]),
    (_3_leaves_tree, 0, 1, _3_leaves_tree.leaves[0].child),
    (_3_leaves_tree, 1, 0, _3_leaves_tree.leaves[1]),
    (_3_leaves_tree, 2, 0, _3_leaves_tree.leaves[2]),
    (_4_leaves_tree, 0, 0, _4_leaves_tree.leaves[0]),
    (_4_leaves_tree, 0, 1, _4_leaves_tree.leaves[0].child),
    (_4_leaves_tree, 0, 2, _4_leaves_tree.root),
    (_4_leaves_tree, 1, 0, _4_leaves_tree.leaves[1]),
    (_4_leaves_tree, 2, 0, _4_leaves_tree.leaves[2]),
    (_4_leaves_tree, 2, 1, _4_leaves_tree.leaves[2].child),
    (_4_leaves_tree, 3, 0, _4_leaves_tree.leaves[3]),
    (_5_leaves_tree, 0, 0, _5_leaves_tree.leaves[0]),
    (_5_leaves_tree, 0, 1, _5_leaves_tree.leaves[0].child),
    (_5_leaves_tree, 0, 2, _5_leaves_tree.leaves[0].child.child),
    (_5_leaves_tree, 1, 0, _5_leaves_tree.leaves[1]),
    (_5_leaves_tree, 2, 0, _5_leaves_tree.leaves[2]),
    (_5_leaves_tree, 2, 1, _5_leaves_tree.leaves[2].child),
    (_5_leaves_tree, 3, 0, _5_leaves_tree.leaves[3]),
    (_5_leaves_tree, 4, 0, _5_leaves_tree.leaves[4]),
]


@pytest.mark.parametrize('tree, start, height, subroot', __subroots)
def test_subroot(tree, start, height, subroot):
    assert tree.subroot(start, height) is subroot

__no_principal_subroots_exceptions = [
    (_1_leaves_tree, -1),
    (_1_leaves_tree, +2),
    (_2_leaves_tree, -1),
    (_2_leaves_tree, +3),
    (_3_leaves_tree, -1),
    (_3_leaves_tree, +4),
    (_4_leaves_tree, -1),
    (_4_leaves_tree, +5),
    (_5_leaves_tree, -1),
    (_5_leaves_tree, +6),
]

@pytest.mark.parametrize("tree, sublength", __no_principal_subroots_exceptions)
def test_NoSubrootsException(tree, sublength):
    with pytest.raises(NoPrincipalSubroots):
        tree.principal_subroots(sublength)

__principal_subroots = [
    (_0_leaves_tree, 0, []),
    (_1_leaves_tree, 0, []),
    (_1_leaves_tree, 1, [(+1, _1_leaves_tree.root)]),
    (_2_leaves_tree, 0, []),
    (_2_leaves_tree, 1, [(+1, _2_leaves_tree.leaves[0])]),
    (_2_leaves_tree, 2, [(+1, _2_leaves_tree.root)]),
    (_3_leaves_tree, 0, []),
    (_3_leaves_tree, 1, [(+1, _3_leaves_tree.leaves[0])]),
    (_3_leaves_tree, 2, [(+1, _3_leaves_tree.leaves[0].child)]),
    (_3_leaves_tree, 3, [(+1, _3_leaves_tree.leaves[0].child), (+1, _3_leaves_tree.leaves[2])]),
    (_4_leaves_tree, 0, []),
    (_4_leaves_tree, 1, [(+1, _4_leaves_tree.leaves[0])]),
    (_4_leaves_tree, 2, [(+1, _4_leaves_tree.leaves[0].child)]),
    (_4_leaves_tree, 3, [(+1, _4_leaves_tree.leaves[0].child), (+1, _4_leaves_tree.leaves[2])]),
    (_4_leaves_tree, 4, [(+1, _4_leaves_tree.root)]),
    (_5_leaves_tree, 0, []),
    (_5_leaves_tree, 1, [(+1, _5_leaves_tree.leaves[0])]),
    (_5_leaves_tree, 2, [(+1, _5_leaves_tree.leaves[0].child)]),
    (_5_leaves_tree, 3, [(+1, _5_leaves_tree.leaves[0].child), (+1, _5_leaves_tree.leaves[2])]),
    (_5_leaves_tree, 4, [(+1, _5_leaves_tree.leaves[0].child.child)]),
    (_5_leaves_tree, 5, [(+1, _5_leaves_tree.leaves[0].child.child), (+1, _5_leaves_tree.leaves[-1])]),
]

@pytest.mark.parametrize("tree, sublength, principal_subroots", __principal_subroots)
def test_principalSubroots(tree, sublength, principal_subroots):
    assert tree.principal_subroots(sublength) == principal_subroots


__minimal_complements = [
    (_0_leaves_tree, [], []),
    (_1_leaves_tree, [], [(+1, _1_leaves_tree.leaves[0])]),
    (_1_leaves_tree, [(+1, _1_leaves_tree.root)], []),
    (_2_leaves_tree, [], [(+1, _2_leaves_tree.root)]),
    (_2_leaves_tree, [(+1, _2_leaves_tree.leaves[0])], [(+1, _2_leaves_tree.leaves[1])]),
    (_2_leaves_tree, [(+1, _2_leaves_tree.root)], []),
    (_3_leaves_tree, [], [(+1, _3_leaves_tree.leaves[0].child), (+1, _3_leaves_tree.leaves[2])]),
    (_3_leaves_tree, [(+1, _3_leaves_tree.leaves[0])], [(+1, _3_leaves_tree.leaves[1]), (+1, _3_leaves_tree.leaves[2])]),
    (_3_leaves_tree, [(+1, _3_leaves_tree.leaves[0].child)], [(+1, _3_leaves_tree.leaves[2])]),
    (_3_leaves_tree, [(+1, _3_leaves_tree.leaves[0].child), (+1, _3_leaves_tree.leaves[2])], []),
    (_4_leaves_tree, [], [(+1, _4_leaves_tree.root)]),
    (_4_leaves_tree, [(+1, _4_leaves_tree.leaves[0])], [(+1, _4_leaves_tree.leaves[1]), (+1, _4_leaves_tree.leaves[2].child)]),
    (_4_leaves_tree, [(+1, _4_leaves_tree.leaves[0].child)], [(+1, _4_leaves_tree.leaves[2].child)]),
    (_4_leaves_tree, [(+1, _4_leaves_tree.leaves[0].child), (+1, _4_leaves_tree.leaves[2])], [(-1, _4_leaves_tree.leaves[3])]),
    (_4_leaves_tree, [(+1, _4_leaves_tree.root)], []),
    (_5_leaves_tree, [], [(+1, _5_leaves_tree.leaves[0].child.child), (+1, _5_leaves_tree.leaves[4])]),
    (_5_leaves_tree, [(+1, _5_leaves_tree.leaves[0])], [(+1, _5_leaves_tree.leaves[1]), (+1, _5_leaves_tree.leaves[2].child), (+1, _5_leaves_tree.leaves[4])]),
    (_5_leaves_tree, [(+1, _5_leaves_tree.leaves[0].child)], [(+1, _5_leaves_tree.leaves[2].child), (+1, _5_leaves_tree.leaves[4])]),
    (_5_leaves_tree, [(+1, _5_leaves_tree.leaves[0].child), (+1, _5_leaves_tree.leaves[2])], [(-1, _5_leaves_tree.leaves[3]), (+1, _5_leaves_tree.leaves[4])]),
    (_5_leaves_tree, [(+1, _5_leaves_tree.leaves[0].child.child)], [(+1, _5_leaves_tree.leaves[4])]),
    (_5_leaves_tree, [(+1, _5_leaves_tree.leaves[0].child.child), (+1, _5_leaves_tree.leaves[4])], []),
]

@pytest.mark.parametrize("tree, subroots, _minimal_complement", __minimal_complements)
def test_minimal_complement(tree, subroots, _minimal_complement):
    assert tree.minimal_complement(subroots) == _minimal_complement

__no_path_exceptions = [
    (_0_leaves_tree, -1),
    (_0_leaves_tree, +0),
    (_0_leaves_tree, +1),
    (_1_leaves_tree, -1),
    (_1_leaves_tree, +2),
    (_2_leaves_tree, -1),
    (_2_leaves_tree, +3),
    (_3_leaves_tree, -1),
    (_3_leaves_tree, +4),
    (_4_leaves_tree, -1),
    (_4_leaves_tree, +5),
    (_5_leaves_tree, -1),
    (_5_leaves_tree, +6)
]


@pytest.mark.parametrize("tree, sublength", __no_path_exceptions)
def test_consistency_NoPathException(tree, sublength):
    """
    Tests NoPathException upon requesting consistency-path for incompatible sublength
    """
    with pytest.raises(NoPathException):
        tree.consistency_path(sublength)

__consistency_paths = [
    (_1_leaves_tree, 0, (+0, (),
                             ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),))),
    (_1_leaves_tree, 1, (+0, ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),),
                             ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),))),
    (_2_leaves_tree, 0, (+0, (),
                             ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),))),
    (_2_leaves_tree, 1, (+0, ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),),
                             ((+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                              (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31')))),
    (_2_leaves_tree, 2, (+0, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),),
                             ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),))),
    (_3_leaves_tree, 0, (+1, (),
                             ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')))),
    (_3_leaves_tree, 1, (+0, ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),),
                             ((+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                              (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                              (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')))),
    (_3_leaves_tree, 2, (+0, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),),
                             ((+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')))),
    (_3_leaves_tree, 3, (+1, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')),
                             ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')))),
    (_4_leaves_tree, 0, (+0, (),
                             ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),))),
    (_4_leaves_tree, 1, (+0, ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),),
                             ((+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                              (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                              (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138')))),
    (_4_leaves_tree, 2, (+0, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),),
                             ((+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138')))),
    (_4_leaves_tree, 3, (+1, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')),
                             ((+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                              (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d')))),
    (_4_leaves_tree, 4, (+0, ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),),
                             ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),))),
    (_5_leaves_tree, 0, (+1, (),
                             ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                              (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
    (_5_leaves_tree, 1, (+0, ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),),
                             ((+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                              (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                              (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'),
                              (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
    (_5_leaves_tree, 2, (+0, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),),
                             ((+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'),
                              (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
    (_5_leaves_tree, 3, (+1, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')),
                             ((+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                              (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d'),
                              (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
    (_5_leaves_tree, 4, (+0, ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),),
                             ((+1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                              (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
    (_5_leaves_tree, 5, (+1, ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                              (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')),
                             ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                              (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
]

@pytest.mark.parametrize("tree, sublength, consistency_path", __consistency_paths)
def test_consistency_path(tree, sublength, consistency_path):
    assert tree.consistency_path(sublength) == consistency_path

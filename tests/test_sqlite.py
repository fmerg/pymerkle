import pytest

from pymerkle import SqliteTree, InmemoryTree


entries = [b'%d' % i for i in range(10)]


def make_tree(**opts):
    tree = SqliteTree(':memory:', **opts)
    tree.append_entries(entries[:3])

    return tree


def test_append_entries_atomic():
    tree = make_tree()
    state = tree.get_state()

    with pytest.raises(ValueError):
        tree.append_entries(entries[3:6] + ['nonbinary'] + entries[6:],
            chunksize=2)

    assert tree.get_size() == 3
    assert tree.get_state() == state


def test_append_entries_iterable():
    tree = make_tree()

    assert tree.append_entries(e for e in entries[3:]) == len(entries)
    assert tree.get_state() == \
        InmemoryTree.init_from_entries(entries).get_state()


@pytest.mark.parametrize('chunksize', [1, 3, 100])
def test_append_entries_chunksize(chunksize):
    tree = make_tree()

    assert tree.append_entries(entries[3:], chunksize) == len(entries)
    assert tree.get_state() == \
        InmemoryTree.init_from_entries(entries).get_state()


def test_append_entries_empty():
    tree = make_tree()

    assert tree.append_entries([]) == 3


def test_append_entries_encoding():

    class Tree(SqliteTree):

        def _encode_entry(self, data):
            return data.upper()

    tree1 = Tree(':memory:')
    tree1.append_entries([b'foo', b'bar'])

    tree2 = Tree(':memory:')
    tree2.append_entry(b'foo')
    tree2.append_entry(b'bar')

    assert tree1.get_leaf(1) == tree2.get_leaf(1) == tree1.hash_buff(b'FOO')
    assert tree1.get_state() == tree2.get_state()

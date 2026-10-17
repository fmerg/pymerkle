import sqlite3

import pytest

from pymerkle import SqliteTree, InmemoryTree


entries = [b'%d' % i for i in range(10)]


def make_tree(**opts):
    tree = SqliteTree(':memory:', **opts)
    tree.append_entries(entries[:3])

    return tree


def test_append_entries_atomic():
    tree = make_tree()
    state = tree.get_root()

    with pytest.raises(ValueError):
        tree.append_entries(entries[3:6] + ['nonbinary'] + entries[6:],
            chunksize=2)

    assert tree.get_size() == 3
    assert tree.get_root() == state


def test_append_entries_iterable():
    tree = make_tree()

    assert tree.append_entries(e for e in entries[3:]) == len(entries)
    assert tree.get_root() == \
        InmemoryTree.init_from_entries(entries).get_root()


@pytest.mark.parametrize('chunksize', [1, 3, 100])
def test_append_entries_chunksize(chunksize):
    tree = make_tree()

    assert tree.append_entries(entries[3:], chunksize) == len(entries)
    assert tree.get_root() == \
        InmemoryTree.init_from_entries(entries).get_root()


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
    assert tree1.get_root() == tree2.get_root()


@pytest.mark.parametrize('statement', [
    'DELETE FROM leaf WHERE id = 2',
    'DELETE FROM leaf',
    "UPDATE leaf SET hash = x'00' WHERE id = 1",
])
def test_leaf_table_append_only(statement):
    """
    Deleting rows used to break the contiguity of leaf indices, so that
    subsequent operations failed or returned wrong results.
    """
    tree = make_tree()
    state = tree.get_root()

    with pytest.raises(sqlite3.DatabaseError):
        with tree.con:
            tree.con.execute(statement)

    tree.append_entry(b'new')
    assert tree.get_size() == 4
    assert tree.get_root(3) == state
    assert tree.get_root() == \
        InmemoryTree.init_from_entries(entries[:3] + [b'new']).get_root()


def test_non_contiguous_database(tmp_path):
    dbfile = str(tmp_path / 'merkle.db')
    with SqliteTree(dbfile) as tree:
        tree.append_entries(entries)

    con = sqlite3.connect(dbfile)
    with con:
        con.execute('DROP TRIGGER leaf_no_delete')
        con.execute('DELETE FROM leaf WHERE id = 5')
    con.close()

    with pytest.raises(ValueError):
        SqliteTree(dbfile)


def test_reopen_database(tmp_path):
    dbfile = str(tmp_path / 'merkle.db')
    with SqliteTree(dbfile) as tree:
        tree.append_entries(entries)
        state = tree.get_root()

    with SqliteTree(dbfile) as tree:
        assert tree.get_size() == len(entries)
        assert tree.get_root() == state

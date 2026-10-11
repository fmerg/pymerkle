import sys
import threading

import pytest

from pymerkle import InmemoryTree, verify_inclusion, verify_consistency


@pytest.fixture(autouse=True)
def frequent_thread_switching():
    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    yield
    sys.setswitchinterval(interval)


def run_threads(*targets):
    errors = []

    def guard(target):
        try:
            target()
        except Exception as err:
            errors.append(err)

    threads = [threading.Thread(target=guard, args=(t,)) for t in targets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, errors


def make_tree():
    return InmemoryTree.init_from_entries([b'%d' % i for i in range(64)],
        threshold=2)


def test_concurrent_appends():
    tree = make_tree()

    def writer(i):
        return lambda: [tree.append_entry(b'%d-%d' % (i, j))
                        for j in range(300)]

    run_threads(*[writer(i) for i in range(4)])

    expected = InmemoryTree.init_from_entries(l.data for l in tree.leaves)

    assert tree.get_size() == 64 + 4 * 300
    assert tree.get_state() == expected.get_state()
    assert tree.get_state() == tree._get_root_naive(0, tree.get_size())


def test_reads_during_appends():
    tree = make_tree()
    done = threading.Event()
    observed = []

    def writer():
        for i in range(2000):
            tree.append_entry(b'x%d' % i)
        done.set()

    def reader():
        while not done.is_set():
            size = tree.get_size()
            observed.append((size, tree.get_state(size),
                tree.prove_inclusion(1, size),
                tree.prove_consistency(size // 2 or 1, size)))

    run_threads(writer, reader, reader)

    # The tree is append-only, so earlier states can be recomputed afterwards
    assert observed
    for size, state, inclusion, consistency in observed:
        assert state == tree._get_root_naive(0, size)
        verify_inclusion(tree.get_leaf(1), state, inclusion, index=1,
            size=size)
        verify_consistency(tree.get_state(size // 2 or 1), state,
            consistency, size2=size)

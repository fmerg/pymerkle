import hashlib
import tracemalloc

from pymerkle import InmemoryTree, SqliteTree


def test_cache_capacity_accounts_memory():
    """
    Cache entries used to be accounted by digest length only, so that real
    memory usage exceeded the configured capacity several times.
    """
    tree = InmemoryTree()
    cache = tree.cache
    count = 20_000

    tracemalloc.start()
    for i in range(count):
        cache[(i * 1024 + 10 ** 9, 1024)] = hashlib.sha256(b'%d' % i).digest()
    measured, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert 0.5 < cache.currsize / measured < 2


def test_cache_capacity_respected():
    tree = SqliteTree(':memory:', threshold=2, capacity=2048)
    tree.append_entries([b'%d' % i for i in range(64)])
    tree.get_state()
    for size in range(1, tree.get_size() + 1):
        tree.prove_consistency(size)

    info = tree.get_cache_info()
    assert 0 < info.size <= info.capacity == 2048

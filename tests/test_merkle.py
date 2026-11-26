import hashlib

import pytest

from anagram.core.crypto import merkle


def leaves(n):
    return [merkle.leaf_hash(f"leaf-{i}".encode()) for i in range(n)]


def test_known_values():
    assert merkle.EMPTY_ROOT.hex() == hashlib.sha256(b"").hexdigest()
    assert merkle.root([]) == merkle.EMPTY_ROOT
    one = merkle.leaf_hash(b"")
    assert one.hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert merkle.root([one]) == one
    two = [merkle.leaf_hash(b"a"), merkle.leaf_hash(b"b")]
    assert merkle.root(two) == merkle.node_hash(*two)
    three = [merkle.leaf_hash(x) for x in (b"a", b"b", b"c")]
    assert merkle.root(three) == merkle.node_hash(merkle.node_hash(three[0], three[1]), three[2])


@pytest.mark.parametrize("size", list(range(1, 34)) + [64, 65, 127, 255, 256, 257])
def test_inclusion_all_indices(size):
    hs = leaves(size)
    sub = merkle.list_subtree(hs)
    r = merkle.root(hs)
    for i in range(size):
        path = merkle.inclusion_path(sub, i, size)
        assert merkle.verify_inclusion(hs[i], i, size, path, r)
        # Wrong index, wrong leaf, wrong size, cut path all fail.
        if size > 1:
            assert not merkle.verify_inclusion(hs[i], (i + 1) % size, size, path, r)
            assert not merkle.verify_inclusion(hs[(i + 1) % size], i, size, path, r)
            assert not merkle.verify_inclusion(hs[i], i, size, path[:-1], r)


def test_inclusion_bad_index():
    hs = leaves(4)
    assert not merkle.verify_inclusion(hs[0], 4, 4, [], merkle.root(hs))
    with pytest.raises(ValueError):
        merkle.inclusion_path(merkle.list_subtree(hs), 4, 4)


@pytest.mark.parametrize("new_size", list(range(1, 34)) + [100])
def test_consistency_all_pairs(new_size):
    hs = leaves(new_size)
    sub = merkle.list_subtree(hs)
    new_root = merkle.root(hs)
    for old_size in range(0, new_size + 1):
        old_root = merkle.root(hs[:old_size])
        path = merkle.consistency_path(sub, old_size, new_size)
        assert merkle.verify_consistency(old_size, new_size, path, old_root, new_root)
        if 0 < old_size < new_size:
            bad_old = merkle.root(leaves(old_size + 1)[1:])
            assert not merkle.verify_consistency(old_size, new_size, path, bad_old, new_root)
            assert not merkle.verify_consistency(old_size, new_size, path, old_root, bad_old)
            assert not merkle.verify_consistency(old_size, new_size, path[:-1], old_root, new_root)


def test_consistency_rejects_shrink():
    hs = leaves(5)
    assert not merkle.verify_consistency(5, 4, [], merkle.root(hs), merkle.root(hs[:4]))


@pytest.mark.parametrize("n", [0, 1, 2, 3, 5, 8, 13, 100, 1025])
def test_streaming_root_matches(n):
    hs = leaves(n)
    s = merkle.StreamingRoot()
    for h in hs:
        s.add_leaf_hash(h)
    assert s.root() == merkle.root(hs)


def test_frontier_matches_root():
    from anagram.core.crypto.merkle import frontier_append, frontier_root

    leaves = [merkle.leaf_hash(bytes([i])) for i in range(40)]
    f: list[bytes] = []
    for n, leaf in enumerate(leaves):
        assert frontier_root(f) == merkle.root(leaves[:n])
        f = frontier_append(f, n, leaf)
    assert frontier_root(f) == merkle.root(leaves)

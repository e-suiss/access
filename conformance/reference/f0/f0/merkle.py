import hashlib


def sha256(data):
    return hashlib.sha256(data).digest()


def leaf_hash(data):
    # OP-106 m.12
    return sha256(b"\x00" + data)


def node_hash(left, right):
    # OP-106 m.12
    return sha256(b"\x01" + left + right)


def tree_hash(leaves):
    # RFC 9162 §2.1.1
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return node_hash(tree_hash(leaves[:k]), tree_hash(leaves[k:]))


def verify_inclusion(index, size, leaf, path, root):
    # RFC 9162 §2.1.3.2
    if index >= size:
        return False
    fn = index
    sn = size - 1
    r = leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first, second, first_root, second_root, path):
    # RFC 9162 §2.1.4.2
    if first > second:
        return False
    if first == second:
        return not path and first_root == second_root
    if first == 0:
        return False
    if not path:
        return False
    if first & (first - 1) == 0:
        path = [first_root] + list(path)
    fn = first - 1
    sn = second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = path[0]
    sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root

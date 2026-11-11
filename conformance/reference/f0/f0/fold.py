"""State fold over decision record effects, from L2-REC-2 and L2-REC-3."""

from .codec import encode

MAX_KEY = 512
OUTCOMES = ("allow", "deny", "require_action")


class FoldError(Exception):
    pass


def _claim_key(key):
    # L2-REC-2: a claim record writes only claim, member and successor keys
    from .codec import decode_canonical

    try:
        k = decode_canonical(key)
    except Exception:
        return False
    return isinstance(k, list) and len(k) > 0 and k[0] in ("claim", "member", "successor")


def effects(record):
    fields = record["fields"]
    listed = fields.get("effects")
    claim = record["kind"] == "claim"
    if record["kind"] != "decision" and not claim:
        # L2-REC-2: effects belong to decisions and admitted claims
        if listed is not None:
            raise FoldError("effects-outside-decision")
        return []
    if claim:
        if listed is None:
            return []
        if fields.get("disposition") != "admit":
            raise FoldError("effects-without-allow")
    else:
        outcome = fields.get("outcome")
        if not isinstance(outcome, dict) or outcome.get("outcome") not in OUTCOMES:
            raise FoldError("outcome")
        if listed is None:
            return []
        if outcome["outcome"] != "allow":
            raise FoldError("effects-without-allow")
    if not isinstance(listed, list) or len(listed) == 0:
        raise FoldError("effect")
    out = []
    keys = set()
    for effect in listed:
        if not isinstance(effect, list) or len(effect) not in (1, 2):
            raise FoldError("effect")
        key = effect[0]
        if not isinstance(key, bytes) or not 1 <= len(key) <= MAX_KEY:
            raise FoldError("effect")
        if claim and not _claim_key(key):
            raise FoldError("effects-outside-decision")
        if key in keys:
            raise FoldError("duplicate-effect")
        keys.add(key)
        out.append((key, effect[1] if len(effect) == 2 else None, len(effect) == 2))
    return out


def fold(records):
    """L2-REC-3: the state after records 1..n given in position order."""
    state = {}
    for index, record in enumerate(records):
        if record["pos"] != index + 1:
            raise FoldError("order")
        for key, value, present in effects(record):
            state[key] = (encode(value) if present else None, record["pos"])
    return state


# SEC21, SEC22, §13.6, OP-158 m.3 (b)
WITNESS_FRESHNESS_MS = 3_600_000


class GuardError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def rollback_guard(heads, replica, cited, cited_root, fork, now):
    fresh = [h for h in heads if h and h["at"] <= now and now - h["at"] <= WITNESS_FRESHNESS_MS]
    all_fresh = bool(heads) and len(fresh) == len(heads)
    roots = {}
    for h in fresh:
        roots.setdefault(h["size"], set()).add(bytes(h["root"]))
    forked = any(len(r) > 1 for r in roots.values())
    if forked != fork:
        raise GuardError("rollback-guard-fork")
    if not fresh:
        raise GuardError("rollback-guard-unwitnessed")
    highest = max(h["size"] for h in fresh)
    if cited > highest or (cited in roots and bytes(cited_root) not in roots[cited]):
        raise GuardError("rollback-guard-unwitnessed")
    if replica is not None and cited < replica:
        raise GuardError("rollback-guard")
    forks = sorted(size for size, r in roots.items() if len(r) > 1)
    if forks and not (cited <= replica if replica is not None else cited < forks[0]):
        raise GuardError("rollback-guard-fork")
    if replica is not None and all_fresh and not forked and replica == highest and cited == replica:
        return {"guard": "pass"}
    return {"guard": "lossy", "from": cited, "until": highest}


def pre_recovery(iat, recovered_at, nonce_known):
    # TI-RT3, U28: issued before the recovery and not in the continuing lineage
    return iat < recovered_at and not nonce_known

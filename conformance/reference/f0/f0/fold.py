"""State fold over decision record effects, from L2-REC-2 and L2-REC-3."""

from .codec import encode

MAX_KEY = 512
OUTCOMES = ("allow", "deny", "require_action")


class FoldError(Exception):
    pass


def effects(record):
    fields = record["fields"]
    listed = fields.get("effects")
    if record["kind"] != "decision":
        # L2-REC-2: effects belong to decisions
        if listed is not None:
            raise FoldError("effects-outside-decision")
        return []
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

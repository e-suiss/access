"""The superseded-at predicate (L0-SIG-80, §9.10, §13.3, P18, SEC25, U12, U27)."""

from . import merkle, note, record
from .codec import Rejection


def superseded_inclusion(binding, evidence):
    # L0-SIG-80
    superseded = binding.get("superseded")
    if superseded is None:
        return False
    log = note.parse_vkey(evidence["log"])
    witnesses = [w for w in (note.parse_vkey(v) for v in evidence["witnesses"])
                 if w["kind"] == note.COSIGNER_KEY and (w["name"], w["id"]) != (log["name"], log["id"])]
    try:
        (_, size, root, _), accepted = note.verify_checkpoint(evidence["note"], evidence["origin"], log, witnesses)
        disclosed = record.decode_disclosure(evidence["record"], envelope=False)
        leaf = record.leaf_hash(disclosed)
    except (note.NoteError, record.RecordError, Rejection):
        return False
    cosigned = any(t is not None and any((w["name"], w["id"]) == (n, i) for w in witnesses) for n, i, t in accepted)
    committed = record.commits_artefact(disclosed, evidence["artefact"])
    if (not cosigned or not committed or root != bytes(superseded["cited"][1])
            or not merkle.verify_inclusion(disclosed["pos"], size, leaf, evidence["path"], root)):
        return False
    at = bytes(superseded["at"][1])
    consistency = evidence.get("consistency")
    if consistency is None:
        return at == bytes(superseded["cited"][1])
    to_size, to_root, path = consistency
    return to_root == at and merkle.verify_consistency(size, to_size, root, to_root, path)

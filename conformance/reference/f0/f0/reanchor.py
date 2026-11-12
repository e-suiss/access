"""Post-quantum re-anchor evidence (CR-45 RA-5, RA-7, L0-SIG-81, OP-159 m.3 (h))."""

from . import merkle, note, record
from .codec import Rejection, decode_canonical
from .cose import CoseError, verify_sign1
from .keyscope import ML_DSA_NAMES, thumbprint

CHECKPOINT_CONTENT_TYPE = "application/access-pq-checkpoint"
COSIGN_CONTENT_TYPE = "application/access-pq-cosign"


def verify(sign1, content_type, key):
    if "ml_dsa" not in key or key["ml_dsa"][0] not in ML_DSA_NAMES:
        return None
    kid = thumbprint(key)
    try:
        _, payload = verify_sign1(sign1, content_type, [key["ml_dsa"][0]], {kid: key}, ml_dsa=True)
    except CoseError:
        return None
    return payload


def accept_retired(anchors, domain, origin, artefact, bundle):
    # L0-SIG-81
    matching = [a for a in anchors if bytes(a["domain"][1]) == domain]
    if not matching:
        return "pq-anchor-missing"
    if bundle is None:
        return "superseded"
    anchor = matching[0]
    payload = verify(bundle["checkpoint"], CHECKPOINT_CONTENT_TYPE, anchor["key"])
    if payload is None:
        return "superseded"
    try:
        body = payload.decode("utf-8")
        cp_origin, size, root, _ = note.parse_checkpoint(body)
        disclosed = record.decode_disclosure(bundle["record"], envelope=False)
        leaf = record.leaf_hash(disclosed)
    except (UnicodeDecodeError, note.NoteError, record.RecordError, Rejection):
        return "superseded"
    cosigned = any(
        w["independent"] and w["name"] == c["name"]
        and verify(c["sign1"], COSIGN_CONTENT_TYPE, w["key"]) == body.encode("utf-8") + c["timestamp"].to_bytes(8, "big")
        for c in bundle["cosigns"] for w in anchor["witnesses"]
    )
    field = disclosed.get("fields", {}).get("artefact")
    committed = isinstance(field, list) and len(field) == 2 and bytes(field[1]) == artefact
    header_domain = disclosed.get("domain")
    if (cp_origin != origin or not cosigned or not committed
            or not (isinstance(header_domain, list) and bytes(header_domain[1]) == domain)
            or not merkle.verify_inclusion(disclosed["pos"], size, leaf, bundle["path"], root)):
        return "superseded"
    return "ok"


def decode_anchor(data):
    return decode_canonical(data)

"""C2SP signed notes, checkpoints and Ed25519 cosignatures, written from L2-CKP-1 to L2-CKP-4."""

import base64
import binascii
import hashlib
import unicodedata

from . import ed25519

MAX_NOTE = 256 * 1024
MAX_SIGNATURES = 64
MAX_NAME = 255
DASH = "— "
LOG_KEY = 0x01
COSIGNER_KEY = 0x04

SIGNATURE_REASONS = {
    "length": "signature-length",
    "non_canonical_a": "signature-non-canonical-key",
    "non_canonical_r": "signature-non-canonical-r",
    "s_not_reduced": "signature-unreduced-s",
    "small_order_a": "signature-small-order-key",
    "small_order_r": "signature-small-order-r",
    "equation": "signature-invalid",
}


class NoteError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def is_control(ch):
    return unicodedata.category(ch) == "Cc"


def check_name(name):
    if not name or len(name.encode()) > MAX_NAME:
        raise NoteError("note-name")
    if any(ch.isspace() or ch == "+" or is_control(ch) for ch in name):
        raise NoteError("note-name")


def b64decode(text, code):
    # RFC 4648: standard alphabet, padding, and only the canonical spelling
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise NoteError(code) from None
    if base64.b64encode(raw).decode() != text:
        raise NoteError(code)
    return raw


def key_id(name, kind, key):
    return int.from_bytes(hashlib.sha256(name.encode() + b"\n" + bytes([kind]) + key).digest()[:4], "big")


def parse_vkey(vkey):
    name, ident, material = vkey.split("+")
    raw = b64decode(material, "note-verifier-key")
    kind, key = raw[0], raw[1:]
    if key_id(name, kind, key) != int(ident, 16):
        raise NoteError("note-verifier-key")
    return {"name": name, "id": int(ident, 16), "kind": kind, "key": key}


def parse_note(text):
    if len(text.encode()) > MAX_NOTE:
        raise NoteError("note-too-large")
    split = text.rfind("\n\n")
    if split < 0:
        raise NoteError("note-malformed")
    body, signatures = text[: split + 1], text[split + 2 :]
    if any(is_control(ch) and ch != "\n" for ch in body):
        raise NoteError("note-control")
    if not signatures or not signatures.endswith("\n"):
        raise NoteError("note-malformed")
    lines = []
    for line in signatures.rstrip("\n").split("\n"):
        if len(lines) == MAX_SIGNATURES:
            raise NoteError("note-too-large")
        if not line.startswith(DASH):
            raise NoteError("note-malformed")
        name, sep, encoded = line[len(DASH) :].partition(" ")
        if not sep:
            raise NoteError("note-malformed")
        check_name(name)
        raw = b64decode(encoded, "note-base64")
        if len(raw) < 5:
            raise NoteError("note-malformed")
        ident = int.from_bytes(raw[:4], "big")
        if any(n == name and i == ident for n, i, _ in lines):
            raise NoteError("note-duplicate")
        lines.append((name, ident, raw[4:]))
    return body, lines


def cosigned_message(timestamp, body):
    return f"cosignature/v1\ntime {timestamp}\n{body}".encode()


def check(public_key, message, signature):
    result, reason = ed25519.verify(public_key, message, signature)
    if result != "accept":
        raise NoteError(SIGNATURE_REASONS[reason])


def parse_checkpoint(body):
    if not body.endswith("\n"):
        raise NoteError("checkpoint-malformed")
    lines = body[:-1].split("\n")
    if len(lines) < 3:
        raise NoteError("checkpoint-malformed")
    origin, size, root = lines[0], lines[1], lines[2]
    check_name(origin)
    if not size or not size.isascii() or not size.isdigit() or (size != "0" and size.startswith("0")):
        raise NoteError("checkpoint-malformed")
    if int(size) >= 2**64:
        raise NoteError("checkpoint-malformed")
    root = b64decode(root, "checkpoint-malformed")
    if len(root) != 32:
        raise NoteError("checkpoint-malformed")
    extensions = lines[3:]
    if any(not e or any(is_control(ch) for ch in e) for e in extensions):
        raise NoteError("checkpoint-malformed")
    return origin, int(size), root, extensions


def verify_checkpoint(text, origin, log, cosigners):
    known = [log] + [c for c in cosigners if c["kind"] == COSIGNER_KEY]
    body, lines = parse_note(text)
    accepted = []
    for name, ident, signature in lines:
        key = next((k for k in known if k["name"] == name and k["id"] == ident), None)
        if key is None:
            continue
        if key["kind"] == COSIGNER_KEY:
            if len(signature) < 8:
                raise NoteError("note-malformed")
            timestamp = int.from_bytes(signature[:8], "big")
            check(key["key"], cosigned_message(timestamp, body), signature[8:])
            accepted.append((name, ident, timestamp))
        else:
            check(key["key"], body.encode(), signature)
            accepted.append((name, ident, None))
    if not accepted:
        raise NoteError("note-unverified")
    checkpoint = parse_checkpoint(body)
    if checkpoint[0] != origin:
        raise NoteError("checkpoint-malformed")
    if not any(n == log["name"] and i == log["id"] for n, i, _ in accepted):
        raise NoteError("note-unverified")
    return checkpoint, accepted

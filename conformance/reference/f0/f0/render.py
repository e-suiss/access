"""The render of an intent for an Approval Surface and the surface's WYSIWYS check, written
from §9.13.3, §9.14.5 k.1, U7, PI-17 and XI-8 (OP-157 m.3 (l))."""

import hashlib

from .codec import Rejection, decode_canonical, encode
from .digest import intent_digest, tagged_digest

CONTEXT = "access/render/v1"
BODY_CONTEXT = "access/opaque-body/v1"


def context_digest(context, data):
    return hashlib.sha256(context.encode("utf-8") + b"\x00" + data).digest()


def flag(value):
    return "true" if value else "false"


def resource_text(resource):
    out = resource["namespace"]
    for part in resource["path"]:
        out += "/" + part
    if resource.get("incarnation", 0) != 0:
        out += "@" + str(resource["incarnation"])
    return out


def window_text(window):
    return f"{window[0]}..{window[1]}"


def eq_text(value):
    if isinstance(value, bool):
        return flag(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, int):
        return str(value)
    return value


def param_text(param):
    (kind, inner), = param.items()
    if kind == "enum":
        return inner
    if kind == "eq":
        return eq_text(inner)
    if kind == "amount":
        return f"{inner['value']} {inner['unit']}"
    if kind == "count":
        return str(inner)
    if kind == "interval":
        return window_text(inner)
    if kind == "resource":
        return resource_text(inner)
    if kind == "subject":
        return inner.hex()
    if kind == "purpose":
        (which, value), = inner.items()
        return value if which == "code" else value[1].hex()
    if kind == "flag":
        return flag(inner)
    if kind == "origin":
        return ("write " if inner["access"] == "write" else "read ") + inner["origin"]
    raise Rejection("unknown", f"parameter kind {kind}")


def render_of(schema, intent, locale):
    material = schema is None or schema["effect_class"] != "none"
    action = intent["action"]
    fields = [["action", f"{action['namespace']}/{action['name']}@{action['major']}", True]]
    if intent["resources"]:
        fields.append(["resource", resource_text(intent["resources"][0]), True])
    params = intent.get("params", {})
    for name in sorted(params, key=lambda k: k.encode("utf-8")):
        fields.append([name, param_text(params[name]), material])
    if "recipient" in intent:
        fields.append(["recipient", intent["recipient"].hex(), True])
    fields.append(["validity", window_text(intent["validity"]), False])
    value = {
        "schema": action["schema"],
        "intent": intent_digest(encode(intent)),
        "locale": locale,
        "fields": fields,
    }
    if schema is not None and "render" in schema:
        value["template"] = schema["render"]
    if schema is not None and "reversibility" in schema:
        value["reversibility"] = schema["reversibility"]
    return value


def material_fields(render):
    return sorted({name for name, _, material in render["fields"] if material}, key=lambda k: k.encode("utf-8"))


def render_bytes(schema_bytes, intent_bytes, locale):
    schema = None if schema_bytes is None else decode_canonical(schema_bytes)
    intent = decode_canonical(intent_bytes)
    render = render_of(schema, intent, locale)
    return encode(render), tagged_digest(CONTEXT, render), material_fields(render)


def wysiwys(shown, render_digest, material, intent_bytes, bodies):
    try:
        render = decode_canonical(shown)
    except Rejection:
        return "render"
    if encode(render) != shown or context_digest(CONTEXT, shown) != render_digest[1]:
        return "render"
    if material_fields(render) != sorted(material, key=lambda k: k.encode("utf-8")):
        return "material"
    if not bodies:
        return "accept"
    if intent_bytes is None:
        return "body"
    try:
        intent = decode_canonical(intent_bytes)
        digest = intent_digest(intent_bytes)
    except Rejection:
        return "body"
    if digest != render["intent"]:
        return "body"
    opaque = intent.get("opaque", {})
    for name, body in bodies.items():
        if name not in opaque or opaque[name][1] != context_digest(BODY_CONTEXT, body):
            return "body"
    return "accept"

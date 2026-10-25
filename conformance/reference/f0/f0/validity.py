from .codec import (
    UINT_MAX,
    check_authority_set,
    check_bytes,
    check_digest,
    check_ident,
    check_ident_map,
    check_list,
    check_map,
    check_requirement_set,
    check_text_in,
    check_true,
    check_tstr,
    check_uint,
    check_unit,
    decode_canonical,
    fail,
)


VARIANT_CLASS = {
    "online-strict": "online",
    "bounded-staleness": "intermittent",
    "revalidate-on-reconnect": "intermittent",
    "checkpointed-offline": "offline",
    "checkpoint-continuation": "long-running",
}


class ValidityError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


def check_profile(value):
    check_map(value, {
        "class": check_text_in("online", "intermittent", "offline", "long-running"),
        "variant": check_text_in(*VARIANT_CLASS),
        # OP-120 m.8
        "version": check_uint,
    }, {"params": check_ident_map(check_uint)})
    # L0-VAL-3
    if VARIANT_CLASS[value["variant"]] != value["class"]:
        fail("profile class is not the class of its variant")


def check_revalidation(value):
    check_map(value, {}, {
        "every_uses": check_uint,
        "on_reconnect": check_true,
        "action_classes": check_list(check_ident, nonempty=True, is_set=True),
    })


def check_slice_unit(value):
    if value != "count":
        check_unit(value)


def check_slice_entry(value):
    check_map(value, {"budget_term": check_digest, "amount": check_uint, "unit": check_slice_unit})


def check_clock(value):
    check_map(value, {"source_class": check_ident, "skew_ms": check_uint})


def check_validity_contract(value):
    # §9.12, OP-114 m.4
    check_map(value, {
        "issuing_exercise": check_digest,
        "basis_ref": check_bytes(),
        "holder": check_digest,
        "audience": check_list(check_tstr, nonempty=True, is_set=True),
        "bounds": check_authority_set,
        "profile": check_profile,
        "horizon": check_uint,
        "verifier_profile_ref": check_digest,
        "clock": check_clock,
    }, {
        "max_staleness_ms": check_uint,
        "freshness_sources": check_list(check_tstr, nonempty=True, is_set=True),
        "revalidation": check_revalidation,
        "offline_slice": check_list(check_slice_entry, nonempty=True, is_set=True),
        "local_requirements": check_requirement_set,
        "must_understand": check_list(check_ident, nonempty=True, is_set=True),
    })


def decode_validity_contract(data):
    value = decode_canonical(data)
    check_validity_contract(value)
    return value


def checked_add(a, b):
    # L0-VAL-20
    if a + b > UINT_MAX:
        raise ValidityError("overflow")
    return a + b


def effective_cap(metadata_cap, profile_cap, policy_default):
    # OP-118 m.4
    return min(cap for cap in (metadata_cap, profile_cap, policy_default) if cap is not None)


def accept_until(contract, iat, cap):
    # L0-VAL-10, OP-118 m.4
    if iat is None or cap is None:
        return contract["horizon"]
    return min(contract["horizon"], checked_add(iat, cap))


def check_validity(contract, now, audience, understood, last_refresh, online, skew_ms, iat=None, cap=None):
    # L0-VAL-19
    for extension in contract.get("must_understand", []):
        if extension not in understood:
            raise ValidityError("must-understand")
    # L0-VAL-13
    if audience not in contract["audience"]:
        raise ValidityError("audience")
    # L0-VAL-14, OP-117 m.13
    skew = min(skew_ms, contract["clock"]["skew_ms"])
    # L0-VAL-14a, L0-VAL-14b
    if iat is not None and iat > checked_add(now, skew):
        raise ValidityError("not-yet-valid")
    # L0-VAL-10, L0-VAL-11, L0-VAL-20, OP-117 m.12
    if now > checked_add(accept_until(contract, iat, cap), skew):
        raise ValidityError("expired")
    # L0-VAL-16a: `online` means the verifier obtains an online decision for this use
    if online:
        return
    variant = contract["profile"]["variant"]
    if variant == "online-strict":
        raise ValidityError("online-required")
    if variant == "bounded-staleness":
        # L0-VAL-16, L0-VAL-7
        delta = contract.get("max_staleness_ms")
        if delta is None or last_refresh is None or last_refresh > now or now - last_refresh > delta:
            raise ValidityError("stale")


def check_validity_bytes(data, now, audience, understood, last_refresh, online, skew_ms, iat=None, cap=None):
    contract = decode_validity_contract(data)
    check_validity(contract, now, audience, understood, last_refresh, online, skew_ms, iat, cap)

from .codec import decode_canonical
from .keyscope import check_spec_versions


class VersionError(Exception):
    def __init__(self, name, track):
        super().__init__(f"{name} ({track})")
        self.name = name
        self.track = track


def decode_spec_versions(data):
    value = decode_canonical(data)
    check_spec_versions(value)
    return value


def tracks(cited):
    # L0-ENC-38: core, meta-schema, then profiles (by name)
    yield "core", "core", None
    yield "meta-schema", "meta_schema", None
    for name in sorted(cited.get("profiles", {})):
        yield "profile", "profiles", name


def level(versions, field, name):
    if name is None:
        return versions[field]
    return versions.get("profiles", {}).get(name)


def check(cited, supported, adopted, minimum):
    # L0-ENC-38 rule 1: understood; rule 2: adopted; rule 3: not below the minimum
    for reason, ceiling in (("not-understood", supported), ("not-adopted", adopted)):
        for track, field, name in tracks(cited):
            limit = level(ceiling, field, name)
            if limit is None or level(cited, field, name) > limit:
                raise VersionError(reason, track)
    for track, field, name in tracks(cited):
        floor = level(minimum, field, name)
        if floor is not None and level(cited, field, name) < floor:
            raise VersionError("below-minimum", track)


# OP-158 m.3 (b), SI-18, CR-8, §15.4
TRANSITION_MS = 90 * 24 * 3600 * 1000
DOWNGRADE_DELAY_MS = 24 * 3600 * 1000


def lowers(old, new):
    if new["core"] < old["core"] or new["meta_schema"] < old["meta_schema"]:
        return True
    new_profiles = new.get("profiles", {})
    for name, floor in old.get("profiles", {}).items():
        if name not in new_profiles or new_profiles[name] < floor:
            return True
    new_schemas = [bytes(s[1]) for s in new.get("schemas", [])]
    return any(bytes(s[1]) not in new_schemas for s in old.get("schemas", []))


def downgrades(old_min, new_min, old_algs, new_algs):
    # lowering the minimum or adding any algorithm widens
    return lowers(old_min, new_min) or not set(new_algs) <= set(old_algs)


def minimum_at(current, activated, activated_at, now):
    # the activated minimum binds once the transition window has passed; never lower
    if now < activated_at + TRANSITION_MS:
        return current
    out = dict(current)
    out["core"] = max(current["core"], activated["core"])
    out["meta_schema"] = max(current["meta_schema"], activated["meta_schema"])
    profiles = dict(current.get("profiles", {}))
    for name, v in activated.get("profiles", {}).items():
        profiles[name] = max(profiles.get(name, v), v)
    if profiles:
        out["profiles"] = profiles
    schemas = {bytes(s[1]): s for s in current.get("schemas", [])}
    for s in activated.get("schemas", []):
        schemas.setdefault(bytes(s[1]), s)
    if schemas:
        out["schemas"] = [schemas[k] for k in sorted(schemas)]
    return out

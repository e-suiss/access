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

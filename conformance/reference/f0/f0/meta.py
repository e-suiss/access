import hashlib

from .algebra import authority_within, child_within_parent, is_subset, resource_within, subject_within, window_within
from .codec import (
    HASH_ALG_SHA256,
    Rejection,
    check_bytes,
    check_canonical_authority,
    check_capacity,
    check_choice,
    check_digest,
    check_equality_value,
    check_id,
    check_ident,
    check_list,
    check_map,
    check_requirement_set,
    check_resource_selector,
    check_subject_selector,
    check_text_in,
    check_time_window,
    check_tstr,
    check_uint,
    check_uint_at_least,
    check_assurance,
    check_authority_set,
    check_constraint_set,
    decode_canonical,
    encode,
    same,
)
from .keyscope import check_cose_alg, check_public_key, thumbprint


OBJECT_CONTEXT = "access/object/v1"
MAX_LINEAGE = 16
NO_CATALOG = {}


class MetaError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def refuse(code):
    raise MetaError(code)


# ---------------------------------------------------------------- payload shapes (L0-META-1)


def check_named_pin(value):
    check_map(value, {"name": check_ident, "version": check_uint, "digest": check_digest})


def check_key_set(value):
    def keys(table):
        if not isinstance(table, dict) or not table:
            refuse("meta-malformed")
        for kid, key in table.items():
            check_bytes(32)(kid)
            check_public_key(key)
    check_map(value, {"keys": keys, "allowed": check_list(check_cose_alg, nonempty=True)})


def check_root(value):
    check_choice(value, {
        "sole": check_id,
        "joint": lambda joint: check_map(joint, {
            "parties": check_list(check_id, is_set=True),
            "k": check_uint_at_least(1),
        }),
    })
    if "joint" in value and len(value["joint"]["parties"]) < 2:
        refuse("meta-malformed")


def check_scope(value):
    check_choice(value, {"resource": check_resource_selector, "party": check_id}, texts=("domain",))


def check_holding(value):
    if not isinstance(value, list) or len(value) != 3:
        refuse("meta-malformed")
    check_id(value[0])
    check_id(value[1])
    check_uint(value[2])


def check_grant_basis(value):
    check_choice(value, {"anchor": check_id, "holding": check_holding})


def check_disposition(value):
    def entry(item):
        if not isinstance(item, list) or len(item) != 2:
            refuse("meta-malformed")
        check_id(item[0])
        check_text_in("keep", "revoke")(item[1])
    check_list(entry)(value)


def check_ed25519_key(value):
    check_choice(value, {"ed25519": check_bytes(32)})


def check_mandate_envelope(value):
    check_map(value, {"authority": check_authority_set, "constraints": check_constraint_set}, {
        "requirements": check_requirement_set,
        "pin": check_holding,
    })


def check_grant_content(value):
    check_map(value, {
        "basis": check_grant_basis,
        "holder": check_subject_selector,
        "authority": check_canonical_authority,
    }, {
        "agency": check_list(check_capacity, nonempty=True),
        "named": lambda named: check_map(named, {"name": check_ident, "version": check_uint, "digest": check_digest}),
    })


def check_acceptance_content(value):
    check_map(value, {
        "issuer": lambda issuer: check_id(issuer) if isinstance(issuer, bytes) else check_map(issuer, {"keys": check_key_set}),
        "use": check_text_in("actor-binding", "predicate-input", "subject-selection", "foreign-authority", "schema-definition"),
        "classes": check_list(check_ident, nonempty=True),
        "subject": check_subject_selector,
        "validity": check_time_window,
    }, {
        "anchor": check_id,
        "assurance_floor": check_assurance,
        "ingest_until": check_uint,
        "issued_until": check_uint,
        "quota": lambda quota: check_map(quota, {"count": check_uint_at_least(1), "window_s": check_uint_at_least(1)}),
    })


def check_requirement_map(value):
    # OP-141 m.27 (b): `@require` references to requirement sets
    if not isinstance(value, dict) or not value:
        fail("shape")
    for ref, terms in value.items():
        if not isinstance(ref, str) or not ref:
            fail("shape")
        check_requirement_set(terms)


def check_policy_content(value):
    # L0-META-27: the one schema of this version
    check_map(value, {
        "schema": check_text_in("access/restriction/v1"),
        "source": check_tstr,
        "target": lambda target: check_choice(
            target, {"anchor": check_id, "party": check_id, "instance": check_id}, texts=("domain",)
        ),
    }, {"requirements": check_requirement_map})


PAYLOADS = {
    "anchor_create": ({"scope": check_scope, "root": check_root}, {"root_terms": check_requirement_set}),
    "anchor_transfer": ({"anchor": check_id, "root": check_root, "disposition": check_disposition}, {}),
    "anchor_amend": ({"anchor": check_id}, {"root": check_root, "root_terms": check_requirement_set}),
    "anchor_retire": ({"anchor": check_id, "disposition": check_disposition}, {}),
    "party_register": ({"party": check_id, "root": check_root}, {}),
    "party_depart": ({"party": check_id, "disposition": check_disposition}, {}),
    "instance_create": ({"party": check_id, "key": check_ed25519_key}, {"mandate": check_mandate_envelope}),
    "instance_rekey": ({"instance": check_id, "key": check_ed25519_key}, {}),
    "instance_terminate": ({"instance": check_id}, {}),
    "instance_recover": ({"instance": check_id, "key": check_ed25519_key}, {}),
    "mandate_bind": ({"instance": check_id, "envelope": check_mandate_envelope}, {}),
    "mandate_rebind": ({"mandate": check_id, "envelope": check_mandate_envelope}, {}),
    "mandate_revoke": ({"mandate": check_id}, {}),
    "grant_issue": None,
    "grant_amend": ({"grant": check_id, "authority": check_canonical_authority},
                    {"agency": check_list(check_capacity, nonempty=True), "named": check_named_pin}),
    "grant_revoke": ({"grant": check_id}, {}),
    "grant_renounce": ({"grant": check_id}, {}),
    "acceptance_establish": None,
    "acceptance_amend": ({"acceptance": check_id, "content": check_acceptance_content}, {}),
    "acceptance_revoke": ({"acceptance": check_id}, {}),
    "policy_set": ({"content": check_policy_content}, {"policy": check_id}),
    "policy_retire": ({"policy": check_id}, {}),
    "claim_issue": ({"subject": check_id, "class": check_ident, "value": check_equality_value},
                    {"validity": check_time_window, "bound_intent": check_digest, "supersedes": check_id}),
    "contribute": ({"target": check_digest, "class": check_ident}, {}),
    "authority_set_define": ({"name": check_ident, "authority": check_authority_set}, {}),
    "consumption_release": ({"exercise": check_digest, "grounds": check_list(check_id, nonempty=True)}, {}),
}


def decode_payload(data):
    # L0-META-1
    try:
        value = decode_canonical(data)
        if not isinstance(value, dict) or len(value) != 1:
            refuse("meta-malformed")
        name, body = next(iter(value.items()))
        if name not in PAYLOADS:
            refuse("meta-action")
        if name == "grant_issue":
            check_grant_content(body)
        elif name == "acceptance_establish":
            check_acceptance_content(body)
        else:
            required, optional = PAYLOADS[name]
            check_map(body, required, optional)
    except Rejection:
        refuse("meta-malformed")
    return name, body


def check_exercise_basis(value):
    try:
        check_choice(value, {"anchor": check_id, "holding": check_holding, "public": check_id})
    except Rejection:
        refuse("meta-malformed")


# ---------------------------------------------------------------- identifiers and keys


def object_id(origin, kind, n):
    # L0-META-4
    preimage = OBJECT_CONTEXT.encode("utf-8") + b"\x00" + encode([[HASH_ALG_SHA256, origin], kind, n])
    return hashlib.sha256(preimage).digest()[:16]


def state_key(kind, ident):
    # L0-META-5
    return encode([kind, ident])


def as_set(items):
    unique = {encode(item): item for item in items}
    return [unique[key] for key in sorted(unique)]


def authority_set_digest(authority):
    # L0-META-33
    preimage = b"access/authority-set/v1\x00" + encode(authority)
    return [HASH_ALG_SHA256, hashlib.sha256(preimage).digest()]


# ---------------------------------------------------------------- the run


class Apply:
    def __init__(self, state, domain_id, exercise, pos, party, instance, basis, capacity):
        self.state = state
        self.domain_id = domain_id
        self.exercise = exercise
        self.pos = pos
        self.party = party
        self.instance = instance
        self.basis = basis
        self.capacity = capacity
        self.effects = []
        self.requirements = []
        self.counters = {}

    # -- state

    def read(self, kind, ident):
        return self.state.get(state_key(kind, ident))

    def write(self, kind, ident, value):
        # L0-META-29
        key = state_key(kind, ident)
        self.state[key] = value
        self.effects.append((key, value))

    def remove(self, kind, ident):
        key = state_key(kind, ident)
        self.state.pop(key, None)
        self.effects.append((key, None))

    def add_to_index(self, kind, ident, member):
        # L0-META-5
        self.write(kind, ident, as_set((self.read(kind, ident) or []) + [member]))

    def end(self, kind, ident, value, how):
        # L0-META-6
        ended = dict(value)
        ended["ended"] = {"at": self.pos, "how": how}
        self.write(kind, ident, ended)

    def live(self, kind, ident):
        value = self.read(kind, ident)
        if value is None:
            refuse("meta-unknown")
        if "ended" in value:
            refuse("meta-ended")
        return value

    def new_id(self, kind):
        # L0-META-4
        n = self.counters.get(kind, 0)
        self.counters[kind] = n + 1
        return object_id(self.exercise, kind, n)

    def meta_anchor_id(self):
        # L0-META-7
        return object_id(self.domain_id, "anchor", 0)

    # -- powers

    def principal(self):
        if self.capacity == "own":
            return self.party
        return self.capacity["for"]

    def root_power(self, anchor):
        # L0-META-10
        root = anchor["root"]
        if "sole" in root:
            return root["sole"] == self.party
        return self.party in root["joint"]["parties"]

    def require_root(self, anchor):
        # L0-META-10
        if "ended" in anchor or not self.root_power(anchor):
            refuse("meta-not-authorized")
        self.add_root_requirements(anchor)

    def add_root_requirements(self, anchor):
        # L0-META-10
        root = anchor["root"]
        if "joint" in root:
            needed = root["joint"]["k"] - 1
            if needed >= 1:
                term = {
                    "proof_kind": "contribution",
                    "class": "co_root",
                    "binding": "intent_digest",
                    "independence": {"distinct": "party"},
                    "consumption": "single_use",
                }
                if needed >= 2:
                    term["count"] = needed
                self.requirements.append(term)
        self.requirements.extend(anchor.get("root_terms", []))

    def basis_anchor(self, wanted=None):
        # L0-META-13
        if "anchor" not in self.basis:
            refuse("meta-basis")
        ident = self.basis["anchor"]
        if wanted is not None and ident != wanted:
            refuse("meta-basis")
        anchor = self.read("anchor", ident)
        if anchor is None:
            refuse("meta-unknown")
        if "ended" in anchor:
            refuse("meta-ended")
        return ident, anchor

    def meta_root(self):
        # L0-META-27
        ident, anchor = self.basis_anchor(self.meta_anchor_id())
        self.require_root(anchor)
        return ident

    def lineage(self, grant_id):
        # L0-META-11
        chain = []
        current = grant_id
        while True:
            grant = self.read("grant", current)
            if grant is None:
                refuse("meta-unknown")
            chain.append((current, grant))
            if len(chain) > MAX_LINEAGE:
                refuse("meta-depth")
            basis = grant["content"]["basis"]
            if "anchor" in basis:
                return chain, basis["anchor"]
            current = basis["holding"][0]

    def holds(self, grant):
        return same(grant["content"]["holder"], {"party": self.party})

    def require_lineage_power(self, grant_id):
        # L0-META-11
        chain, anchor_id = self.lineage(grant_id)
        for _, above in chain[1:]:
            if "ended" not in above and self.holds(above):
                return
        anchor = self.read("anchor", anchor_id)
        if anchor is None:
            refuse("meta-unknown")
        self.require_root(anchor)

    def require_own_instance(self, instance):
        # L0-META-12
        if instance["party"] != self.party:
            refuse("meta-not-authorized")

    # -- dispositions

    def dispose(self, anchor_id, disposition, keep_allowed):
        # L0-META-21
        dependents = [g for g in self.read("children", anchor_id) or [] if "ended" not in self.read("grant", g)]
        named = [entry[0] for entry in disposition]
        if len(set(named)) != len(named) or as_set(named) != as_set(dependents):
            refuse("meta-disposition")
        if not keep_allowed and any(entry[1] == "keep" for entry in disposition):
            refuse("meta-disposition")
        return [entry[0] for entry in disposition if entry[1] == "revoke"]

    def revoke_grants(self, grants):
        for grant_id in grants:
            self.end("grant", grant_id, self.read("grant", grant_id), "revoked")

    # -- actions

    def anchor_create(self, body):
        # L0-META-20
        anchor_id, anchor = self.basis_anchor()
        self.require_root(anchor)
        scope = body["scope"]
        if scope == "domain" or not scope_within(scope, anchor["scope"]):
            refuse("meta-not-within")
        value = {"scope": scope, "root": body["root"], "since": self.pos}
        if "root_terms" in body:
            value["root_terms"] = body["root_terms"]
        self.write("anchor", self.new_id("anchor"), value)
        return True

    def anchor_transfer(self, body):
        # L0-META-20, L0-META-21
        anchor_id, anchor = self.basis_anchor(body["anchor"])
        self.require_root(anchor)
        revoked = self.dispose(anchor_id, body["disposition"], keep_allowed=True)
        self.revoke_grants(revoked)
        value = dict(anchor, root=body["root"], since=self.pos)
        self.write("anchor", anchor_id, value)
        return True

    def anchor_amend(self, body):
        # L0-META-20, L0-META-28
        anchor_id, anchor = self.basis_anchor(body["anchor"])
        self.require_root(anchor)
        value = dict(anchor, since=self.pos)
        expansion = False
        if "root" in body:
            expansion = expansion or not same(body["root"], anchor["root"])
            value["root"] = body["root"]
        if "root_terms" in body:
            expansion = expansion or not is_subset(anchor.get("root_terms", []), body["root_terms"])
            value["root_terms"] = body["root_terms"]
            if not body["root_terms"]:
                del value["root_terms"]
        self.write("anchor", anchor_id, value)
        return expansion

    def anchor_retire(self, body):
        # L0-META-20, L0-META-21
        if body["anchor"] == self.meta_anchor_id():
            refuse("meta-basis")
        anchor_id, anchor = self.basis_anchor(body["anchor"])
        self.require_root(anchor)
        self.revoke_grants(self.dispose(anchor_id, body["disposition"], keep_allowed=False))
        self.end("anchor", anchor_id, anchor, "retired")
        return False

    def party_register(self, body):
        # L0-META-22, L0-META-13
        if "public" not in self.basis:
            refuse("meta-basis")
        if body["party"] != self.party:
            refuse("meta-not-authorized")
        if self.read("party", self.party) is not None:
            refuse("meta-ended")
        anchor_id = self.new_id("anchor")
        self.write("anchor", anchor_id, {"scope": {"party": self.party}, "root": body["root"], "since": self.pos})
        self.write("party", self.party, {"anchor": anchor_id, "since": self.pos})
        return True

    def party_depart(self, body):
        # L0-META-22
        self.meta_root()
        party = self.live("party", body["party"])
        anchor_id = party["anchor"]
        anchor = self.live("anchor", anchor_id)
        self.revoke_grants(self.dispose(anchor_id, body["disposition"], keep_allowed=False))
        self.end("anchor", anchor_id, anchor, "retired")
        self.end("party", body["party"], party, "departed")
        for instance_id in self.read("instances", body["party"]) or []:
            instance = self.read("instance", instance_id)
            if "ended" not in instance:
                self.end("instance", instance_id, instance, "departed")
        return False

    def instance_create(self, body):
        # L0-META-23, L0-META-13
        if "public" not in self.basis:
            refuse("meta-basis")
        if body["party"] != self.party:
            refuse("meta-not-authorized")
        self.live("party", self.party)
        instance_id = self.new_id("instance")
        if instance_id != self.instance:
            refuse("meta-not-authorized")
        self.write("instance", instance_id, {"party": self.party, "key": body["key"], "since": self.pos})
        self.add_to_index("instances", self.party, instance_id)
        self.write("key", thumbprint(body["key"]), instance_id)
        if "mandate" in body:
            self.bind(instance_id, body["mandate"])
        return True

    def instance_rekey(self, body):
        # L0-META-23
        instance = self.live("instance", body["instance"])
        if body["instance"] != self.instance:
            refuse("meta-not-authorized")
        self.write("instance", body["instance"], dict(instance, key=body["key"], since=self.pos))
        self.remove("key", thumbprint(instance["key"]))
        self.write("key", thumbprint(body["key"]), body["instance"])
        # L0-META-28: rekeying is not expansion
        return False

    def instance_terminate(self, body):
        # L0-META-23, L0-META-12
        instance = self.live("instance", body["instance"])
        if instance["party"] != self.party:
            party = self.read("party", instance["party"])
            anchor = None if party is None else self.read("anchor", party["anchor"])
            if anchor is None:
                refuse("meta-unknown")
            self.require_root(anchor)
        self.end("instance", body["instance"], instance, "terminated")
        return False

    def instance_recover(self, body):
        # L0-META-23
        instance = self.live("instance", body["instance"])
        self.require_own_instance(instance)
        successor = self.new_id("instance")
        ended = dict(instance, successor=successor)
        self.end("instance", body["instance"], ended, "recovered")
        self.write("instance", successor, {"party": instance["party"], "key": body["key"], "since": self.pos})
        self.add_to_index("instances", instance["party"], successor)
        self.remove("key", thumbprint(instance["key"]))
        self.write("key", thumbprint(body["key"]), successor)
        return True

    def check_pin(self, envelope):
        # L0-META-24
        if "pin" not in envelope:
            return
        grant_id, holder, since = envelope["pin"]
        grant = self.read("grant", grant_id)
        if grant is None:
            refuse("meta-unknown")
        # L0-META-31
        if holder != self.party or not self.holds(grant) or grant["since"] != since:
            refuse("meta-not-authorized")
        if "ended" in grant:
            refuse("meta-ended")

    def bind(self, instance_id, envelope):
        self.check_pin(envelope)
        mandate_id = self.new_id("mandate")
        self.write("mandate", mandate_id, {"instance": instance_id, "envelope": envelope, "since": self.pos})
        self.add_to_index("mandates", instance_id, mandate_id)

    def mandate_bind(self, body):
        # L0-META-24
        instance = self.live("instance", body["instance"])
        self.require_own_instance(instance)
        self.bind(body["instance"], body["envelope"])
        return True

    def mandate_rebind(self, body):
        # L0-META-24, L0-META-28
        mandate = self.live("mandate", body["mandate"])
        instance = self.read("instance", mandate["instance"])
        self.require_own_instance(instance)
        self.check_pin(body["envelope"])
        old, new = mandate["envelope"], body["envelope"]
        narrows = (
            authority_within(new["authority"], old["authority"], NO_CATALOG)
            and window_within(new["constraints"]["validity"], old["constraints"]["validity"])
            and is_subset(old["constraints"].get("while", []), new["constraints"].get("while", []))
            and is_subset(old.get("requirements", []), new.get("requirements", []))
        )
        self.write("mandate", body["mandate"], dict(mandate, envelope=new, since=self.pos))
        return not narrows

    def mandate_revoke(self, body):
        # L0-META-24
        mandate = self.live("mandate", body["mandate"])
        self.require_own_instance(self.read("instance", mandate["instance"]))
        self.end("mandate", body["mandate"], mandate, "revoked")
        return False

    def check_agency(self, agency):
        # L0-META-25
        for capacity in agency:
            if capacity != "own" and capacity != {"for": self.principal()}:
                refuse("meta-agency")

    def grant_issue(self, content):
        # L0-META-25, L0-META-13
        if not same(self.basis, content["basis"]):
            refuse("meta-basis")
        authority = content["authority"]
        if "anchor" in content["basis"]:
            anchor_id, anchor = self.basis_anchor()
            self.require_root(anchor)
            if not resource_in_scope(authority["authority"]["resource"], anchor["scope"]):
                refuse("meta-not-within")
            parent_id = anchor_id
        else:
            parent_id, holder, since = content["basis"]["holding"]
            if holder != self.party:
                refuse("meta-basis")
            parent = self.read("grant", parent_id)
            if parent is None:
                refuse("meta-unknown")
            if not self.holds(parent) or parent["since"] != since:
                refuse("meta-basis")
            if "ended" in parent:
                refuse("meta-ended")
            chain, _ = self.lineage(parent_id)
            if len(chain) + 1 > MAX_LINEAGE:
                refuse("meta-depth")
            if not child_within_parent(authority, parent["content"]["authority"], content["holder"], NO_CATALOG):
                refuse("meta-not-within")
        self.check_agency(content.get("agency", []))
        if "named" in content:
            self.pinned(content["named"], authority["authority"])
        grant_id = self.new_id("grant")
        self.write("grant", grant_id, {"content": content, "since": self.pos, "revision": 0})
        self.add_to_index("children", parent_id, grant_id)
        return True

    def grant_amend(self, body):
        # L0-META-26, L0-META-28
        grant = self.live("grant", body["grant"])
        self.require_lineage_power(body["grant"])
        content = dict(grant["content"], authority=body["authority"])
        if "agency" in body:
            content["agency"] = body["agency"]
        basis = content["basis"]
        if "holding" in basis:
            parent = self.read("grant", basis["holding"][0])
            if not child_within_parent(body["authority"], parent["content"]["authority"], content["holder"], NO_CATALOG):
                refuse("meta-not-within")
        # L0-META-33
        if "named" in body:
            content["named"] = body["named"]
        if "named" in content:
            self.pinned(content["named"], body["authority"]["authority"])
        narrows = authority_narrows(body["authority"], grant["content"]["authority"]) and is_subset(
            content.get("agency", []), grant["content"].get("agency", [])
        )
        self.write("grant", body["grant"], dict(grant, content=content, revision=grant["revision"] + 1))
        return not narrows

    def grant_revoke(self, body):
        # L0-META-26
        grant = self.live("grant", body["grant"])
        self.require_lineage_power(body["grant"])
        self.end("grant", body["grant"], grant, "revoked")
        return False

    def grant_renounce(self, body):
        # L0-META-26
        grant = self.live("grant", body["grant"])
        if not self.holds(grant):
            refuse("meta-not-authorized")
        self.end("grant", body["grant"], grant, "renounced")
        return False

    def check_selection(self, acceptance_id, content):
        # L0-META-27
        if content["use"] != "subject-selection":
            return
        for cls in content["classes"]:
            for other_id in self.read("selection", cls) or []:
                if other_id == acceptance_id:
                    continue
                other = self.read("acceptance", other_id)
                if "ended" not in other and not same(other["content"]["issuer"], content["issuer"]):
                    refuse("meta-not-within")

    def index_acceptance(self, acceptance_id, content, old=None):
        # L0-META-5
        if old is None and isinstance(content["issuer"], bytes):
            self.add_to_index("acceptances", content["issuer"], acceptance_id)
        if content["use"] == "subject-selection":
            old_classes = [] if old is None else old["classes"]
            for cls in old_classes:
                if cls not in content["classes"]:
                    remaining = [a for a in self.read("selection", cls) or [] if a != acceptance_id]
                    if remaining:
                        self.write("selection", cls, remaining)
                    else:
                        # L0-META-27: an entry left empty is removed
                        self.remove("selection", cls)
            for cls in content["classes"]:
                if cls not in old_classes:
                    self.add_to_index("selection", cls, acceptance_id)

    def acceptance_establish(self, content):
        # L0-META-27
        self.meta_root()
        acceptance_id = self.new_id("acceptance")
        self.check_selection(acceptance_id, content)
        self.write("acceptance", acceptance_id, {"content": content, "since": self.pos})
        self.index_acceptance(acceptance_id, content)
        return True

    def acceptance_amend(self, body):
        # L0-META-27, L0-META-28
        self.meta_root()
        acceptance = self.live("acceptance", body["acceptance"])
        old, new = acceptance["content"], body["content"]
        if not same(old["issuer"], new["issuer"]) or old["use"] != new["use"]:
            refuse("meta-not-within")
        self.check_selection(body["acceptance"], new)
        self.write("acceptance", body["acceptance"], dict(acceptance, content=new, since=self.pos))
        self.index_acceptance(body["acceptance"], new, old)
        return not acceptance_narrows(new, old)

    def acceptance_revoke(self, body):
        # L0-META-27
        self.meta_root()
        acceptance = self.live("acceptance", body["acceptance"])
        self.end("acceptance", body["acceptance"], acceptance, "revoked")
        return False

    def policy_set(self, body):
        # L0-META-27, L0-META-29
        self.meta_root()
        target = body["content"]["target"]
        if "policy" in body:
            old = self.live("policy", body["policy"])
            policy_id = body["policy"]
            # L0-META-5: an amend that changes the target moves the policy between entries
            if old["content"]["target"] != target:
                remaining = [p for p in self.read("policies", old["content"]["target"]) or [] if p != policy_id]
                if remaining:
                    self.write("policies", old["content"]["target"], remaining)
                else:
                    self.remove("policies", old["content"]["target"])
        else:
            policy_id = self.new_id("policy")
        self.add_to_index("policies", target, policy_id)
        self.write("policy", policy_id, {"content": body["content"], "since": self.pos})
        # L0-META-28: a new RestrictionPolicy only narrows; changing one is expansion
        return "policy" in body

    def policy_retire(self, body):
        # L0-META-27, L0-META-28
        self.meta_root()
        policy = self.live("policy", body["policy"])
        self.end("policy", body["policy"], policy, "retired")
        return True

    def claim_issue(self, body):
        # L0-META-27
        self.meta_root()
        value = {
            "issuer": self.party,
            "subject": body["subject"],
            "class": body["class"],
            "value": body["value"],
            "since": self.pos,
        }
        # L0-META-27: without a validity, [0, 2^64 - 1]
        value["validity"] = body.get("validity", [0, 2**64 - 1])
        if "bound_intent" in body:
            value["bound_intent"] = body["bound_intent"]
        claim_id = self.new_id("claim")
        # OP-141 m.31 (f)
        member = encode(["member", body["class"], body["subject"], claim_id])
        self.state[member] = claim_id
        self.effects.append((member, claim_id))
        # OP-141 m.30 (b)
        if "supersedes" in body:
            value["supersedes"] = body["supersedes"]
            key = encode(["successor", body["supersedes"], claim_id])
            self.state[key] = claim_id
            self.effects.append((key, claim_id))
        self.write("claim", claim_id, value)
        return True

    def contribute(self, body):
        # L0-META-30
        self.write("contribution", [HASH_ALG_SHA256, self.exercise], {
            "target": body["target"],
            "class": body["class"],
            "party": self.party,
            "instance": self.instance,
            "since": self.pos,
        })
        return True

    def pinned(self, pin, authority):
        # L0-META-33
        version = self.state.get(encode(["authority_set", pin["name"], pin["version"]]))
        if version is None:
            refuse("meta-unknown")
        if not same(authority_set_digest(version["authority"]), pin["digest"]):
            refuse("meta-not-within")
        if not authority_within(authority, version["authority"], NO_CATALOG):
            refuse("meta-not-within")

    def authority_set_define(self, body):
        # L0-META-33
        self.meta_root()
        latest_key = encode(["authority_set", body["name"]])
        version = self.state.get(latest_key, 0) + 1
        self.state[latest_key] = version
        self.effects.append((latest_key, version))
        key = encode(["authority_set", body["name"], version])
        value = {"authority": body["authority"], "since": self.pos}
        self.state[key] = value
        self.effects.append((key, value))
        return True

    def consumption_release(self, body):
        # L0-META-32
        key = body["exercise"]
        exercise = self.state.get(state_key("exercise", key))
        if exercise is None:
            refuse("meta-unknown")
        draws = [dict(d) for d in exercise.get("draws", [])]
        if exercise["actor"] != self.instance and not any(self.lineage_holder(d["key"]) for d in draws):
            refuse("meta-not-authorized")
        none, actual = False, None
        for ground in body["grounds"]:
            claim = self.live("claim", ground)
            if not same(claim.get("bound_intent"), exercise["intent"]):
                refuse("meta-not-within")
            value = claim.get("value")
            if claim["class"] == "access_non_execution":
                none = True
            elif claim["class"] == "access_actual_amount" and isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                if actual is not None and actual != value:
                    refuse("meta-not-within")
                actual = value
            else:
                refuse("meta-not-within")
        used = exercise.get("grounds", [])
        if any(g in used for g in body["grounds"]):
            refuse("meta-release-exceeds-draw")
        returned = False
        for d in draws:
            if none:
                target = d["drawn"]
            elif "unit" in d:
                a = d["drawn"] if actual is None else actual
                target = d["drawn"] - min(a, d["drawn"])
            else:
                target = 0
            if target > d["released"]:
                d["released"] = target
                returned = True
        if not returned:
            refuse("meta-release-exceeds-draw")
        updated = dict(exercise)
        if draws:
            updated["draws"] = draws
        updated["grounds"] = as_set(used + list(body["grounds"]))
        self.state[state_key("exercise", key)] = updated
        self.effects.append((state_key("exercise", key), updated))
        return True

    def lineage_holder(self, key):
        # L0-META-32
        parts = decode_canonical(key)
        if not (isinstance(parts, list) and len(parts) == 4 and parts[0] == "budget"):
            return False
        grant = self.read("grant", parts[1])
        return grant is not None and "ended" not in grant and self.holds(grant)


# ---------------------------------------------------------------- scopes and narrowing


def resource_in_scope(resource, scope):
    # L0-META-25
    if scope == "domain" or "party" in scope:
        return True
    return resource_within(resource, scope["resource"])


def scope_within(scope, parent):
    # L0-META-20
    if parent == "domain":
        return True
    if "resource" in scope and "resource" in parent:
        return resource_within(scope["resource"], parent["resource"])
    if "party" in scope and "party" in parent:
        return scope["party"] == parent["party"]
    return False


def authority_narrows(new, old):
    # L0-META-28
    if not authority_within(new["authority"], old["authority"], NO_CATALOG):
        return False
    if not window_within(new["constraints"]["validity"], old["constraints"]["validity"]):
        return False
    if not is_subset(old["constraints"].get("while", []), new["constraints"].get("while", [])):
        return False
    if new["delegation"].get("depth", 0) > old["delegation"].get("depth", 0):
        return False
    old_class = old["delegation"].get("downstream_holder_class")
    new_class = new["delegation"].get("downstream_holder_class")
    if old_class is not None and (new_class is None or not subject_within(new_class, old_class)):
        return False
    return is_subset(old["requirements"], new["requirements"])


def assurance_at_least(new, old):
    for dimension, level in old.items():
        if dimension not in new:
            return False
        if dimension == "synced":
            if new[dimension] > level:
                return False
        elif new[dimension] < level:
            return False
    return True


def acceptance_narrows(new, old):
    # L0-META-28
    if not is_subset(new["classes"], old["classes"]):
        return False
    if not subject_within(new["subject"], old["subject"]):
        return False
    if not assurance_at_least(new.get("assurance_floor", {}), old.get("assurance_floor", {})):
        return False
    if not window_within(new["validity"], old["validity"]):
        return False
    for field in ("ingest_until", "issued_until"):
        if field in old and (field not in new or new[field] > old[field]):
            return False
    if "quota" in old:
        if "quota" not in new:
            return False
        if new["quota"]["count"] > old["quota"]["count"] or new["quota"]["window_s"] < old["quota"]["window_s"]:
            return False
    return True


# ---------------------------------------------------------------- entry point


def apply(state, domain_id, exercise, pos, party, instance, basis, capacity, payload):
    """Returns (effects, requirements, expansion) or raises MetaError."""
    store = {key: decode_canonical(value) for key, value in state}
    name, body = decode_payload(payload)
    exercise_basis = decode_canonical(basis)
    check_exercise_basis(exercise_basis)
    run = Apply(store, domain_id, exercise, pos, party, instance, exercise_basis, decode_canonical(capacity))
    expansion = getattr(run, name)(body)
    # L0-META-29
    effects = dict(run.effects)
    return sorted(effects.items()), as_set(run.requirements), expansion

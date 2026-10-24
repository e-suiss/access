from .codec import encode, same


BOTTOM = None


def kind_of(choice):
    if isinstance(choice, str):
        return choice
    return next(iter(choice))


def unique_sorted(items):
    by_encoding = {}
    for item in items:
        by_encoding[encode(item)] = item
    return [by_encoding[key] for key in sorted(by_encoding)]


def contains(items, wanted):
    return any(same(item, wanted) for item in items)


def is_subset(small, large):
    return all(contains(large, item) for item in small)


# ---------------------------------------------------------------- actions


def find_catalog(catalog, digest):
    for entry in catalog.get("catalogs", []):
        if same(entry["catalog"], digest):
            return entry
    return None


def namespace_under(namespace, prefix_namespace):
    return namespace == prefix_namespace or namespace.startswith(prefix_namespace + ".")


def action_identity(action):
    return (action["namespace"], action["name"], action["major"])


def resolve_prefix(prefix, catalog):
    # OP-107 m.2
    entry = find_catalog(catalog, prefix["catalog"])
    if entry is None:
        return None
    reserved = catalog.get("reserved", [])
    return [
        action for action in entry["actions"]
        if namespace_under(action["namespace"], prefix["namespace"]) and not contains(reserved, action)
    ]


def resolve_actions(action_set, catalog):
    resolved = list(action_set.get("exact", []))
    for prefix in action_set.get("prefix", []):
        actions = resolve_prefix(prefix, catalog)
        if actions is None:
            return None
        resolved.extend(actions)
    return unique_sorted(resolved)


def action_covered(action, action_set, catalog):
    # OP-107 m.1
    for exact in action_set.get("exact", []):
        if same(exact, action):
            return True
    # OP-107 m.2, m.3
    for prefix in action_set.get("prefix", []):
        actions = resolve_prefix(prefix, catalog)
        if actions is not None and contains(actions, action):
            return True
    return False


def actions_within(child, parent, catalog):
    # OP-109 m.10
    child_actions = resolve_actions(child, catalog)
    if child_actions is None:
        return False
    return all(action_covered(action, parent, catalog) for action in child_actions)


# ---------------------------------------------------------------- resources


def is_exact(selector):
    return "exact" in selector


def path_starts_with(path, prefix):
    return len(prefix) <= len(path) and path[:len(prefix)] == prefix


def resource_within(child, parent):
    # OP-109 m.9 resource
    if is_exact(child) and is_exact(parent):
        return same(child["exact"], parent["exact"])
    if is_exact(child):
        ref = child["exact"]
        return (
            ref["namespace"] == parent["namespace"]
            and path_starts_with(ref["path"], parent.get("prefix", []))
            and "type" not in parent
            and "where" not in parent
        )
    if is_exact(parent):
        return False
    if child["namespace"] != parent["namespace"]:
        return False
    if not path_starts_with(child.get("prefix", []), parent.get("prefix", [])):
        return False
    if "type" in parent and child.get("type") != parent["type"]:
        return False
    child_where = child.get("where", {})
    for key, value in parent.get("where", {}).items():
        if key not in child_where or not same(child_where[key], value):
            return False
    return True


def resource_ref_within(ref, selector):
    # OP-107 m.13
    return resource_within({"exact": ref}, selector)


def resource_intersect(left, right):
    # OP-109 m.9 resource
    if is_exact(left) and is_exact(right):
        return left if same(left, right) else BOTTOM
    if is_exact(left):
        return left if resource_within(left, right) else BOTTOM
    if is_exact(right):
        return right if resource_within(right, left) else BOTTOM
    if left["namespace"] != right["namespace"]:
        return BOTTOM
    left_prefix = left.get("prefix", [])
    right_prefix = right.get("prefix", [])
    if path_starts_with(left_prefix, right_prefix):
        prefix = left_prefix
    elif path_starts_with(right_prefix, left_prefix):
        prefix = right_prefix
    else:
        return BOTTOM
    if "type" in left and "type" in right and left["type"] != right["type"]:
        return BOTTOM
    selector_type = left.get("type", right.get("type"))
    where = dict(left.get("where", {}))
    for key, value in right.get("where", {}).items():
        if key in where and not same(where[key], value):
            return BOTTOM
        where[key] = value
    result = {"namespace": left["namespace"]}
    if prefix:
        result["prefix"] = prefix
    if selector_type is not None:
        result["type"] = selector_type
    if where:
        result["where"] = where
    return result


# ---------------------------------------------------------------- subjects


def subject_within(child, parent):
    # OP-109 m.9 subject, OP-107 m.14
    if parent == "public":
        return True
    if child == "public":
        return False
    if kind_of(child) != kind_of(parent):
        return False
    if kind_of(child) == "pred":
        return is_subset(parent["pred"], child["pred"])
    return same(child, parent)


def party_within(party, selector):
    return subject_within({"party": party}, selector)


def subject_intersect(left, right):
    # OP-109 m.9 subject
    if subject_within(left, right):
        return left
    if subject_within(right, left):
        return right
    if kind_of(left) == "pred" and kind_of(right) == "pred":
        return {"pred": unique_sorted(left["pred"] + right["pred"])}
    return BOTTOM


# ---------------------------------------------------------------- purposes


def purpose_below(child, parent, catalog):
    # OP-107 m.15
    if same(child, parent):
        return True
    for entry in catalog.get("purposes", []):
        if same(entry["purpose"], parent):
            for lower in entry["below"]:
                if purpose_below(child, lower, catalog):
                    return True
    return False


def purposes_within(child, parent, catalog):
    # OP-109 m.9 purpose
    return all(any(purpose_below(c, p, catalog) for p in parent) for c in child)


def all_purposes(catalog):
    known = []
    for entry in catalog.get("purposes", []):
        known.append(entry["purpose"])
        known.extend(entry["below"])
    return unique_sorted(known)


def maximal_purposes(purposes, catalog):
    # OP-109 m.9 purpose
    purposes = unique_sorted(purposes)
    return [
        p for p in purposes
        if not any(not same(p, q) and purpose_below(p, q, catalog) for q in purposes)
    ]


def purposes_intersect(left, right, catalog):
    # OP-109 m.9 purpose
    candidates = unique_sorted(left + right + all_purposes(catalog))
    common = [
        c for c in candidates
        if any(purpose_below(c, p, catalog) for p in left) and any(purpose_below(c, p, catalog) for p in right)
    ]
    if not common:
        return BOTTOM
    return maximal_purposes(common, catalog)


# ---------------------------------------------------------------- parameter bounds


def range_is_empty(bound):
    return "min" in bound and "max" in bound and bound["min"] > bound["max"]


def bound_within(child, parent, catalog):
    # OP-109 m.9
    kind = kind_of(child)
    if kind != kind_of(parent):
        return False
    c = child[kind]
    p = parent[kind]
    if kind == "enum":
        return is_subset(c, p)
    if kind in ("eq", "flag"):
        return same(c, p)
    if kind == "range":
        if c["unit"] != p["unit"]:
            return False
        if "min" in p and ("min" not in c or c["min"] < p["min"]):
            return False
        if "max" in p and ("max" not in c or c["max"] > p["max"]):
            return False
        return True
    if kind == "count_max":
        return c <= p
    if kind == "interval":
        return p[0] <= c[0] and c[1] <= p[1]
    if kind == "purpose":
        return purposes_within(c, p, catalog)
    if kind == "resource":
        return resource_within(c, p)
    if kind == "subject":
        return subject_within(c, p)
    return False


def bound_intersect(left, right, catalog):
    # OP-109 m.9
    kind = kind_of(left)
    if kind != kind_of(right):
        return BOTTOM
    a = left[kind]
    b = right[kind]
    if kind == "enum":
        common = [item for item in a if item in b]
        return {"enum": unique_sorted(common)} if common else BOTTOM
    if kind in ("eq", "flag"):
        return left if same(a, b) else BOTTOM
    if kind == "range":
        if a["unit"] != b["unit"]:
            return BOTTOM
        result = {"unit": a["unit"]}
        mins = [x["min"] for x in (a, b) if "min" in x]
        maxes = [x["max"] for x in (a, b) if "max" in x]
        if mins:
            result["min"] = max(mins)
        if maxes:
            result["max"] = min(maxes)
        if range_is_empty(result):
            return BOTTOM
        return {"range": result}
    if kind == "count_max":
        return {"count_max": min(a, b)}
    if kind == "interval":
        start = max(a[0], b[0])
        end = min(a[1], b[1])
        return {"interval": [start, end]} if start <= end else BOTTOM
    if kind == "purpose":
        common = purposes_intersect(a, b, catalog)
        return BOTTOM if common is BOTTOM else {"purpose": common}
    if kind == "resource":
        selector = resource_intersect(a, b)
        return BOTTOM if selector is BOTTOM else {"resource": selector}
    if kind == "subject":
        selector = subject_intersect(a, b)
        return BOTTOM if selector is BOTTOM else {"subject": selector}
    return BOTTOM


def normalize_bound(bound, catalog):
    # OP-109 m.10
    kind = kind_of(bound)
    value = bound[kind]
    if kind == "enum":
        return {"enum": unique_sorted(value)}
    if kind == "range" and range_is_empty(value):
        return BOTTOM
    if kind == "purpose":
        return {"purpose": maximal_purposes(value, catalog)}
    return bound


# ---------------------------------------------------------------- authority sets


def authority_within(child, parent, catalog):
    # OP-109 m.10
    if not actions_within(child["actions"], parent["actions"], catalog):
        return False
    if not resource_within(child["resource"], parent["resource"]):
        return False
    child_params = child.get("params", {})
    for name, bound in parent.get("params", {}).items():
        if name not in child_params or not bound_within(child_params[name], bound, catalog):
            return False
    if "recipient" in parent:
        if "recipient" not in child or not subject_within(child["recipient"], parent["recipient"]):
            return False
    if "purpose" in parent:
        if "purpose" not in child or not purposes_within(child["purpose"], parent["purpose"], catalog):
            return False
    return True


def actions_intersect(left, right, catalog):
    left_actions = resolve_actions(left, catalog) or []
    common = [action for action in left_actions if action_covered(action, right, catalog)]
    return {"exact": unique_sorted(common)} if common else {}


def authority_intersect(left, right, catalog):
    # OP-109 m.10
    actions = actions_intersect(left["actions"], right["actions"], catalog)
    if not actions:
        return BOTTOM
    resource = resource_intersect(left["resource"], right["resource"])
    if resource is BOTTOM:
        return BOTTOM
    result = {"actions": actions, "resource": resource}
    params = dict(left.get("params", {}))
    for name, bound in right.get("params", {}).items():
        if name in params:
            joined = bound_intersect(params[name], bound, catalog)
            if joined is BOTTOM:
                return BOTTOM
            params[name] = joined
        else:
            params[name] = bound
    if params:
        result["params"] = params
    if "recipient" in left and "recipient" in right:
        recipient = subject_intersect(left["recipient"], right["recipient"])
        if recipient is BOTTOM:
            return BOTTOM
        result["recipient"] = recipient
    elif "recipient" in left or "recipient" in right:
        result["recipient"] = left.get("recipient", right.get("recipient"))
    if "purpose" in left and "purpose" in right:
        purpose = purposes_intersect(left["purpose"], right["purpose"], catalog)
        if purpose is BOTTOM:
            return BOTTOM
        result["purpose"] = purpose
    elif "purpose" in left or "purpose" in right:
        result["purpose"] = left.get("purpose", right.get("purpose"))
    return normalize_authority(result, catalog)


def normalize_authority(authority, catalog):
    # OP-109 m.10
    if authority is BOTTOM:
        return BOTTOM
    actions = {}
    for key in ("exact", "prefix"):
        if authority["actions"].get(key):
            actions[key] = unique_sorted(authority["actions"][key])
    result = {"actions": actions, "resource": authority["resource"]}
    params = {}
    for name, bound in authority.get("params", {}).items():
        normal = normalize_bound(bound, catalog)
        if normal is BOTTOM:
            return BOTTOM
        params[name] = normal
    if params:
        result["params"] = params
    if "recipient" in authority:
        recipient = authority["recipient"]
        if kind_of(recipient) == "pred":
            recipient = {"pred": unique_sorted(recipient["pred"])}
        result["recipient"] = recipient
    if authority.get("purpose"):
        result["purpose"] = maximal_purposes(authority["purpose"], catalog)
    return result


# ---------------------------------------------------------------- child within parent


def window_within(child, parent):
    return parent[0] <= child[0] and child[1] <= parent[1]


def child_within_parent(child, parent, holder, catalog):
    # OP-109 m.11
    if not authority_within(child["authority"], parent["authority"], catalog):
        return False
    if not window_within(child["constraints"]["validity"], parent["constraints"]["validity"]):
        return False
    if not is_subset(parent["constraints"].get("while", []), child["constraints"].get("while", [])):
        return False
    # OP-107 m.16
    parent_depth = parent["delegation"].get("depth", 0)
    child_depth = child["delegation"].get("depth", 0)
    if not (parent_depth > 0 and child_depth < parent_depth):
        return False
    parent_class = parent["delegation"].get("downstream_holder_class")
    child_class = child["delegation"].get("downstream_holder_class")
    # OP-107 m.18
    if parent_class == "public":
        return False
    if child_depth > 0 and (holder == "public" or child_class == "public"):
        return False
    # OP-107 m.17
    if parent_class is not None:
        if not subject_within(holder, parent_class):
            return False
        if child_class is None or not subject_within(child_class, parent_class):
            return False
    # OP-107 m.20
    if not is_subset(parent["requirements"], child["requirements"]):
        return False
    return True

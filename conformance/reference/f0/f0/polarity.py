from .codec import encode


def _skip_string(source, i):
    i += 1
    while i < len(source):
        if source[i] == "\\":
            i += 2
        elif source[i] == '"':
            return i + 1
        else:
            i += 1
    return len(source)


def _skip_comment(source, i):
    end = source.find("\n", i)
    return len(source) if end < 0 else end + 1


def statements(source):
    # OP-157 m.3 (b): top-level `;` ends a statement; strings and `//` comments do not
    out = []
    start = 0
    i = 0
    while i < len(source):
        c = source[i]
        if c == '"':
            i = _skip_string(source, i)
        elif source.startswith("//", i):
            i = _skip_comment(source, i)
        elif c == ";":
            i += 1
            piece = source[start:i].strip(" \t\n\r\x0c")
            if piece:
                out.append(piece)
            start = i
        else:
            i += 1
    piece = source[start:].strip(" \t\n\r\x0c")
    if piece:
        out.append(piece)
    return out


def _skip_space(source, i):
    while i < len(source):
        if source[i] in " \t\n\r\x0c":
            i += 1
        elif source.startswith("//", i):
            i = _skip_comment(source, i)
        else:
            break
    return i


def _ident(c):
    return c.isascii() and (c.isalnum() or c == "_")


def is_forbid(statement):
    i = _skip_space(statement, 0)
    while i < len(statement) and statement[i] == "@":
        i += 1
        while i < len(statement) and _ident(statement[i]):
            i += 1
        i = _skip_space(statement, i)
        if i < len(statement) and statement[i] == "(":
            i += 1
            while True:
                if i >= len(statement):
                    return False
                if statement[i] == ")":
                    i += 1
                    break
                if statement[i] == '"':
                    i = _skip_string(statement, i)
                else:
                    i += 1
        i = _skip_space(statement, i)
    return statement.startswith("forbid", i) and not (i + 6 < len(statement) and _ident(statement[i + 6]))


def policy_narrows(old, new):
    # SI-18, INV-36, OP-157 m.3 (b)
    if encode(old.get("schema")) != encode(new.get("schema")) or encode(old.get("target")) != encode(new.get("target")):
        return False
    old_sets = old.get("requirements")
    new_sets = new.get("requirements")
    if old_sets is None:
        kept = True
    elif isinstance(old_sets, dict) and isinstance(new_sets, dict):
        kept = all(k in new_sets and encode(new_sets[k]) == encode(v) for k, v in old_sets.items())
    else:
        kept = False
    if not isinstance(old.get("source"), str) or not isinstance(new.get("source"), str):
        return False
    added = statements(new["source"])
    for s in statements(old["source"]):
        if s not in added:
            return False
        added.remove(s)
    return kept and all(is_forbid(s) for s in added)

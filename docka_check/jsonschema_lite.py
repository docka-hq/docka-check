"""A small JSON Schema validator, enough to tell whether a tool result matches the tool's own outputSchema.

It checks the keywords that decide shape: $ref (local), type, enum, const, properties, required,
additionalProperties, items, prefixItems, anyOf, oneOf, allOf. Anything else is ignored, so it can miss a violation
but does not invent one. (Clients that validate use full validators; a miss here means "not seen", never "valid".)
"""

TYPES = {
    "null": lambda v: v is None,
    "boolean": lambda v: isinstance(v, bool),
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
}


def _resolve(s, root):
    seen = 0
    while isinstance(s, dict) and "$ref" in s and seen < 20:
        ref = s["$ref"]
        if not ref.startswith("#"):
            return {}
        node = root
        for part in [p for p in ref[1:].split("/") if p]:
            part = part.replace("~1", "/").replace("~0", "~")
            node = node[int(part)] if isinstance(node, list) else node.get(part, {})
        s, seen = node, seen + 1
    return s


def errors(value, schema, root=None, path="$", out=None, limit=20):
    """[(path, message)] for each violation found, at most `limit`."""
    out = [] if out is None else out
    root = schema if root is None else root
    s = _resolve(schema, root)
    if len(out) >= limit or s is True or not isinstance(s, dict):
        return out
    if s is False:
        out.append((path, "no value allowed"))
        return out
    t = s.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(TYPES.get(x, lambda v: True)(value) for x in types):
            out.append((path, f"expected {'/'.join(types)}, got {type(value).__name__ if value is not None else 'null'}"))
            return out
    if "enum" in s and value not in s["enum"]:
        out.append((path, "not one of the enum values"))
    if "const" in s and value != s["const"]:
        out.append((path, "not the const value"))
    for key in ("allOf",):
        for sub in s.get(key) or []:
            errors(value, sub, root, path, out, limit)
    for key in ("anyOf", "oneOf"):
        subs = s.get(key)
        if subs and not any(not errors(value, sub, root, path, [], limit) for sub in subs):
            out.append((path, f"matches none of {key}"))
    if isinstance(value, dict):
        props = s.get("properties") or {}
        for name in s.get("required") or []:
            if name not in value:
                out.append((f"{path}.{name}", "required, missing"))
        for name, v in value.items():
            if name in props:
                errors(v, props[name], root, f"{path}.{name}", out, limit)
            elif s.get("additionalProperties") is False:
                out.append((f"{path}.{name}", "not allowed"))
            elif isinstance(s.get("additionalProperties"), dict):
                errors(v, s["additionalProperties"], root, f"{path}.{name}", out, limit)
    if isinstance(value, list):
        prefix = s.get("prefixItems") or (s.get("items") if isinstance(s.get("items"), list) else [])
        for i, v in enumerate(value):
            if i < len(prefix):
                errors(v, prefix[i], root, f"{path}[{i}]", out, limit)
            elif isinstance(s.get("items"), dict):
                errors(v, s["items"], root, f"{path}[{i}]", out, limit)
    return out

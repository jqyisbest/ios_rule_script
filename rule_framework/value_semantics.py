"""YAML value comparison that retains scalar types and recursive aliases."""

from ruamel.yaml.scalarbool import ScalarBoolean


def yaml_value_kind(value):
    if isinstance(value, ScalarBoolean):
        return bool
    return next((kind for kind in (bool, int, float, str, dict, list, tuple)
                 if isinstance(value, kind)), type(value))


def yaml_values_equal(original, current, seen=None):
    """Presentation classes retain their YAML type; bool/int/float stay distinct."""
    kind = yaml_value_kind(original)
    if kind is not yaml_value_kind(current):
        return False
    if kind not in (dict, list, tuple):
        return original == current
    if len(original) != len(current):
        return False
    seen = set() if seen is None else seen
    pair = (id(original), id(current))
    if pair in seen:
        return True
    seen.add(pair)
    if kind is dict:
        keys = {(yaml_value_kind(key), key): key for key in current}
        return all((yaml_value_kind(key), key) in keys and
                   yaml_values_equal(value, current[keys[(yaml_value_kind(key), key)]], seen)
                   for key, value in original.items())
    return all(yaml_values_equal(left, right, seen) for left, right in zip(original, current))

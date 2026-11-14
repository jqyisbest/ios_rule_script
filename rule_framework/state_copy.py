"""Copy managed YAML state once while retaining presentation data and aliases.

ruamel's sequence deepcopy copies all presentation attributes for each item.
Seed sequence identities first, then copy each sequence and its attributes once;
ordinary objects still use Python's deepcopy with the same graph-wide memo.
"""
from copy import deepcopy
from ruamel.yaml.comments import CommentedSeq


def copy_managed_state(value, *, memo=None, native_values=()):
    memo = {} if memo is None else memo
    pending, scalars, seen = [], [], set()

    def attributes(item):
        values = dict(getattr(item, '__dict__', {}))
        for cls in type(item).__mro__:
            slots = cls.__dict__.get('__slots__', ())
            if isinstance(slots, str):
                slots = (slots,)
            for slot in slots:
                if slot.startswith('__') and not slot.endswith('__'):
                    slot = '_' + cls.__name__.lstrip('_') + slot
                if slot not in {'__dict__', '__weakref__'} and hasattr(item, slot):
                    values[slot] = getattr(item, slot)
        return values

    def discover(item, native=False):
        cls = type(item)
        custom_reducer = isinstance(item, str) and cls is not str and any(
            getattr(cls, name, None) is not getattr(str, name, None)
            for name in ('__reduce__', '__reduce_ex__'))
        if native and custom_reducer and getattr(cls, '__deepcopy__', None) is None:
            if id(item) in memo:
                return
            # Preserve the immutable payload/type and copy its Python attributes.
            # Explicit custom deepcopy implementations keep their existing protocol.
            clone = str.__new__(cls, str.__str__(item))
            memo[id(item)] = clone
            scalars.append((item, clone))
            for child in attributes(item).values():
                discover(child, native)
            return
        if isinstance(item, (str, bytes, int, float, bool, type(None))):
            return
        identity = id(item)
        if identity in seen or identity in memo:
            return
        seen.add(identity)
        if cls is CommentedSeq:
            clone = type(item)()
            memo[identity] = clone
            pending.append((item, clone))
        if isinstance(item, dict):
            for key, child in item.items():
                discover(key, native)
                discover(child, native)
        elif isinstance(item, (list, tuple)):
            for child in item:
                discover(child, native)
        for child in attributes(item).values():
            discover(child, native)

    # Release recursive discovery and its identity index before allocating copies.
    try:
        # Seed native graphs first so their aliases use the same preserved copy
        # throughout this state, including references from extension fields.
        for item in native_values:
            discover(item, native=True)
        discover(value)
    finally:
        del discover, seen
    for original, clone in scalars:
        for name, item in attributes(original).items():
            setattr(clone, name, deepcopy(item, memo))
    for original, clone in pending:
        list.extend(clone, (deepcopy(item, memo) for item in original))
        for name, item in attributes(original).items():
            setattr(clone, name, deepcopy(item, memo))
    return deepcopy(value, memo)

"""Lossless text storage and explicit JSON editing helpers."""

import codecs
import re


def split_physical_lines(raw):
    """Return source records ending at CR, LF or CRLF, retaining their endings."""
    return [record for record in re.findall(r'[^\r\n]*(?:\r\n|\r|\n|$)', raw) if record]


def split_physical_records(raw):
    """Split raw text into (line, line_ending) tuples on CR, LF, or CRLF boundaries."""
    if not raw:
        return []
    parts = re.split(r'(\r\n|\r|\n)', raw)
    records = []
    for i in range(0, len(parts) - 1, 2):
        records.append((parts[i], parts[i + 1]))
    if parts[-1]:
        records.append((parts[-1], ''))
    return records


def decode_text(raw):
    """Use UTF-8 or an explicit Unicode BOM; preserve raw newline characters."""
    for bom, encoding in (
        (codecs.BOM_UTF32_LE, 'utf-32-le'), (codecs.BOM_UTF32_BE, 'utf-32-be'),
        (codecs.BOM_UTF8, 'utf-8'),
        (codecs.BOM_UTF16_LE, 'utf-16-le'), (codecs.BOM_UTF16_BE, 'utf-16-be'),
    ):
        if raw.startswith(bom):
            return raw[len(bom):].decode(encoding), encoding, bom
    return raw.decode('utf-8'), 'utf-8', b''


def encode_text(content, encoding, bom):
    supported = {
        'utf-8': (b'', codecs.BOM_UTF8),
        'utf-16-le': (codecs.BOM_UTF16_LE,), 'utf-16-be': (codecs.BOM_UTF16_BE,),
        'utf-32-le': (codecs.BOM_UTF32_LE,), 'utf-32-be': (codecs.BOM_UTF32_BE,),
    }
    if not isinstance(encoding, str) or encoding not in supported:
        raise ValueError('Unsupported managed text encoding')
    if not isinstance(bom, bytes) or bom not in supported[encoding]:
        raise ValueError('Managed text BOM must match its declared encoding')
    return bom + content.encode(encoding)


def serialize_physical_nodes(nodes, *, newline, ends_with_newline, encoding, bom):
    """Serialize ordered client-owned nodes with their physical source endings."""
    records = []
    for index, node in enumerate(nodes):
        line = getattr(node, 'raw_section_line', node.render())
        ending = getattr(node, 'line_ending', newline)
        if index < len(nodes) - 1 and not ending:
            ending = newline
        if index == len(nodes) - 1:
            if not ends_with_newline:
                ending = ''
            elif not ending:
                ending = newline
        records.append(line + ending)
    return encode_text(''.join(records), encoding, bom)


def validate_text_operation(search, replace, is_regex=False, count=0):
    """The same explicit text argument contract applies to Actions and Hooks."""
    for name, value in (('search', search), ('replace', replace)):
        if not isinstance(value, str):
            raise ValueError(f'{name} must be a string')
    if not isinstance(is_regex, bool):
        raise ValueError('is_regex must be a boolean')
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError('count must be a non-negative integer')
    if is_regex:
        import re
        # Validate both pattern and replacement, including when no text matches.
        re.sub(search, replace, '', count=count)


# JSON uses the standard library decoder for syntax, and tracks source spans for
# local edits. JSON whitespace is deliberately limited to RFC JSON whitespace.
import json
import re
from dataclasses import dataclass, field


def _reject_constant(value):
    raise ValueError(f'Invalid JSON non-finite number: {value}')


def validate_json_value(value, ancestors=None):
    """Accept JSON types with string keys, finite numbers and acyclic containers."""
    import math
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError('JSON number must be finite')
        return
    if not isinstance(value, (dict, list)):
        raise ValueError(f'Unsupported JSON value type: {type(value).__name__}')
    ancestors = set() if ancestors is None else ancestors
    if id(value) in ancestors:
        raise ValueError('JSON value contains a cycle')
    ancestors.add(id(value))
    try:
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError('JSON object keys must be strings')
            children = value.values()
        else:
            children = value
        for child in children:
            validate_json_value(child, ancestors)
    finally:
        ancestors.remove(id(value))


def load_json(content):
    value = json.loads(content, parse_constant=_reject_constant, parse_float=_finite_json_float)
    validate_json_value(value)
    return value


def _finite_json_float(token):
    """Validate numeric tokens before duplicate object keys discard their values."""
    import math
    value = float(token)
    if not math.isfinite(value):
        raise ValueError('JSON number must be finite')
    return value


def serialize_json(value):
    validate_json_value(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ': '))


@dataclass
class JSONSpan:
    start: int
    end: int
    value: object
    children: list = field(default_factory=list)
    entry_start: int = None
    comma: int = None


def json_spans(content):
    """Locate values in a syntax-validated JSON document without rewriting it."""
    load_json(content)
    decoder = json.JSONDecoder(parse_constant=_reject_constant)

    def whitespace(index):
        return re.compile(r'[ \t\r\n]*').match(content, index).end()

    def parse(index):
        index = whitespace(index)
        start = index
        marker = content[index]
        if marker not in '{[':
            value, end = decoder.raw_decode(content, index)
            return JSONSpan(start, end, value)
        index = whitespace(index + 1)
        closing = '}' if marker == '{' else ']'
        children = []
        values = {} if marker == '{' else []
        while content[index] != closing:
            entry_start = index
            if marker == '{':
                key, index = decoder.raw_decode(content, index)
                index = whitespace(index)
                child = parse(index + 1)  # JSON validation established the colon.
                values[key] = child.value
            else:
                key = len(children)
                child = parse(index)
                values.append(child.value)
            child.entry_start = entry_start
            children.append((key, child))
            index = whitespace(child.end)
            if content[index] == ',':
                child.comma = index
                index = whitespace(index + 1)
            else:
                break
        return JSONSpan(start, index + 1, values, children)

    return parse(0)


def validate_json_path(path):
    if not isinstance(path, list):
        raise ValueError('JSON path must be a list of string keys or non-negative integer indexes')
    for part in path:
        if isinstance(part, str):
            continue
        if isinstance(part, bool) or not isinstance(part, int) or part < 0:
            raise ValueError('JSON path must contain string keys or non-negative integer indexes')


def select_json_span(root, path):
    validate_json_path(path)
    current = root
    for part in path:
        if isinstance(current.value, dict):
            if not isinstance(part, str):
                raise ValueError(f'JSON object path requires a string key: {path!r}')
        elif isinstance(current.value, list):
            if isinstance(part, bool) or not isinstance(part, int):
                raise ValueError(f'JSON array path requires an integer index: {path!r}')
        else:
            raise ValueError(f'JSON path traverses a scalar: {path!r}')
        matches = [child for key, child in current.children if key == part]
        if not matches:
            raise ValueError(f'JSON path does not exist: {path!r}')
        if len(matches) != 1:
            raise ValueError(f'JSON path has an ambiguous duplicate key: {path!r}')
        current = matches[0]
    return current


def remove_json_path(content, path):
    validate_json_path(path)
    if not path:
        raise ValueError('JSON root removal is unsupported; use json_set with path: [] to replace the root')
    root = json_spans(content)
    parent = select_json_span(root, path[:-1])
    selected = select_json_span(root, path)
    children = [child for _, child in parent.children]
    index = children.index(selected)
    if index < len(children) - 1:
        start, end = selected.entry_start, children[index + 1].entry_start
    elif index > 0:
        start, end = children[index - 1].comma, selected.end
    else:
        start, end = selected.entry_start, selected.end
    return content[:start] + content[end:]


def equivalent_json_text(left, right):
    """Compare exact JSON numbers, booleans and collection structure for no-op edits."""
    from decimal import Decimal
    a = json.loads(left, parse_int=Decimal, parse_float=Decimal, parse_constant=_reject_constant)
    b = json.loads(right, parse_int=Decimal, parse_float=Decimal, parse_constant=_reject_constant)

    def same(first, second):
        if type(first) is not type(second):
            return False
        if isinstance(first, dict):
            return first.keys() == second.keys() and all(same(value, second[key]) for key, value in first.items())
        if isinstance(first, list):
            return len(first) == len(second) and all(same(x, y) for x, y in zip(first, second))
        if isinstance(first, Decimal) and first == second == 0:
            return first.is_signed() == second.is_signed()
        return first == second

    return same(a, b)

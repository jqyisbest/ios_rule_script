"""Shared abstract routing intents and exact native selectors."""


def _modify_physical_list(fom, search, replace, is_regex, count, parse_line):
    """Replace whole-file text and retain nodes from unchanged source spans."""
    import itertools
    import re
    from rule_framework.fom import _apply_text_replacement
    from rule_framework.text_json import decode_text, split_physical_records

    original, _encoding, _bom = decode_text(fom.render_bytes())
    updated, _found = _apply_text_replacement(original, search, replace, is_regex, count)
    if updated == original:
        return

    # Track unchanged offsets so repeated identical lines retain the right node.
    ranges = []
    def retain(start, end, destination):
        if start == end:
            return
        if (ranges and ranges[-1][1] == destination
                and ranges[-1][2] + ranges[-1][1] - ranges[-1][0] == start):
            ranges[-1][1] += end - start
        else:
            ranges.append([destination, destination + end - start, start])

    old_cursor = new_cursor = 0
    pattern = search if is_regex else re.escape(search)
    matches = re.finditer(pattern, original)
    if count:
        matches = itertools.islice(matches, count)
    for match in matches:
        retain(old_cursor, match.start(), new_cursor)
        new_cursor += match.start() - old_cursor
        replacement = match.expand(replace) if is_regex else replace
        if replacement == match.group(0):
            retain(match.start(), match.end(), new_cursor)
        new_cursor += len(replacement)
        old_cursor = match.end()
    retain(old_cursor, len(original), new_cursor)

    old_records = split_physical_records(original)
    old_nodes = {}
    if len(old_records) == len(fom.nodes):
        position = 0
        for node, (line, ending) in zip(fom.nodes, old_records):
            old_nodes[position, position + len(line)] = node
            position += len(line) + len(ending)

    nodes = []
    position = range_index = 0
    records = split_physical_records(updated)
    for line, ending in records:
        end = position + len(line)
        while range_index < len(ranges) and ranges[range_index][1] < end:
            range_index += 1
        node = None
        if range_index < len(ranges):
            begin, stop, source = ranges[range_index]
            if begin <= position and end <= stop:
                origin = source + position - begin
                node = old_nodes.get((origin, origin + len(line)))
        if node is None:
            node = parse_line(line)
            node.needs_validation = True
        node.line_ending = ending
        nodes.append(node)
        position = end + len(ending)
    fom.nodes = nodes
    fom.ends_with_newline = updated.endswith(('\r', '\n'))
    fom._newline = next((ending for _, ending in records if ending), fom._newline)
    from rule_framework.metadata import mark_list_header
    mark_list_header(fom)
    fom.is_dirty = True
    fom.validate()
    fom.update_metadata(only_if_changed=True)


SEMANTIC_TYPES = {
    'domain': {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-WILDCARD', 'HOST', 'HOST-SUFFIX', 'HOST-WILDCARD'},
    'ip': {'IP-CIDR', 'IP-CIDR6', 'IP6-CIDR'},
    'asn': {'IP-ASN', 'ASN'},
    'keyword': {'DOMAIN-KEYWORD', 'HOST-KEYWORD'},
}


def select_rule_types(rule_type):
    """Lowercase category names express intent; native names select one type."""
    if not isinstance(rule_type, str) or not rule_type.strip():
        raise ValueError('Rule type must be a non-empty string')
    return SEMANTIC_TYPES.get(rule_type, {rule_type.upper()})


def native_rule_type(rule_type, value, *, client=None):
    if not isinstance(rule_type, str) or not rule_type.strip():
        raise ValueError('Rule type must be a non-empty string')
    abstract = {
        'domain': 'DOMAIN', 'domain_suffix': 'DOMAIN-SUFFIX',
        'domain_wildcard': 'DOMAIN-WILDCARD', 'keyword': 'DOMAIN-KEYWORD', 'asn': 'IP-ASN',
    }
    if rule_type == 'ip':
        import ipaddress
        network = ipaddress.ip_network(value, strict=False)
        return 'IP-CIDR6' if network.version == 6 and client != 'Shadowrocket' else 'IP-CIDR'
    return abstract.get(rule_type, rule_type.upper())


from enum import Enum


class _Absent(Enum):
    field = 'absent'


UNSET = _Absent.field
OPTION_CONDITIONS = {'no_resolve': 'no-resolve', 'extended_matching': 'extended-matching'}


def condition_options(conditions):
    if not isinstance(conditions, dict):
        raise ValueError('conditions must be a dictionary')
    unknown = set(conditions) - OPTION_CONDITIONS.keys()
    if unknown:
        raise ValueError(f'Unsupported matching conditions: {sorted(unknown)}')
    if any(not isinstance(value, bool) for value in conditions.values()):
        raise ValueError('Matching conditions must be booleans')
    return tuple(sorted(OPTION_CONDITIONS[key] for key, enabled in conditions.items() if enabled))


def validate_options(options, rule_type, client='unknown'):
    if not isinstance(options, (list, tuple)) or any(not isinstance(option, str) for option in options):
        raise ValueError('options must be a list of option strings; [] clears options')
    for option in options:
        if option not in OPTION_CONDITIONS.values():
            raise ValueError(f'Unsupported external rule option: {option}')
        if option == 'no-resolve' and rule_type not in {'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP'}:
            raise ValueError(f'no-resolve requires an IP rule, received {rule_type}')
        if option == 'extended-matching' and (client != 'Surge' or rule_type not in SEMANTIC_TYPES['domain'] | SEMANTIC_TYPES['keyword']):
            raise ValueError('extended-matching requires a supported Surge domain rule')
    if len(set(options)) != len(options):
        raise ValueError('Duplicate external rule options')
    return tuple(options)


def calculate_insert_index(nodes, insert, is_section=False, section_name=None):
    """Return a validated zero-based boundary, raising for explicit bad locators."""
    import re
    from rule_framework.ast import SectionNode, CommentNode, BlankNode
    if isinstance(insert, _BatchInsert):
        return insert.locate(nodes, is_section, section_name)
    if insert is None:
        return len(nodes)
    if not isinstance(insert, dict):
        raise ValueError('insert must be a dictionary')
    locators = ('position', 'at_line', 'after', 'before', 'after_regex', 'before_regex')
    unknown = set(insert) - set(locators) - {'offset', 'occurrence', 'section'}
    if unknown:
        raise ValueError(f'Unsupported insert fields: {sorted(unknown)}')
    if 'section' in insert and (not is_section or insert['section'] != section_name):
        raise ValueError(f'Invalid insert section: {insert["section"]!r}')
    supplied = [key for key in locators if key in insert]
    if len(supplied) != 1:
        raise ValueError('insert requires exactly one position or marker locator')
    occurrence = insert.get('occurrence', 'first')
    if occurrence not in ('first', 'last'):
        raise ValueError('insert.occurrence must be first or last')
    offset = insert.get('offset', 0)
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError('insert.offset must be an integer')
    minimum = 1 if is_section and nodes and isinstance(nodes[0], SectionNode) else 0
    key = supplied[0]
    value = insert[key]
    if key == 'position':
        if value not in ('start', 'end', 'after_header'):
            raise ValueError('insert.position must be start, end or after_header')
        index = len(nodes) if value == 'end' else minimum
        if value == 'after_header' and not is_section:
            while index < len(nodes) and isinstance(nodes[index], CommentNode):
                index += 1
    elif key == 'at_line':
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError('insert.at_line must be an integer')
        index = value
    else:
        if not isinstance(value, str) or not value:
            raise ValueError(f'insert.{key} marker must be a non-empty string')
        pattern = re.compile(value) if key.endswith('_regex') else None
        matches = []
        for current, node in enumerate(nodes):
            if isinstance(node, dict):
                text = str(node.get('match', '')) + ' ' + str(node.get('name', ''))
            else:
                text = node.render().strip() if hasattr(node, 'render') else str(node).strip()
            if pattern.search(text) if pattern else value in text:
                matches.append(current + (1 if key.startswith('after') else 0))
        if not matches:
            raise ValueError(f'Insert marker was not found: {key}={value!r}')
        index = matches[-1] if occurrence == 'last' else matches[0]
    index += offset
    if not minimum <= index <= len(nodes):
        raise ValueError(f'Insert boundary outside valid range {minimum}..{len(nodes)}: {index}')
    return index


class _BatchInsert(dict):
    """Advance a declared batch after its actual newly inserted nodes."""

    def __init__(self, insert):
        super().__init__(insert)
        self.anchors = {}
        self.observations = {}

    def begin_item(self):
        self.observations.clear()

    def locate(self, nodes, is_section, section_name):
        index = calculate_insert_index(nodes, dict(self), is_section, section_name)
        anchor = self.anchors.get(section_name)
        anchor_position = None
        if anchor is not None:
            anchor_position = next((position for position, node in enumerate(nodes) if node is anchor), None)
            if anchor_position is not None:
                index = anchor_position + 1
        self.observations.setdefault((section_name, id(nodes)),
                                     (nodes, {id(node) for node in nodes}, len(nodes), anchor_position))
        return index

    def advance(self):
        import re
        metadata = re.compile(r'^\s*(?:#\s*(?:AUTHOR|REPO|NAME|UPDATED|TOTAL):|#!(?:author|homepage|name|desc|total)\s*=)', re.IGNORECASE)
        for (section, _identity), (nodes, previous, previous_size, anchor_position) in self.observations.items():
            if len(nodes) <= previous_size:
                if len(nodes) == previous_size and anchor_position is not None:
                    self.anchors[section] = nodes[anchor_position]
                continue
            added = [node for node in nodes if id(node) not in previous
                     and not (hasattr(node, 'render') and metadata.match(node.render()))]
            if added:
                self.anchors[section] = added[-1]


STANDARD_TYPES = {
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-WILDCARD', 'DOMAIN-KEYWORD', 'USER-AGENT', 'URL-REGEX',
    'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP', 'PROCESS-NAME',
}


CLIENT_STRUCTURED_TYPES = {
    'Surge': STANDARD_TYPES,
    'Loon': STANDARD_TYPES - {'PROCESS-NAME', 'DOMAIN-WILDCARD'},
    'Shadowrocket': STANDARD_TYPES - {'PROCESS-NAME', 'IP-CIDR6'},
}


def validate_standard_value(rule_type, value, *, client=None):
    """Validate structural values, with native pass-through as a separate API."""
    import ipaddress
    import re
    if client in CLIENT_STRUCTURED_TYPES and rule_type not in CLIENT_STRUCTURED_TYPES[client]:
        raise ValueError(f'Unverified structured type {rule_type} for {client}; use explicit native input')
    if rule_type not in STANDARD_TYPES:
        raise ValueError(f'Unsupported structured standard rule type: {rule_type}; use explicit native input')
    if not isinstance(value, str) or not value.strip() or any(char in value for char in '\r\n\0'):
        raise ValueError('Rule value must be a non-empty single-line string')
    if rule_type in {'DOMAIN', 'DOMAIN-SUFFIX'}:
        if not re.fullmatch(r'[\w-]+(?:\.[\w-]+)*\.?', value, re.UNICODE):
            raise ValueError('Domain value must be a literal hostname; wildcard expressions have separate identities')
    elif rule_type == 'DOMAIN-WILDCARD':
        if re.search(r'[\s,/#]', value):
            raise ValueError('Invalid domain wildcard expression')
    elif rule_type in {'IP-CIDR', 'IP-CIDR6'}:
        network = ipaddress.ip_network(value, strict=False)
        expected_version = 6 if rule_type == 'IP-CIDR6' else 4
        if network.version != expected_version and not (client == 'Shadowrocket' and rule_type == 'IP-CIDR'):
            raise ValueError(f'IP address family differs from {rule_type}')
    elif rule_type == 'IP-ASN':
        if not re.fullmatch(r'[0-9]+', value) or not 0 <= int(value) <= 4294967295:
            raise ValueError('ASN must be an integer in range 0..4294967295')
    elif rule_type != 'URL-REGEX' and ',' in value:
        raise ValueError('Rule value contains a field delimiter')


def rule_identity(rule_type, value, options=()):
    """Type, reference value and canonical matching conditions form identity."""
    if rule_type.upper() in SEMANTIC_TYPES['domain']:
        from rule_framework.domain_refs import canonical_domain
        value = canonical_domain(value)
    return rule_type.upper(), value, tuple(sorted(option.lower() for option in options))


def validate_domain_selector(value):
    if not isinstance(value, str):
        raise ValueError('Domain selector must be a string')
    rule_type = 'DOMAIN-WILDCARD' if any(char in value for char in '*?[') else 'DOMAIN'
    validate_standard_value(rule_type, value)

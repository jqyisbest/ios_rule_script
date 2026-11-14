"""Exact references in policy-free logical routing conditions."""

from rule_framework.domain_refs import (canonical_domain, url_host_references,
    domain_pattern_references, ReferenceRecognitionError)
from rule_framework.rule_helpers import validate_standard_value, validate_options, STANDARD_TYPES


def _fields(text):
    if not isinstance(text, str) or not text.strip() or any(char in text for char in '\r\n\0'):
        raise ReferenceRecognitionError('Logical condition must be a non-empty single-line string')
    fields, start, depth, quote, escaped = [], 0, 0, None, False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == '\\':
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth < 0:
                raise ReferenceRecognitionError('Unbalanced logical parentheses')
        elif char == ',' and depth == 0:
            fields.append(text[start:index].strip())
            start = index + 1
    if depth or quote or escaped:
        raise ReferenceRecognitionError('Unclosed logical parentheses, quotation or escape')
    fields.append(text[start:].strip())
    if any(not field for field in fields):
        raise ReferenceRecognitionError('Empty logical condition or field')
    return fields


def _unwrap(text):
    text = text.strip()
    if not text.startswith('(') or not text.endswith(')') or len(_fields(text)) != 1:
        raise ReferenceRecognitionError('Logical conditions require parenthesized groups')
    return text[1:-1]


LOGICAL_TYPES = frozenset({'AND', 'OR', 'NOT'})

DOMAIN_TYPES = frozenset({'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-WILDCARD'})
CLIENT_LEAF_TYPES = {
    'Surge': STANDARD_TYPES | {'SRC-IP', 'SRC-PORT', 'DEST-PORT', 'PROTOCOL', 'RULE-SET', 'DOMAIN-SET', 'SCRIPT'},
    'Loon': (STANDARD_TYPES - {'DOMAIN-WILDCARD', 'PROCESS-NAME'}) | {'SRC-PORT', 'DEST-PORT', 'PROTOCOL', 'RULE-SET'},
    'Shadowrocket': (STANDARD_TYPES - {'IP-CIDR6', 'PROCESS-NAME'}) | {'DST-PORT', 'PROTOCOL', 'RULE-SET', 'DOMAIN-SET', 'SCRIPT'},
    'mihomo': (STANDARD_TYPES - {'USER-AGENT', 'URL-REGEX'}) | {'DOMAIN-REGEX', 'NETWORK', 'DST-PORT', 'RULE-SET'},
    'Stash': STANDARD_TYPES | {'DOMAIN-REGEX', 'NETWORK', 'PROTOCOL', 'DST-PORT', 'SRC-IP', 'RULE-SET', 'GEOSITE', 'PROCESS-PATH', 'SCRIPT'},
}


def _leaf_options(options, kind, client):
    if 'pre-matching' in options:
        raise ReferenceRecognitionError('Nested logical sub-rules do not support pre-matching')
    if client == 'Shadowrocket':
        from rule_framework.shadowrocket import validate_options as shadowrocket_options
        return shadowrocket_options(options, kind)
    if client == 'Surge' and kind == 'URL-REGEX':
        if len(set(options)) != len(options) or any(option != 'extended-matching' for option in options):
            raise ReferenceRecognitionError('Unsupported Surge logical URL condition option')
        return tuple(options)
    return validate_options(options, kind, client)


def _leaf_references(kind, value, options, client):
    if client == 'Stash' and kind == 'SCRIPT':
        raise ReferenceRecognitionError('Opaque Stash SCRIPT matching conditions require explicit maintenance')
    if kind not in CLIENT_LEAF_TYPES[client]:
        raise ReferenceRecognitionError(f'Unknown {client} logical sub-rule type {kind!r}')
    quoted = value.startswith(('"', "'"))
    if quoted and client in {'mihomo', 'Stash'}:
        raise ReferenceRecognitionError(f'Native quoted {client} logical field grammar is unverified')
    if quoted:
        value = value[1:-1]
    if not value.strip():
        raise ReferenceRecognitionError('Logical sub-rule value must be non-empty')
    try:
        _leaf_options(options, kind, client)
        if kind in DOMAIN_TYPES:
            validate_standard_value(kind, value, client=client)
            return frozenset({canonical_domain(value)})
        if kind == 'URL-REGEX':
            return url_host_references(value).hosts
        if kind == 'DOMAIN-REGEX':
            return domain_pattern_references(value).hosts
        if kind in STANDARD_TYPES and not (quoted and kind in {'USER-AGENT', 'DOMAIN-KEYWORD', 'PROCESS-NAME'}):
            validate_standard_value(kind, value, client=client)
    except ValueError as error:
        raise ReferenceRecognitionError(str(error)) from error
    return frozenset()


def logical_domain_references(rule_type, payload, *, client):
    if client not in {'Surge', 'Loon', 'Shadowrocket', 'mihomo', 'Stash'}:
        raise ReferenceRecognitionError(f'Unsupported logical reference grammar for {client}')

    def visit(kind, condition, depth):
        kind = kind.upper()
        if kind not in LOGICAL_TYPES:
            raise ReferenceRecognitionError(f'Unknown logical operator {kind!r}')
        if depth > 10:
            raise ReferenceRecognitionError('Logical nesting exceeds the supported limit of 10')
        children = _fields(_unwrap(condition))
        if kind == 'NOT' and len(children) != 1:
            raise ReferenceRecognitionError('NOT requires exactly one sub-rule')
        references = set()
        for child in children:
            parts = _fields(_unwrap(child))
            if len(parts) < 2:
                raise ReferenceRecognitionError('Logical sub-rule requires a type and value')
            child_kind, value, *options = parts
            child_kind = child_kind.upper()
            if child_kind in LOGICAL_TYPES:
                if options:
                    raise ReferenceRecognitionError('Nested logical sub-rules cannot have a policy or trailing fields')
                references.update(visit(child_kind, value, depth + 1))
                continue
            references.update(_leaf_references(child_kind, value, options, client))
        return frozenset(references)

    return visit(rule_type, payload, 1)


def logical_reference_matches(rule_type, payload, value, *, client, location):
    try:
        references = logical_domain_references(rule_type, payload, client=client)
    except ReferenceRecognitionError as error:
        raise ValueError(f'Cannot recognize required {client} logical domain references at {location}: {error}') from error
    return select_logical_references(references, value, client=client, rule_type=rule_type, location=location)


def select_logical_references(references, value, *, client, rule_type, location):
    import logging
    selected = bool(references) and (value is None or canonical_domain(value) in references)
    logging.getLogger('RuleFramework').info(
        'Logical reference selection client=%s type=%s target=%r location=%s references=%s matched=%s',
        client, rule_type, value, location, sorted(references), selected)
    return selected


def is_parenthesized_payload(value):
    """Identify the structural shape requiring compound reference recognition."""
    return isinstance(value, str) and value.lstrip().startswith('(')

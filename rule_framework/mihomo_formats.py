"""Lossless mihomo YAML routing edits, with explicit unsupported source shapes."""
from rule_framework.text_json import split_physical_lines

from dataclasses import dataclass
from typing import Any

from rule_framework.logical_refs import is_parenthesized_payload, select_logical_references, LOGICAL_TYPES

from difflib import SequenceMatcher
from io import StringIO
import json
import re

from ruamel.yaml.nodes import MappingNode, ScalarNode, SequenceNode
from ruamel.yaml.resolver import VersionedResolver
from ruamel.yaml.scalarstring import DoubleQuotedScalarString, SingleQuotedScalarString


_SCALAR_RESOLVERS = (VersionedResolver(version=(1, 1)), VersionedResolver(version=(1, 2)))


def yaml_dump(yaml, value):
    stream = StringIO()
    yaml.dump(value, stream)
    return stream.getvalue()


def _scalar(value, style=None):
    if not isinstance(value, str):
        raise ValueError('mihomo routing entries must be strings')
    # Changed source spans must remain a single line and retain their string type
    # under either YAML version supported by the source parser.
    if (style == '"' or (style is None and value.startswith('DOMAIN-REGEX,'))
            or any(char in '\r\n\x85\u2028\u2029' or ord(char) < 0x20 for char in value)):
        value = DoubleQuotedScalarString(value)
    elif style == "'" or any(str(resolver.resolve(ScalarNode, value, (True, False))) != 'tag:yaml.org,2002:str'
                              for resolver in _SCALAR_RESOLVERS):
        value = SingleQuotedScalarString(value)
    parser = YAML()
    parser.width = max(4096, len(value) * 8 + 2)
    rendered = yaml_dump(parser, value)
    if rendered.endswith('...\n'):
        rendered = rendered[:-4]
    return rendered.removesuffix('\n')


def _header_metadata(raw, current, *, physical=False):
    # Preserve original spelling, whitespace and endings of unrelated comments.
    header = current.splitlines()
    desired = {}
    for line in header:
        if line and not line.startswith('#'):
            break
        match = re.fullmatch(r'#\s+([A-Z0-9_-]+|Total count):\s*(.*)', line)
        if match:
            key = 'TOTAL' if match[1] == 'Total count' else match[1]
            desired.setdefault(key, []).append(match[2])
    lines = split_physical_lines(raw) if physical else raw.splitlines(keepends=True)
    present = {}
    for index, line in enumerate(lines):
        if line.strip() and not line.lstrip().startswith('#'):
            if line.startswith(('%YAML ', '%TAG ')) or re.fullmatch(r'---(?:[ \t]+#.*)?[ \t]*', line.rstrip('\r\n')):
                continue
            break
        match = re.fullmatch(r'(\s*#\s+)([A-Z0-9_-]+|Total count)(:\s*)([^\r\n]*)(\r\n|\n|\r)?', line)
        key = ('TOTAL' if match[2] == 'Total count' else match[2]) if match else None
        if match and key in desired:
            values = desired[key]
            occurrence = present.get(key, 0)
            present[key] = occurrence + 1
            value = values[min(occurrence, len(values) - 1)]
            lines[index] = match[1] + match[2] + match[3] + value + (match[5] or '')
    newline = next((line[-2:] if line.endswith('\r\n') else line[-1:]
                    for line in lines if line.endswith(('\n', '\r'))), '\n')
    missing = [f'# {key}: {value}{newline}' for key, values in desired.items()
               for value in values[present.get(key, 0):]]
    return ''.join(missing + lines)


def _comment_indices(parts, *, line_starts=None, line_offset=0):
    pending = list(parts)
    while pending:
        comment = pending.pop()
        if isinstance(comment, (list, tuple)):
            pending.extend(comment)
        elif comment is not None:
            mark = getattr(comment, 'start_mark', None)
            if mark is None:
                yield None
            elif line_starts is None:
                yield mark.index
            else:
                line = mark.line + line_offset
                yield line_starts[line] + mark.column if 0 <= line < len(line_starts) else None


def _sequence_comment_keys(raw, spans, current, old_keys, new_keys, *, source_line=None):
    """Match surviving inline annotations to their actual source rows."""
    line_starts, line_offset = None, 0
    original_line = getattr(getattr(current, 'lc', None), 'line', None)
    if source_line is not None and original_line is not None:
        # Header replay can change absolute character/line offsets while data
        # retains its parsed marks. Sequence-relative coordinates stay valid.
        line_starts = [0, *(match.end() for match in re.finditer(r'\r\n|\n|\r', raw))]
        line_offset = source_line - original_line
    origins_by_position = {}
    for index, (end, line_end) in enumerate(spans):
        suffix = raw[end:line_end]
        if suffix.lstrip().startswith('#'):
            position = end + len(suffix) - len(suffix.lstrip())
            origins_by_position[position] = index
            old_keys[index] = ('source-row', index)
    for index, parts in getattr(getattr(current, 'ca', None), 'items', {}).items():
        origins = {origins_by_position[position] for position in _comment_indices(
                       parts, line_starts=line_starts, line_offset=line_offset)
                   if position in origins_by_position}
        if len(origins) == 1:
            new_keys[index] = ('source-row', origins.pop())


def render_yaml_routing(raw, baseline, data, yaml, key='payload'):
    """Patch single-line routing scalar spans and retain all other source bytes.

    Modified unsupported YAML shapes raise so a Task can restore its input.
    """
    if not yaml_values_equal({k: v for k, v in baseline.items() if k != key},
                             _semantic_snapshot({k: v for k, v in data.items() if k != key})):
        raise ValueError('Cannot reliably render changed non-routing YAML structures; use an explicit text modification')
    original = list(baseline.get(key, []))
    current = list(data.get(key, []))
    root = yaml.compose(raw)
    if not isinstance(root, MappingNode):
        raise ValueError('mihomo YAML must have a mapping root')
    pair = next(((name, value) for name, value in root.value if name.value == key), None)
    sequence = pair[1] if pair else None
    if original == current:
        return raw
    newline = next((match[0] for match in re.finditer(r'\r\n|\n|\r', raw)), '\n')
    if sequence is None and key not in baseline:
        block = key + ':' + newline + ''.join('  - ' + _scalar(value) + newline for value in current)
        marker = re.search(r'(?m)^\.\.\.(?:[ \t]*)(?:\r?\n)?\Z', raw)
        boundary = marker.start() if marker else len(raw)
        separator = '' if not raw[:boundary] or raw[:boundary].endswith(('\n', '\r')) else newline
        raw = raw[:boundary] + separator + block + raw[boundary:]
        return raw
    if not isinstance(sequence, SequenceNode):
        raise ValueError('Changed routing sequence requires recognizable YAML entries')
    if sequence.flow_style:
        segment = raw[sequence.start_mark.index:sequence.end_mark.index]
        if '#' in segment:
            raise ValueError('Cannot reliably preserve modified flow sequence comments; use an explicit text modification')
        replacement = '[' + ', '.join(_scalar(value, "'") for value in current) + ']'
        raw = raw[:sequence.start_mark.index] + replacement + raw[sequence.end_mark.index:]
        return raw
    records = []
    for scalar in sequence.value:
        if not isinstance(scalar, ScalarNode):
            raise ValueError('Changed routing sequence contains non-scalar items')
        start, end = scalar.start_mark.index, scalar.end_mark.index
        line_start = max(raw.rfind('\n', 0, start), raw.rfind('\r', 0, start)) + 1
        ending = re.search(r'\r\n|\r|\n', raw[end:])
        line_end = end + ending.end() if ending else len(raw)
        prefix = raw[line_start:start]
        if not re.fullmatch(r'[ \t]*-[ \t]+', prefix) or scalar.start_mark.line != scalar.end_mark.line:
            raise ValueError('Changed routing sequence requires recognizable single-line entries')
        records.append((start, end, line_start, line_end, scalar.style, prefix))
    newline = next((match[0] for match in re.finditer(r'\r\n|\n|\r', raw)), '\n')
    prefix = records[0][5] if records else '  - '
    patches = []
    if not current:
        key_end = pair[0].end_mark.index
        colon = raw.find(':', key_end)
        patches.append((colon + 1, colon + 1, ' []'))
    old_keys, new_keys = list(original), list(current)
    _sequence_comment_keys(raw, ((record[1], record[3]) for record in records),
                           data.get(key, []), old_keys, new_keys, source_line=sequence.start_mark.line)
    for operation, first, last, new_first, new_last in SequenceMatcher(a=old_keys, b=new_keys, autojunk=False).get_opcodes():
        shared = min(last - first, new_last - new_first)
        for offset in range(shared):
            if original[first + offset] == current[new_first + offset]:
                continue
            start, end, _, _, style, _ = records[first + offset]
            if raw[start:end].lstrip().startswith(('&', '!', '*')):
                raise ValueError('Cannot reliably modify anchored/tagged routing entries; use an explicit text modification')
            patches.append((start, end, _scalar(current[new_first + offset], style)))
        for offset in range(shared, last - first):
            start, end, line_start, line_end, _, _ = records[first + offset]
            if raw[start:end].lstrip().startswith(('&', '!', '*')):
                raise ValueError('Cannot reliably remove anchored/tagged routing entries; use an explicit text modification')
            patches.append((line_start, line_end, ''))
        if new_last - new_first > shared:
            boundary = records[last][2] if last < len(records) else records[-1][3]
            additions = ''.join(prefix + _scalar(item) + newline for item in current[new_first + shared:new_last])
            patches.append((boundary, boundary, additions))
    for first, last, replacement in sorted(patches, key=lambda patch: (patch[0], patch[1]), reverse=True):
        raw = raw[:first] + replacement + raw[last:]
    return raw

from collections import Counter
from copy import deepcopy
from pathlib import Path
import ipaddress
import logging

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarbool import ScalarBoolean
from rule_framework.value_semantics import yaml_values_equal

from rule_framework.ast import ASTNode, RuleNode, CommentNode, BlankNode, get_comma_indices_at_depth_0
from rule_framework.rule_helpers import (UNSET, native_rule_type, select_rule_types, rule_identity,
                                          validate_standard_value, validate_domain_selector,
                                          calculate_insert_index)

logger = logging.getLogger('RuleFramework')
BEHAVIORS = {'domain', 'ipcidr', 'classical'}
MIHOMO_TYPES = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX',
                'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP', 'PROCESS-NAME'}
IP_TYPES = {'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP'}
MIHOMO_FIELDS = ('_metadata_baseline', '_metadata_committed', 'behavior', 'format', 'file_role', 'client', '_raw_bytes', '_encoding', '_newline',
                 '_source_data', '_synced_values', '_source_values', '_metadata', '_sequence_key', '_annotations_full', '_annotations_outside', '_source_exists')


def is_mihomo_path(filepath):
    parts = str(filepath).replace('\\', '/').lower().split('/')
    return bool(set(parts[:-1]) & {'clash', 'mihomo'} or
                re.match(r'^(?:clash|mihomo)(?:[._ -]|$)', parts[-1]))


def _semantic_snapshot(value, memo=None):
    """Keep independent values without copying ruamel's per-item source metadata."""
    memo = {} if memo is None else memo
    if id(value) in memo:
        return memo[id(value)]
    if isinstance(value, dict):
        result = {}
        memo[id(value)] = result
        result.update({_semantic_snapshot(key, memo): _semantic_snapshot(item, memo) for key, item in value.items()})
        return result
    if isinstance(value, list):
        result = []
        memo[id(value)] = result
        result.extend(_semantic_snapshot(item, memo) for item in value)
        return result
    if isinstance(value, ScalarBoolean):
        return bool(value)
    if isinstance(value, str):
        return str(value)
    if hasattr(value, 'tag') and hasattr(value, 'value'):
        return ('yaml-tag', str(value.tag), _semantic_snapshot(value.value, memo))
    return deepcopy(value, memo)


def _yaml_annotations(data, skip_key=None):
    """Record meaningful YAML attributes independently of ruamel parser handles."""
    result = []
    seen = set()

    def comments(value, path):
        if isinstance(value, dict):
            for key, item in value.items():
                comments(item, path + (str(key),))
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                comments(item, path + (str(index),))
        elif value is not None and isinstance(getattr(value, 'value', None), str):
            result.append(('comment', path, value.value))

    def walk(value, path):
        if id(value) in seen:
            return
        seen.add(id(value))
        anchor = getattr(value, '_yaml_anchor', None)
        if anchor is not None and anchor.value:
            result.append(('anchor', path, str(anchor.value)))
        tag = getattr(value, '_yaml_tag', None)
        if tag is not None and getattr(tag, 'value', None):
            result.append(('tag', path, str(tag.value)))
        annotation = getattr(value, '_yaml_comment', None)
        if annotation is not None:
            comments(annotation.comment, path + ('ca-comment',))
            comments(annotation.items, path + ('ca-items',))
            comments(annotation.end, path + ('ca-end',))
        if isinstance(value, dict):
            for key, item in value.items():
                if not (path == () and key == skip_key):
                    walk(item, path + (str(key),))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, path + (str(index),))

    walk(data, ())
    return tuple(result)


def _readme_link_destinations(line):
    """Keep inline-link destinations while consuming labels and title text."""
    pieces, cursor = [], 0
    for marker in re.finditer(r'\]\(', line):
        if marker.start() < cursor:
            continue
        begin, depth = marker.start() - 1, 1
        while begin >= cursor and depth:
            if begin and line[begin - 1] == '\\':
                begin -= 2
                continue
            if line[begin] == '[':
                depth -= 1
            elif line[begin] == ']':
                depth += 1
            begin -= 1
        if depth:
            continue
        begin += 1
        start = index = marker.end()
        depth, quote, angle = 1, None, False
        while index < len(line) and depth:
            char = line[index]
            if char == '\\':
                index += 2
                continue
            if quote:
                if char == quote:
                    quote = None
            elif angle:
                if char == '>':
                    angle = False
            elif char in ('"', "'") and depth == 1 and index > start and line[index - 1].isspace():
                quote = char
            elif char == '<' and depth == 1:
                angle = True
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            index += 1
        if depth:
            # An incomplete construct supplies no trustworthy asset reference.
            pieces.append(line[cursor:begin])
            cursor = len(line)
            break
        payload = line[start:index - 1].strip()
        if payload.startswith('<'):
            end = payload.find('>')
            destination = payload[1:end] if end >= 0 else ''
        else:
            destination = payload.split(None, 1)[0] if payload else ''
        pieces.extend((line[cursor:begin], ' ', destination, ' '))
        cursor = index
    return ''.join(pieces) + line[cursor:]


def _readme_references_asset(line, filename):
    """Compare complete prose/code references and Markdown link destinations."""
    from urllib.parse import unquote, urlsplit

    # Link labels can name a different asset; the destination supplies identity.
    line = _readme_link_destinations(line)
    references = re.finditer(
        r"""\x60([^\x60]+)\x60|"([^"]+)"|'([^']+)'|([^\s|<>，；。]+)""", line)
    for reference in references:
        value = next(part for part in reference.groups() if part is not None)
        if value.startswith(('file:', 'path:', 'url:')):
            value = value.split(':', 1)[1]
        if value.startswith(('http://', 'https://')):
            try:
                value = unquote(urlsplit(value).path)
            except ValueError:
                continue
        if value.replace('\\', '/').rsplit('/', 1)[-1] == filename:
            return True
    return False


def provider_behavior(filepath, values, data=None):
    """Use provider settings, import notes, filename and unambiguous content."""
    data = data or {}
    explicit = data.get('behavior')
    if explicit is not None:
        if explicit not in BEHAVIORS:
            raise ValueError(f'Unsupported mihomo provider behavior: {explicit!r}')
        return explicit
    path = Path(filepath)
    # A neighboring import instruction can establish a purpose for arbitrary names.
    readme = path.with_name('README.md')
    if readme.is_file():
        for line in readme.read_text(encoding='utf-8-sig').splitlines():
            if _readme_references_asset(line, path.name):
                match = re.search(r'behavior\s*:\s*["\']?(domain|ipcidr|classical)\b', line, re.I)
                if match:
                    return match[1].lower()
    stem = path.stem.lower()
    if stem.endswith('_domain'):
        return 'domain'
    if re.search(r'_ip(?:_no_ipv6)?$', stem):
        return 'ipcidr'
    if stem.endswith('_classical') or path.suffix.lower() == '.list':
        return 'classical'
    active = [str(value).strip() for value in values if str(value).strip() and not str(value).lstrip().startswith('#')]
    if not active:
        return 'classical' if path.suffix.lower() in ('.yaml', '.yml') else None
    if all(re.match(r'^[A-Za-z][A-Za-z0-9-]*,', value) for value in active):
        return 'classical'
    if all(re.fullmatch(r'[\w.*+-]+', value, re.UNICODE) for value in active):
        return 'domain'
    if all('/' in value and _network(value) is not None for value in active):
        return 'ipcidr'
    return None


def _network(value):
    try:
        return ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return None


def mihomo_options(options, rule_type):
    if not isinstance(options, (list, tuple)) or any(not isinstance(value, str) for value in options):
        raise ValueError('options must be a list of strings; [] clears options')
    if len(set(options)) != len(options):
        raise ValueError('Duplicate mihomo matching options')
    for option in options:
        if option not in {'no-resolve', 'src'}:
            raise ValueError(f'Unsupported mihomo matching option: {option}')
        if rule_type not in IP_TYPES:
            raise ValueError(f'{option} requires a target IP rule')
    return tuple(options)


def mihomo_conditions(conditions):
    if not isinstance(conditions, dict) or set(conditions) - {'no_resolve', 'src'}:
        raise ValueError('mihomo conditions require no_resolve/src booleans')
    if any(not isinstance(value, bool) for value in conditions.values()):
        raise ValueError('mihomo matching conditions must be booleans')
    return tuple(sorted({'no_resolve': 'no-resolve', 'src': 'src'}[key]
                        for key, enabled in conditions.items() if enabled))


class MihomoRuleNode(RuleNode):
    """Reference, matching options and result are separate; raw fields stay local."""

    def __init__(self, line, behavior, *, profile=False):
        self.original = line
        self.behavior = behavior
        self.profile = profile
        policy = None
        self.inline_comment = ''
        self.raw_tokens = []
        value = line.strip()
        if behavior == 'domain':
            if value.startswith('+.') and '*' not in value[2:]:
                rule_type, value = 'DOMAIN-SUFFIX', value[2:]
            elif value.startswith('.') or '*' in value or '+' in value:
                rule_type = 'DOMAIN-WILDCARD'
            else:
                rule_type = 'DOMAIN'
            options = ()
        elif behavior == 'ipcidr':
            network = _network(value)
            rule_type = 'IP-CIDR6' if network and network.version == 6 else 'IP-CIDR'
            options = ()
        else:
            match = re.search(r'\s+#', line)
            self.inline_comment = line[match.start():] if match else ''
            content = line[:match.start()] if match else line
            native_type = content.split(',', 1)[0].strip().upper()
            if native_type in {'DOMAIN-REGEX', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX'}:
                # Pinned ParseRulePayload joins the complete regex payload, with
                # the final comma field being the result in a complete profile.
                first = content.find(',')
                last = content.rfind(',') if profile else len(content)
                self.raw_tokens = ([content[:first], content[first + 1:last], content[last + 1:]]
                                   if profile and last > first else [content[:first], content[first + 1:]])
            else:
                boundaries = [-1, *get_comma_indices_at_depth_0(content), len(content)]
                self.raw_tokens = [content[first + 1:last] for first, last in zip(boundaries, boundaries[1:])]
            if len(self.raw_tokens) < 2:
                raise ValueError('classical rule requires type and value')
            parts = [part.strip() for part in self.raw_tokens]
            rule_type, value = parts[:2]
            if profile and rule_type.upper() == 'MATCH':
                value, policy, options = '', parts[1], tuple(parts[2:])
            elif profile:
                policy = parts[2] if len(parts) > 2 else None
                options = tuple(parts[3:])
            else:
                options = tuple(parts[2:])
        super().__init__(rule_type, value, policy)
        self.options = options
        self._original_fields = (self.type, self.value, self.policy, self.options)
        self.native_passthrough = False

    @property
    def identity(self):
        return rule_identity(self.type, self.value, self.options)

    def render(self):
        if (self.type, self.value, self.policy, self.options) == self._original_fields:
            return self.original
        if self.behavior == 'domain':
            content = ('+.' if self.type == 'DOMAIN-SUFFIX' else '') + self.value
        elif self.behavior == 'ipcidr':
            content = self.value
        else:
            fields = [self.type, self.value]
            original = list(self._original_fields[:2])
            if self.profile:
                if self.type.upper() == 'MATCH':
                    fields, original = [self.type], [self._original_fields[0]]
                fields.append(self.policy or '')
                original.append(self._original_fields[2])
            fields.extend(self.options)
            original.extend(self._original_fields[3])
            for index, current in enumerate(fields):
                if index < len(self.raw_tokens):
                    raw = self.raw_tokens[index]
                    fields[index] = raw if index < len(original) and current == original[index] else (
                        raw[:len(raw) - len(raw.lstrip())] + current + raw[len(raw.rstrip()):])
            content = ','.join(fields) + self.inline_comment
        if self.behavior != 'classical':
            content = self.original[:len(self.original) - len(self.original.lstrip())] + content + self.original[len(self.original.rstrip()):]
        return content


def parse_mihomo_entry(value, behavior, *, text=False, profile=False):
    if not isinstance(value, str):
        raise ValueError('mihomo routing sequence entries must be strings')
    if text and not value.strip():
        return BlankNode(value)
    if text and value.lstrip().startswith(('#', '//', ';')):
        return CommentNode(value)
    try:
        if behavior is None:
            raise ValueError('Provider behavior is unknown')
        return MihomoRuleNode(value, behavior, profile=profile)
    except ValueError as error:
        node = CommentNode(value)
        node.recognition_error = str(error)
        return node


def validate_mihomo_node(node, behavior):
    if not isinstance(node, MihomoRuleNode):
        if isinstance(node, (CommentNode, BlankNode)) and not getattr(node, 'recognition_error', None):
            from rule_framework.managed_validation import validate_passive_node
            validate_passive_node(node)
            return
        raise ValueError('Changed mihomo routing content has unrecognized syntax')
    if node.profile:
        if not isinstance(node.policy, str) or not node.policy.strip() or re.search(r'[,\r\n\0]', node.policy):
            raise ValueError('Complete mihomo profile rules require a non-empty policy result')
        if node.type.upper() == 'MATCH':
            if node.options:
                raise ValueError('MATCH does not support matching options')
            return
    elif node.policy not in (None, ''):
        raise ValueError('mihomo provider content has no policy result')
    if not isinstance(node.value, str) or not node.value.strip() or any(char in node.value for char in '\r\n\0'):
        raise ValueError('Rule value must be a non-empty single-line string')
    if behavior == 'domain':
        if node.type not in {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-WILDCARD'} or node.options:
            raise ValueError('domain behavior requires domain entries without matching options')
        if node.type in {'DOMAIN', 'DOMAIN-SUFFIX'}:
            validate_standard_value(node.type, node.value)
        elif not re.fullmatch(r'[\w.*+-]+', node.value, re.UNICODE):
            raise ValueError('Invalid Clash domain wildcard expression')
    elif behavior == 'ipcidr':
        if node.type not in {'IP-CIDR', 'IP-CIDR6'} or node.options or _network(node.value) is None or '/' not in node.value:
            raise ValueError('ipcidr behavior requires a naked CIDR without matching options')
    else:
        if node.type.upper() not in MIHOMO_TYPES:
            raise ValueError(f'Unverified mihomo structured type {node.type!r}; use explicit native input')
        if node.type.upper() in {'IP-CIDR', 'IP-CIDR6'}:
            if _network(node.value) is None or '/' not in node.value:
                raise ValueError('mihomo IP rules require a CIDR prefix with an explicit mask')
        elif node.type.upper() == 'DOMAIN-REGEX':
            pass  # Payload structure is verified; native regex execution is catalogued separately.
        else:
            validate_standard_value(node.type.upper(), node.value)
        mihomo_options(node.options, node.type.upper())


def mihomo_domain_references(node, *, client='mihomo'):
    """Finite exact references, including supported recursive logical conditions."""
    from rule_framework.domain_refs import canonical_domain, domain_pattern_references, ReferenceRecognitionError
    kind = node.type.upper()
    if kind in {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-WILDCARD'}:
        return frozenset({canonical_domain(node.value)})
    if kind == 'DOMAIN-REGEX':
        return domain_pattern_references(node.value).hosts
    if kind in {'AND', 'OR', 'NOT'}:
        from rule_framework.logical_refs import logical_domain_references
        return logical_domain_references(kind, node.value, client=client)
    if kind == 'SUB-RULE':
        raise ReferenceRecognitionError('SUB-RULE external control-flow references require explicit maintenance')
    return frozenset()


class MihomoRoutingMixin:
    @property
    def is_domain_behavior(self):
        return self.behavior == 'domain'

    def _require_behavior(self):
        if self.behavior not in BEHAVIORS:
            raise ValueError('Cannot reliably identify mihomo provider behavior from source/context')

    def add_rule(self, rule_type, value, policy=UNSET, insert=None, *, conditions=UNSET, options=UNSET):
        self._require_behavior()
        self._sync_managed_state()
        profile = self.file_role == 'full-profile'
        if not profile and policy is not UNSET and policy not in (None, ''):
            raise ValueError('mihomo provider content has no policy result')
        native_type = native_rule_type(rule_type, value, client='mihomo')
        if self.behavior == 'domain' and native_type not in {'DOMAIN', 'DOMAIN-SUFFIX'}:
            raise ValueError('domain behavior generation supports literal/domain_suffix; expressions use explicit native input')
        if self.behavior == 'ipcidr' and native_type not in {'IP-CIDR', 'IP-CIDR6'}:
            raise ValueError('ipcidr behavior requires an IP rule')
        selected = mihomo_conditions(conditions) if conditions is not UNSET else UNSET
        if selected is not UNSET:
            mihomo_options(selected, native_type)
        if options is not UNSET:
            options = mihomo_options(options, native_type)
        index = self._insert_index(insert)
        desired_options = options if options is not UNSET else (() if selected is UNSET else selected)
        prefix = rule_identity(native_type, value)[:2]
        matches = [node for node in self.nodes if isinstance(node, MihomoRuleNode) and node.identity[:2] == prefix
                   and (selected is UNSET or node.identity[2] == selected)]
        # Validate the intended entry even for a repeat/no-op operation.
        result = policy if policy is not UNSET else (matches[0].policy if matches else None)
        content = (('+.' if native_type == 'DOMAIN-SUFFIX' else '') + value if self.behavior == 'domain'
                   else value if self.behavior == 'ipcidr' else ','.join(
                       [native_type, value, *([result or ''] if profile else []), *desired_options]))
        candidate = MihomoRuleNode(content, self.behavior, profile=profile)
        validate_mihomo_node(candidate, self.behavior)
        self._validate_policy_target(candidate)
        if matches:
            for node in matches:
                validate_mihomo_node(node, self.behavior)
            modified = 0
            for node in matches:
                changed = False
                if policy is not UNSET and node.policy != policy:
                    node.policy = policy
                    changed = True
                if options is not UNSET and node.options != options:
                    node.options = options
                    changed = True
                modified += changed
            if modified:
                self._changed()
            logger.info('Rule update matched=%s modified=%s in %s', len(matches), modified, self.filepath)
            return
        satisfied = [node for node in self.nodes if isinstance(node, MihomoRuleNode)
                     and node.identity == candidate.identity
                     and (policy is UNSET or node.policy == policy)]
        if satisfied:
            logger.info('Rule update already satisfied; matched=%s modified=0 in %s', len(satisfied), self.filepath)
            return
        self.nodes.insert(index, candidate)
        self._changed()

    def add_native_rule(self, content, insert=None):
        from rule_framework.native_input import validate_native_entry
        validate_native_entry(self, content, kind='rule')
        if not isinstance(content, str) or not content.strip() or any(char in content for char in '\r\n\0'):
            raise ValueError('Native mihomo input must be one non-empty line')
        self._sync_managed_state()
        index = self._insert_index(insert)
        node = parse_mihomo_entry(content, self.behavior, profile=self.file_role == 'full-profile')
        verified = False
        if self.file_role == 'rule-provider' and self.behavior == 'classical' and isinstance(node, MihomoRuleNode) and node.type.upper() in {'MATCH', 'RULE-SET', 'SUB-RULE'}:
            raise ValueError(f'classical provider forbids {node.type.upper()} rules')
        if isinstance(node, MihomoRuleNode) and (node.type.upper() in MIHOMO_TYPES or node.type.upper() == 'MATCH'):
            validate_mihomo_node(node, self.behavior)
            self._validate_policy_target(node)
            verified = True
        if verified:
            matches = [item for item in self.nodes if isinstance(item, MihomoRuleNode) and item.identity == node.identity]
            if matches:
                modified = 0
                for item in matches:
                    if item.policy != node.policy:
                        item.policy = node.policy
                        modified += 1
                if modified:
                    self._changed()
                logger.info('Rule update matched=%s modified=%s in %s', len(matches), modified, self.filepath)
                return
        existing = [item for item in self.nodes if item.render() == content]
        if existing:
            logger.info('Native input already present; matched=%s modified=0', len(existing))
            return
        node.native_passthrough = not verified
        self.nodes.insert(index, node)
        self._changed()

    def _validate_policy_target(self, node):
        if not isinstance(node, MihomoRuleNode) or not node.profile:
            return
        targets = {'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'PASS-RULE', 'COMPATIBLE', 'GLOBAL'}
        for key in ('proxies', 'proxy-groups'):
            for item in self.data.get(key, []) or []:
                if isinstance(item, dict) and isinstance(item.get('name'), str):
                    targets.add(item['name'])
        if node.policy not in targets:
            raise ValueError(f'Policy result target {node.policy!r} is not a declared mihomo outbound')

    def _insert_index(self, insert):
        section = getattr(self, '_sequence_key', None)
        index = calculate_insert_index(self.nodes, insert, is_section=section is not None, section_name=section)
        if insert is None and self.file_role == 'full-profile':
            index = next((index for index, node in enumerate(self.nodes)
                          if isinstance(node, MihomoRuleNode) and node.type.upper() == 'MATCH'), len(self.nodes))
        return index

    def remove_rule(self, rule_type, value=None, *, conditions=UNSET):
        self._require_behavior()
        selected_types = select_rule_types(rule_type)
        if rule_type == 'domain' and value is not None:
            validate_domain_selector(value)
        selected_conditions = mihomo_conditions(conditions) if conditions is not UNSET else UNSET
        from rule_framework.domain_refs import canonical_domain, ReferenceRecognitionError
        self._sync_managed_state()
        retained = []
        removed = 0
        for position, node in enumerate(self.nodes, 1):
            selected = isinstance(node, MihomoRuleNode) and node.type.upper() in selected_types
            if rule_type == 'domain' and isinstance(node, MihomoRuleNode):
                try:
                    references = mihomo_domain_references(node)
                except ReferenceRecognitionError as error:
                    raise ValueError(f'Cannot recognize required domain references at {self.filepath}:{position}: {error}') from error
                if node.type.upper() not in MIHOMO_TYPES | {'MATCH', 'USER-AGENT', 'AND', 'OR', 'NOT'} and (
                        value is None or is_parenthesized_payload(node.value) or canonical_domain(node.value) == canonical_domain(value)):
                    raise ValueError(f'Cannot recognize required domain reference in unknown rule type {node.type!r} '
                                     f'at {self.filepath}:{position}')
                selected = bool(references) and (value is None or canonical_domain(value) in references)
                if node.type.upper() in LOGICAL_TYPES:
                    selected = select_logical_references(references, value, client=self.client,
                        rule_type=node.type, location=f'{self.filepath}:{position}')
            elif selected and value is not None:
                selected = node.value == value
            elif rule_type == 'domain' and getattr(node, 'recognition_error', None):
                content = node.render()
                if (value is None or value in content
                        or re.match(r'^\s*(?:AND|OR|NOT)(?:$|[\s,(])', content, re.IGNORECASE)):
                    raise ValueError(f'Cannot recognize required domain reference at {self.filepath}:{position}: '
                                     f'{node.recognition_error}')
            if selected and selected_conditions is not UNSET:
                selected = node.identity[2] == selected_conditions
            if selected:
                removed += 1
            else:
                retained.append(node)
        if removed:
            self.nodes = retained
            self._changed()
        logger.info('Removed %s matching rules from %s', removed, self.filepath)

    def modify(self, search, replace, is_regex=False, count=0):
        from rule_framework.fom import _apply_text_replacement
        previous = self.render_bytes().decode(self._encoding)
        updated, _ = _apply_text_replacement(previous, search, replace, is_regex, count)
        if updated == previous:
            return
        candidate = type(self)(self.filepath)
        candidate.settings = deepcopy(getattr(self, 'settings', {}))
        candidate._load_bytes(updated.encode(self._encoding))
        before = [node.render() for node in self.nodes]
        after = [node.render() for node in candidate.nodes]
        for operation, _, _, first, last in SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes():
            if operation != 'equal':
                for node in candidate.nodes[first:last]:
                    node.needs_validation = True
        candidate._source_values = tuple(before)
        candidate.validate()
        candidate._source_values = tuple(after)
        from rule_framework.metadata import metadata_key, without_metadata, metadata_baselines, split_header
        owned = MIHOMO_TYPES | LOGICAL_TYPES | {'AUTHOR', 'REPO', 'UPDATED', 'TOTAL'}
        metadata_lines = lambda text: tuple(record for record in split_header(text)[0] if metadata_key(record.rstrip('\r\n'), owned))
        explicit_metadata = metadata_lines(previous) != metadata_lines(updated)
        baseline = self._metadata_baseline
        if not explicit_metadata:
            for original in metadata_baselines(self):
                if without_metadata(updated, owned, header_only=True) == without_metadata(original.decode(self._encoding), owned, header_only=True):
                    candidate._load_bytes(original)
                    break
        if hasattr(self, '_metadata_origin'):
            candidate._metadata_origin = self._metadata_origin
        candidate._metadata_baseline = baseline
        candidate._metadata_committed = dict(self._metadata_committed)
        candidate.is_dirty = True
        candidate._metadata_edit_pending = explicit_metadata
        candidate.update_metadata(only_if_changed=True)
        self.restore_state(candidate.snapshot_state())

    def _changed(self):
        self.is_dirty = True
        self._commit_nodes()
        self.update_metadata(only_if_changed=True)

    def _get_rule_count(self):
        return sum(isinstance(node, MihomoRuleNode) or bool(getattr(node, 'recognition_error', None)) for node in self.nodes)

    def update_metadata(self, *, only_if_changed=False):
        metadata_before = self.render_bytes() if not only_if_changed else None
        from rule_framework.metadata import without_metadata, metadata_baselines, split_header, restore_list_metadata, finish_generated_metadata
        owned = MIHOMO_TYPES | LOGICAL_TYPES | {'AUTHOR', 'REPO', 'UPDATED', 'TOTAL'}
        self._metadata = {}
        current = self.render_bytes()
        if only_if_changed and not getattr(self, '_metadata_edit_pending', False):
            for baseline in metadata_baselines(self):
                text = baseline.decode(self._encoding)
                if without_metadata(current.decode(self._encoding), owned, header_only=True) != without_metadata(text, owned, header_only=True):
                    continue
                header, _ = split_header(text)
                _, source_body = split_header(self._raw_bytes.decode(self._encoding))
                self._raw_bytes = (''.join(header) + ''.join(source_body)).encode(self._encoding)
                if self.format == 'text':
                    restore_list_metadata(self, text, owned, header_only=True)
                    self._commit_nodes()
                self._metadata = {}
                return
        from rule_framework.fom import _get_now
        raw = self._raw_bytes.decode(self._encoding)
        if self.format == 'yaml' and not self._source_exists:
            raw = yaml_dump(self.yaml, self.data)
        counts = Counter(node.type.upper() for node in self.nodes if isinstance(node, MihomoRuleNode))
        metadata = {'TOTAL': str(self._get_rule_count()), 'UPDATED': _get_now(self)}
        for key in counts.keys() | MIHOMO_TYPES | LOGICAL_TYPES:
            if re.search(rf'(?:\A|(?<=[\r\n]))# {key}:', raw):
                metadata[key] = str(counts[key])
        settings = getattr(self, 'settings', {})
        from rule_framework.metadata import resolve_signature
        metadata['AUTHOR'], metadata['REPO'] = resolve_signature(settings)
        self._metadata = metadata
        finish_generated_metadata(self, only_if_changed, (), before=metadata_before)

    def validate(self):
        super().validate()
        self._sync_managed_state()
        if self.behavior not in BEHAVIORS | {None}:
            raise ValueError('Invalid managed provider behavior')
        expected_format = 'yaml' if hasattr(self, 'yaml') else 'text'
        if self.format != expected_format:
            raise ValueError(f'Invalid managed format: {self.format!r}; adapter requires {expected_format}')
        if self.file_role not in {'rule-provider', 'full-profile'} or self.client != 'mihomo':
            raise ValueError('Invalid managed mihomo client/file role')
        if self.file_role == 'full-profile' and expected_format != 'yaml':
            raise ValueError('Complete mihomo profiles require YAML format')
        if hasattr(self, 'data') and self.file_role == 'rule-provider':
            if 'behavior' in self.data and self.data['behavior'] != self.behavior:
                raise ValueError('Managed behavior conflicts with YAML provider settings')
            if self.data.get('format', 'yaml') != 'yaml':
                raise ValueError('YAML provider content requires yaml format')
        source_values = set(self._source_values)
        for node in self.nodes:
            if not isinstance(node, ASTNode):
                raise ValueError('Managed mihomo nodes must be AST nodes')
            changed = getattr(node, 'needs_validation', False) or node.render() not in source_values or (isinstance(node, MihomoRuleNode) and
                       (node.type, node.value, node.policy, node.options) != node._original_fields)
            if changed and not getattr(node, 'native_passthrough', False):
                validate_mihomo_node(node, self.behavior)
                self._validate_policy_target(node)

    def validate_complete(self):
        # Source-shape failures belong to the Task, before batch publication.
        self._metadata_baseline = self.render_bytes()
        self._metadata_committed = dict(self._metadata)

    def _apply_metadata(self, raw):
        if not self._metadata:
            return raw
        desired = []
        for key, value in self._metadata.items():
            if key in {'AUTHOR', 'REPO'}:
                originals = re.findall(rf'(?:\A|(?<=[\r\n]))# {key}: ([^\r\n]*)', raw)
                desired.extend(f'# {key}: {item}' for item in originals)
                if value not in (original.strip() for original in originals):
                    desired.append(f'# {key}: {value}')
            else:
                desired.append(f'# {key}: {value}')
        return _header_metadata(raw, '\n'.join(desired), physical=self.format == 'text')


class MihomoYamlMixin(MihomoRoutingMixin):
    def __init__(self, filepath):
        self.filepath = filepath
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        self.yaml.width = 4096
        self.client, self.format, self.file_role = 'mihomo', 'yaml', 'rule-provider'
        self._sequence_key = 'payload'
        self.data = CommentedMap(payload=CommentedSeq())
        self.nodes = []
        self.behavior = provider_behavior(filepath, [])
        self.is_dirty = False
        self._raw_bytes, self._encoding, self._newline = b'', 'utf-8', '\n'
        self._source_exists = False
        self._source_data = _semantic_snapshot(self.data)
        self._synced_values = self._source_values = ()
        self._metadata = {}
        self._metadata_baseline = self._raw_bytes
        self._metadata_committed = {}
        self._annotations_full = _yaml_annotations(self.data)
        self._annotations_outside = _yaml_annotations(self.data, self._sequence_key)

    def load(self):
        self._load_bytes(Path(self.filepath).read_bytes())

    def _load_bytes(self, raw_bytes):
        self._source_exists = True
        self._raw_bytes = raw_bytes
        self._encoding = 'utf-8-sig' if self._raw_bytes.startswith(b'\xef\xbb\xbf') else 'utf-8'
        raw = self._raw_bytes.decode(self._encoding)
        self._newline = next((match[0] for match in re.finditer(r'\r\n|\n|\r', raw)), '\n')
        self.data = self.yaml.load(raw)
        if self.data is None:
            self.data = CommentedMap(payload=CommentedSeq())
        if not isinstance(self.data, dict):
            raise ValueError('mihomo YAML requires a mapping root')
        if 'rules' in self.data and 'payload' in self.data:
            raise ValueError('Ambiguous mihomo YAML purpose: rules and payload coexist')
        profile = 'rules' in self.data or any(key in self.data for key in ('proxies', 'proxy-groups', 'mixed-port', 'rule-providers'))
        self.file_role = 'full-profile' if profile else 'rule-provider'
        self._sequence_key = 'rules' if profile else 'payload'
        values = self.data.get(self._sequence_key, [])
        if not isinstance(values, list) or (not profile and 'payload' not in self.data):
            raise ValueError(f'mihomo YAML requires a {self._sequence_key} sequence')
        self.behavior = 'classical' if profile else provider_behavior(self.filepath, values, self.data)
        self.nodes = [parse_mihomo_entry(item, self.behavior, profile=profile) for item in values]
        self._synced_values = self._source_values = tuple(str(item) for item in values)
        self._source_data = _semantic_snapshot(self.data)
        self._annotations_full = _yaml_annotations(self.data)
        self._annotations_outside = _yaml_annotations(self.data, self._sequence_key)
        self._metadata = {}
        self._metadata_baseline = self._raw_bytes
        self._metadata_committed = {}
        self.is_dirty = False

    def _commit_nodes(self):
        payload = self.data.setdefault(self._sequence_key, CommentedSeq())
        current = [node.render() for node in self.nodes]
        operations = SequenceMatcher(a=list(map(str, payload)), b=current, autojunk=False).get_opcodes()
        originals = tuple(getattr(node, 'original', None) for node in self.nodes)
        if len(payload) == len(self.nodes) and originals in (tuple(map(str, payload)), self._source_values):
            # Parsed nodes still occupy their known source rows, even when an
            # option update makes several formerly distinct entries identical,
            # or an earlier update already changed the current payload strings.
            operations = [('replace', 0, len(payload), 0, len(current))]
        retained = set(current) | {str(getattr(node, 'original', value)) for node, value in zip(self.nodes, current)}
        for operation, first, last, new_first, new_last in operations:
            if operation == 'equal':
                continue
            shared = min(last - first, new_last - new_first)
            for index in range(first + shared, last):
                if (getattr(getattr(payload, 'ca', None), 'items', {}).get(index)
                        and str(payload[index]) in retained):
                    raise ValueError('Cannot reliably preserve YAML annotations for ambiguous node sequence edits; '
                                     'use managed routing sequence operations or an explicit text modification')
        # Preserve CommentedSeq's attached comments and quote styles on updates.
        for operation, first, last, new_first, new_last in reversed(operations):
            if operation == 'equal':
                continue
            shared = min(last - first, new_last - new_first)
            for offset in range(shared):
                payload[first + offset] = current[new_first + offset]
            for index in range(last - 1, first + shared - 1, -1):
                del payload[index]
            for index in range(new_last - 1, new_first + shared - 1, -1):
                payload.insert(first + shared, current[index])
        self._synced_values = tuple(current)

    def _sync_managed_state(self):
        if not isinstance(self.data, dict) or not isinstance(self.data.get(self._sequence_key, []), list):
            raise ValueError(f'mihomo YAML requires a {self._sequence_key} sequence')
        values = tuple(self.data.get(self._sequence_key, []))
        rendered = tuple(node.render() for node in self.nodes)
        if values != self._synced_values and rendered != self._synced_values and values != rendered:
            raise ValueError('Conflicting managed YAML nodes and payload changes')
        if values != self._synced_values:
            self.nodes = [parse_mihomo_entry(item, self.behavior, profile=self.file_role == 'full-profile') for item in values]
            self._synced_values = values
            self.is_dirty = True
            self.update_metadata(only_if_changed=True)
        elif rendered != self._synced_values:
            self._changed()

    def render_bytes(self):
        self.validate()
        raw = self._raw_bytes.decode(self._encoding)
        same_values = yaml_values_equal(_semantic_snapshot(self.data), self._source_data)
        if self._source_exists and (_yaml_annotations(self.data, self._sequence_key) != self._annotations_outside or
                                    (same_values and _yaml_annotations(self.data) != self._annotations_full)):
            raise ValueError('Changed YAML annotations require an explicit text modification; supported routing edits preserve source annotations')
        if self._source_exists and same_values and not self._metadata:
            return self._raw_bytes
        if not raw:
            raw = yaml_dump(self.yaml, self.data)
        else:
            raw = render_yaml_routing(raw, self._source_data, self.data, self.yaml, self._sequence_key)
        raw = self._apply_metadata(raw)
        parsed = self.yaml.load(raw)
        if not isinstance(parsed, dict) or list(parsed.get(self._sequence_key, [])) != list(self.data.get(self._sequence_key, [])):
            raise ValueError('Rendered mihomo routing sequence differs from current managed state')
        return raw.encode(self._encoding)

    def save(self):
        Path(self.filepath).write_bytes(self.render_bytes())


class MihomoTextMixin(MihomoRoutingMixin):
    def __init__(self, filepath):
        super().__init__(filepath)
        self.client, self.format, self.file_role = 'mihomo', 'text', 'rule-provider'
        self.behavior = provider_behavior(filepath, [])
        self._raw_bytes, self._encoding, self._newline = b'', 'utf-8', '\n'
        self._source_exists = False
        self._source_values = self._synced_values = ()
        self._source_data = {}
        self._metadata = {}
        self._metadata_baseline = self._raw_bytes
        self._metadata_committed = {}

    def load(self):
        self._load_bytes(Path(self.filepath).read_bytes())

    def _load_bytes(self, raw_bytes):
        self._source_exists = True
        self._raw_bytes = raw_bytes
        self._encoding = 'utf-8-sig' if self._raw_bytes.startswith(b'\xef\xbb\xbf') else 'utf-8'
        raw = self._raw_bytes.decode(self._encoding)
        records = split_physical_lines(raw)
        lines = [record.rstrip('\r\n') for record in records]
        self._newline = next((record[len(line):] for record, line in zip(records, lines)
                              if record[len(line):]), '\n')
        self.ends_with_newline = raw.endswith(('\r', '\n'))
        self.behavior = provider_behavior(self.filepath, lines)
        self.nodes = []
        for record, line in zip(records, lines):
            node = parse_mihomo_entry(line, self.behavior, text=True)
            node.line_ending = record[len(line):]
            self.nodes.append(node)
        self._synced_values = self._source_values = tuple(lines)
        self._metadata = {}
        self._metadata_baseline = self._raw_bytes
        self._metadata_committed = {}
        self.is_dirty = False

    def _commit_nodes(self):
        self._synced_values = tuple(node.render() for node in self.nodes)

    def _sync_managed_state(self):
        if tuple(node.render() for node in self.nodes) != self._synced_values:
            self._changed()

    def render_bytes(self):
        self.validate()
        from rule_framework.text_json import serialize_physical_nodes
        raw = serialize_physical_nodes(self.nodes, newline=self._newline,
            ends_with_newline=getattr(self, 'ends_with_newline', True), encoding='utf-8', bom=b'')
        return self._apply_metadata(raw.decode('utf-8')).encode(self._encoding)

    def save(self):
        Path(self.filepath).write_bytes(self.render_bytes())


@dataclass
class _PristineBaseline:
    nodes_id: int
    nodes_len: int
    node_identities: tuple
    raw_bytes: bytes
    source_values: tuple
    synced_values: tuple
    source_data: dict
    metadata: dict
    metadata_baseline: bytes
    metadata_committed: dict
    annotations_full: Any
    annotations_outside: Any
    dict_keys: frozenset
    behavior: str
    filepath: str
    settings: dict



def _capture_pristine_baseline(fom):
    nodes = getattr(fom, 'nodes', None)
    if not isinstance(nodes, list):
        return None
    raw_bytes = getattr(fom, '_raw_bytes', None)
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) == 0:
        return None
    return _PristineBaseline(
        nodes_id=id(nodes),
        nodes_len=len(nodes),
        node_identities=tuple(id(n) for n in nodes),
        raw_bytes=raw_bytes,
        source_values=getattr(fom, '_source_values', ()),
        synced_values=getattr(fom, '_synced_values', ()),
        source_data=getattr(fom, '_source_data', {}),
        metadata=dict(getattr(fom, '_metadata', {})),
        metadata_baseline=getattr(fom, '_metadata_baseline', b''),
        metadata_committed=dict(getattr(fom, '_metadata_committed', {})),
        annotations_full=getattr(fom, '_annotations_full', None),
        annotations_outside=getattr(fom, '_annotations_outside', None),
        dict_keys=frozenset(fom.__dict__.keys()),
        behavior=getattr(fom, 'behavior', None),
        filepath=fom.filepath,
        settings=dict(getattr(fom, 'settings', {})),
    )



def _matches_pristine_yaml_state(fom, baseline, removal_definition, settings_are_immutable):
    """Compare native state; execution eligibility remains with the caller."""
    if fom.filepath != baseline.filepath:
        return False
    if getattr(fom, 'behavior', None) != baseline.behavior or fom.behavior not in {'classical', 'domain', 'ipcidr'}:
        return False
    model_settings = getattr(fom, 'settings', {})
    if model_settings != baseline.settings or not settings_are_immutable(model_settings):
        return False
    nodes = getattr(fom, 'nodes', None)
    if id(nodes) != baseline.nodes_id or len(nodes) != baseline.nodes_len:
        return False
    if tuple(id(n) for n in nodes) != baseline.node_identities:
        return False
    for n, orig_render in zip(nodes, baseline.source_values):
        if n.render() != orig_render:
            return False
        if isinstance(n, MihomoRuleNode):
            if (n.type, n.value, n.policy, n.options) != n._original_fields:
                return False
            if getattr(n, 'needs_validation', False):
                return False
            if n.type.upper() in {'IP-ASN', 'ASN'}:
                match_val = (removal_definition or {}).get('match', {}).get('value')
                if match_val is None or str(n.value) == str(match_val):
                    return False
    if getattr(fom, '_raw_bytes', None) != baseline.raw_bytes:
        return False
    if getattr(fom, '_source_values', None) != baseline.source_values:
        return False
    if getattr(fom, '_synced_values', None) != baseline.synced_values:
        return False
    source_data = getattr(fom, '_source_data', None)
    if source_data != baseline.source_data:
        return False
    if hasattr(fom, 'data'):
        if not yaml_values_equal(_semantic_snapshot(fom.data), baseline.source_data):
            return False
    if getattr(fom, '_metadata', {}) != baseline.metadata or baseline.metadata != {}:
        return False
    if getattr(fom, '_metadata_baseline', b'') != baseline.metadata_baseline:
        return False
    if getattr(fom, '_metadata_committed', {}) != baseline.metadata_committed:
        return False
    if hasattr(fom, 'data'):
        if _yaml_annotations(fom.data) != baseline.annotations_full:
            return False
        if hasattr(fom, '_sequence_key') and _yaml_annotations(fom.data, fom._sequence_key) != baseline.annotations_outside:
            return False
    if frozenset(fom.__dict__.keys()) != baseline.dict_keys:
        return False
    if any(m in fom.__dict__ for m in ('remove_rule', 'validate', 'validate_complete', 'render_bytes', 'save_to', 'save', 'update_metadata', '_sync_managed_state', '_commit_nodes')):
        return False
    return True

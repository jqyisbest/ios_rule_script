"""Stash override maintenance with source-span YAML preservation."""

from rule_framework.logical_refs import is_parenthesized_payload, select_logical_references, LOGICAL_TYPES

from collections import Counter
from copy import deepcopy
from difflib import SequenceMatcher
import base64
import json
import ipaddress
import logging
import math
from pathlib import Path
import re
from urllib.parse import urlsplit

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.nodes import MappingNode, ScalarNode, SequenceNode
from ruamel.yaml.events import AliasEvent, MappingStartEvent, MappingEndEvent, ScalarEvent, SequenceStartEvent

from rule_framework.domain_refs import canonical_domain, url_host_references, ReferenceRecognitionError
from rule_framework.mihomo_formats import _semantic_snapshot, _yaml_annotations, parse_mihomo_entry, mihomo_domain_references, MihomoRuleNode, _scalar, yaml_dump, _comment_indices, _sequence_comment_keys
from rule_framework.rule_helpers import UNSET, select_rule_types, validate_domain_selector, native_rule_type, validate_standard_value, calculate_insert_index, STANDARD_TYPES
from rule_framework.value_semantics import yaml_value_kind as _value_kind, yaml_values_equal as _semantic_equal

logger = logging.getLogger('RuleFramework')
STASH_FIELDS = ('client', 'file_role', '_raw_bytes', '_encoding', '_source_data', '_source_annotations', '_native_entries', '_metadata_stamp', '_metadata_revision', '_native_text')


def _token(value):
    return json.dumps(_semantic_snapshot(value), sort_keys=True, ensure_ascii=False)


def _entry_key(value, path):
    # Match declaration identities so additions cannot inherit another item's comment.
    if path == '$.rules' and isinstance(value, str):
        node = parse_mihomo_entry(value, 'classical', profile=True)
        if isinstance(node, MihomoRuleNode):
            return _token(('rule', *node.identity[:2], tuple(option for option in node.options if option == 'no-resolve')))
    if path in {'$.http.rewrite', '$.http.url-rewrite'}:
        pattern = value.get('match') if isinstance(value, dict) else value.split()[0] if isinstance(value, str) and value.split() else None
        if pattern:
            return _token(('rewrite', pattern, isinstance(value, dict)))
    if path == '$.http.header-rewrite' and isinstance(value, str):
        try:
            return _token(('header', *_header_identity(_header_parts(value))))
        except ValueError:
            pass
    if path == '$.http.body-rewrite' and isinstance(value, str):
        try:
            parsed = _body_jq_parts(value)
            return _token(('body', parsed['match'], parsed['action']))
        except ValueError:
            pass
    if path == '$.http.mock' and isinstance(value, dict):
        return _token(('mock', value.get('match')))
    if path == '$.http.script' and isinstance(value, dict):
        return _token(('script', value.get('name'), value.get('match'), value.get('type')))
    return _token(value)


def _line_start(raw, index):
    return max(raw.rfind('\n', 0, index), raw.rfind('\r', 0, index)) + 1


def _line_end(raw, index):
    match = re.search(r'\r\n|\n|\r', raw[index:])
    return index + match.end() if match else len(raw)


def _content_end(node):
    if isinstance(node, MappingNode):
        return max((max(_content_end(key), _content_end(value)) for key, value in node.value), default=node.end_mark.index)
    if isinstance(node, SequenceNode) and not node.flow_style:
        return max((_content_end(value) for value in node.value), default=node.end_mark.index)
    return node.end_mark.index


def _yaml_scalar(value, style=None):
    if isinstance(value, str):
        return _scalar(value, style)
    if value is None:
        return 'null'
    if _value_kind(value) is bool:
        return 'true' if value else 'false'
    if isinstance(value, (int, float)) and math.isfinite(value):
        return str(value)
    raise ValueError('Changed Stash YAML scalar has an unsupported value')


def _newline(raw):
    return next((match[0] for match in re.finditer(r'\r\n|\n|\r', raw)), '\n')


def _metadata_comment_records(parser, raw):
    """Locate actual comments around initial scalar file metadata fields."""
    fields = {'name', 'desc', 'author', 'homepage', 'openUrl', 'icon', 'category', 'date', 'version'}
    boundary, scalar_spans = len(raw), []
    scalar_anchors = {}
    root, key = False, None
    events = parser.parse(raw)
    try:
        for event in events:
            if not root:
                if isinstance(event, MappingStartEvent):
                    root = True
                elif isinstance(event, (ScalarEvent, SequenceStartEvent, AliasEvent)):
                    boundary = _line_start(raw, event.start_mark.index)
                    break
                continue
            if key is None:
                if isinstance(event, MappingEndEvent):
                    break
                name = event.value if isinstance(event, ScalarEvent) else (
                    scalar_anchors.get(event.anchor) if isinstance(event, AliasEvent) else None)
                if name not in fields:
                    boundary = _line_start(raw, event.start_mark.index)
                    break
                key = event
            elif isinstance(event, ScalarEvent) or (isinstance(event, AliasEvent) and event.anchor in scalar_anchors):
                scalar_spans.append((event.start_mark.index, event.end_mark.index))
                if isinstance(event, ScalarEvent) and event.anchor:
                    scalar_anchors[event.anchor] = event.value
                key = None
            else:
                boundary = _line_start(raw, key.start_mark.index)
                break
    finally:
        events.close()
    records, comments, offset = raw.splitlines(keepends=True), [], 0
    for index, record in enumerate(records):
        if offset >= boundary:
            break
        start = offset + len(record) - len(record.lstrip(' \t'))
        if record.lstrip(' \t').startswith('#') and not any(first <= start < last for first, last in scalar_spans):
            comments.append(index)
        offset += len(record)
    return records, comments


def _new_block(value, column, newline):
    parser = YAML()
    parser.preserve_quotes = True
    parser.indent(mapping=2, sequence=4, offset=2)
    parser.width = 4096
    rendered = yaml_dump(parser, _semantic_snapshot(value))
    if rendered.endswith('...\n'):
        rendered = rendered[:-4]
    return ''.join(' ' * column + line + newline for line in rendered.splitlines())


def _new_entries(items, column, newline):
    rendered = _new_block(items, 0, newline)
    return ''.join(' ' * column + line[2:] + newline for line in rendered.splitlines())


def _yaml_inline(value):
    if isinstance(value, dict):
        return '{' + ', '.join(_yaml_scalar(key) + ': ' + _yaml_inline(item) for key, item in value.items()) + '}'
    if isinstance(value, list):
        return '[' + ', '.join(_yaml_inline(item) for item in value) + ']'
    if isinstance(value, str):
        return _scalar(value, "'")
    return _yaml_scalar(value)


def _routing_comment_keys(raw, node, current, old_keys, new_keys):
    _sequence_comment_keys(raw, ((value.end_mark.index, _line_end(raw, _content_end(value)))
                                for value in node.value), current, old_keys, new_keys)


def _routing_update_positions(raw, node, original, current, old_keys, new_keys):
    if len(original) != len(current) or Counter(old_keys) == Counter(new_keys):
        return False
    old_rules = [parse_mihomo_entry(value, 'classical', profile=True) for value in original]
    new_rules = [parse_mihomo_entry(value, 'classical', profile=True) for value in current]
    if not all(isinstance(old, MihomoRuleNode) and isinstance(new, MihomoRuleNode)
               and old.identity[:2] == new.identity[:2] for old, new in zip(old_rules, new_rules)):
        return False
    # Every surviving identity and unchanged value must fit its original rows.
    # A remove/add operation can retain the length while moving those rows.
    for before, after in ((old_keys, new_keys), (original, current)):
        shared = Counter(before) & Counter(after)
        stationary = Counter(old for old, new in zip(before, after) if old == new)
        if shared - stationary:
            return False
    for index, parts in getattr(getattr(current, 'ca', None), 'items', {}).items():
        start = _line_start(raw, node.value[index].start_mark.index)
        end = _line_end(raw, _content_end(node.value[index]))
        if any(position is None or not start <= position < end for position in _comment_indices(parts)):
            return False
    return True


def _yaml_patches(raw, node, original, current, path):
    """Change source spans only where managed values changed."""
    if _semantic_equal(original, _semantic_snapshot(current)):
        return []
    segment = raw[node.start_mark.index:node.end_mark.index]
    if segment.lstrip().startswith(('&', '!', '*')):
        raise ValueError(f'Cannot reliably modify anchored/tagged YAML at {path}')
    if isinstance(node, ScalarNode) and (current is None or isinstance(current, (str, bool, int, float))):
        if node.start_mark.line != node.end_mark.line:
            raise ValueError(f'Cannot reliably modify multiline scalar at {path}')
        return [(node.start_mark.index, node.end_mark.index, _yaml_scalar(current, node.style))]
    if isinstance(node, MappingNode) and isinstance(original, dict) and isinstance(current, dict):
        added = {key: value for key, value in current.items() if key not in original}
        removed = set(original) - set(current)
        if node.flow_style and (added or removed):
            if '#' in segment:
                raise ValueError(f'Cannot reliably preserve flow mapping comments at {path}')
            return [(node.start_mark.index, node.end_mark.index, _yaml_inline(current))]
        patches = []
        if added:
            boundary = _line_end(raw, _content_end(node))
            separator = '' if raw[:boundary].endswith(('\n', '\r')) else _newline(raw)
            patches.append((boundary, boundary, separator + _new_block(added, node.start_mark.column, _newline(raw))))
        for key, value in node.value:
            if key.value not in current:
                line_start = _line_start(raw, key.start_mark.index)
                if not re.fullmatch(r'[ \t]*', raw[line_start:key.start_mark.index]):
                    raise ValueError(f'Cannot reliably remove the first field of a sequence mapping at {path}')
                patches.append((line_start, _line_end(raw, _content_end(value)), ''))
            else:
                patches.extend(_yaml_patches(raw, value, original[key.value], current[key.value], path + '.' + key.value))
        return patches
    if isinstance(node, SequenceNode) and isinstance(original, list) and isinstance(current, list):
        old_keys = [_entry_key(value, path) for value in original]
        new_keys = [_entry_key(value, path) for value in current]
        if path == '$.rules':
            _routing_comment_keys(raw, node, current, old_keys, new_keys)
        operations = SequenceMatcher(a=old_keys, b=new_keys, autojunk=False).get_opcodes()
        if path == '$.rules' and _routing_update_positions(raw, node, original, current, old_keys, new_keys):
            # Option changes can merge identities while retaining source rows.
            operations = [('equal', 0, len(original), 0, len(current))]
        if node.flow_style:
            if '#' in segment:
                raise ValueError(f'Cannot reliably preserve flow sequence comments at {path}')
            if not original and current and any(isinstance(item, dict) for item in current):
                start = node.start_mark.index - (raw[node.start_mark.index - 1:node.start_mark.index] == ' ')
                line_start = _line_start(raw, start)
                column = len(raw[line_start:]) - len(raw[line_start:].lstrip(' ')) + 2
                boundary = _line_end(raw, node.end_mark.index)
                separator = '' if raw[:boundary].endswith(('\n', '\r')) else _newline(raw)
                return [(start, node.end_mark.index, ''),
                        (boundary, boundary, separator + _new_entries(current, column, _newline(raw)))]
            values = []
            for operation, first, last, new_first, new_last in operations:
                if operation == 'equal':
                    for old_index, new_index in zip(range(first, last), range(new_first, new_last)):
                        value = node.value[old_index]
                        if _semantic_equal(original[old_index], _semantic_snapshot(current[new_index])):
                            values.append(raw[value.start_mark.index:value.end_mark.index])
                        elif isinstance(value, ScalarNode):
                            values.append(_yaml_scalar(current[new_index], value.style))
                        else:
                            values.append(_yaml_inline(current[new_index]))
                else:
                    values.extend(_yaml_inline(value) for value in current[new_first:new_last])
            return [(node.start_mark.index, node.end_mark.index, '[' + ', '.join(values) + ']')]
        records = []
        for value in node.value:
            start = value.start_mark.index
            line_start = _line_start(raw, start)
            prefix = raw[line_start:start]
            if not re.fullmatch(r'[ \t]*-[ \t]+', prefix):
                raise ValueError(f'Cannot reliably edit complex YAML sequence at {path}')
            records.append((line_start, _line_end(raw, _content_end(value)), prefix))
        patches = []
        for operation, first, last, new_first, new_last in operations:
            if operation == 'equal':
                for offset in range(last - first):
                    patches.extend(_yaml_patches(raw, node.value[first + offset], original[first + offset],
                                                  current[new_first + offset], f'{path}[{first + offset}]'))
                continue
            shared = min(last - first, new_last - new_first)
            for offset in range(shared):
                patches.extend(_yaml_patches(raw, node.value[first + offset], original[first + offset],
                                              current[new_first + offset], f'{path}[{first + offset}]'))
            for index in range(first + shared, last):
                value = node.value[index]
                if raw[value.start_mark.index:value.end_mark.index].lstrip().startswith(('&', '!', '*')):
                    raise ValueError(f'Cannot reliably remove anchored/tagged YAML at {path}[{index}]')
                patches.append((records[index][0], records[index][1], ''))
            if new_last - new_first > shared:
                boundary = records[last][0] if last < len(records) else records[-1][1]
                additions = _new_entries(current[new_first + shared:new_last], records[0][2].index('-'), _newline(raw))
                separator = '' if raw[:boundary].endswith(('\n', '\r')) else _newline(raw)
                patches.append((boundary, boundary, separator + additions))
        if not current:
            # Keep the key and its executable comments when its sequence empties.
            prior_end = records[0][0]
            prior_start = _line_start(raw, prior_end - 1)
            while prior_start >= 0:
                prior = raw[prior_start:prior_end]
                match = re.match(r'[ \t]*[^#\r\n][^\r\n]*?:', prior)
                if match:
                    colon = prior_start + match.end()
                    patches.append((colon, colon, ' []'))
                    break
                if prior_start == 0:
                    raise ValueError(f'Cannot recognize sequence key at {path}')
                prior_end, prior_start = prior_start, _line_start(raw, prior_start - 1)
        return patches
    raise ValueError(f'Cannot reliably preserve required YAML change at {path}')


def stash_conditions(conditions):
    if not isinstance(conditions, dict) or set(conditions) - {'no_resolve'}:
        raise ValueError('Stash routing conditions require no_resolve boolean')
    if any(_value_kind(value) is not bool for value in conditions.values()):
        raise ValueError('Stash routing conditions must be booleans')
    return ('no-resolve',) if conditions.get('no_resolve') else ()


def stash_options(options, rule_type):
    if not isinstance(options, (list, tuple)) or any(not isinstance(option, str) for option in options):
        raise ValueError('Stash options must be a list; [] clears options')
    if len(set(options)) != len(options) or set(options) - {'no-resolve', 'no-track'}:
        raise ValueError('Unrecognized or duplicated Stash routing options')
    if 'no-resolve' in options and rule_type not in {'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP'}:
        raise ValueError('Stash no-resolve requires an IP routing rule')
    return tuple(options)


def validate_stash_rule(node):
    if not isinstance(node, MihomoRuleNode):
        raise ValueError('Cannot recognize required Stash routing rule')
    if not isinstance(node.policy, str) or not node.policy.strip() or re.search(r'[,\r\n\0]', node.policy):
        raise ValueError('Stash routing rules require a non-empty policy result')
    if node.type.upper() == 'MATCH':
        if node.options:
            raise ValueError('Stash MATCH forbids extra routing options')
        return
    if node.type.upper() == 'DOMAIN-REGEX':
        if not isinstance(node.value, str) or not node.value.strip() or re.search(r'[\r\n\0]', node.value):
            raise ValueError('Stash DOMAIN-REGEX requires a non-empty regex')
    else:
        validate_standard_value(node.type.upper(), node.value)
    if node.type.upper() in {'IP-CIDR', 'IP-CIDR6'} and '/' not in node.value:
        raise ValueError('Stash IP rules require an explicit CIDR prefix')
    stash_options(node.options, node.type.upper())


URL_MODES = {'reject', 'reject-200', 'reject-img', 'reject-dict', 'reject-array', '302', '307', 'transparent'}


def _one_line(value, name):
    if not isinstance(value, str) or not value.strip() or re.search(r'[\r\n\0]', value):
        raise ValueError(f'Stash {name} must be a non-empty single-line string')
    return value


def _rewrite_parts(item):
    if isinstance(item, dict):
        pattern = _one_line(item.get('match'), 'rewrite match')
        mode = str(item.get('name', ''))
        if mode not in URL_MODES:
            raise ValueError('Cannot recognize required legacy dictionary rewrite result')
        target = item.get('url', '-')
        return pattern, target, mode
    _one_line(item, 'rewrite')
    match = re.fullmatch(r'(\S+)(\s+)(\S+)(\s+)(\S+)(\s*)', item)
    if not match or match[5] not in URL_MODES:
        raise ValueError('Cannot recognize required Stash URL rewrite syntax')
    return match[1], match[3], match[5]


def _rewrite_result(target, mode, reject_type, redirect_url, status_code):
    if reject_type is not UNSET and reject_type not in URL_MODES:
        raise ValueError('Invalid Stash reject/redirect type')
    if redirect_url is not UNSET:
        _one_line(redirect_url, 'redirect URL')
        if re.search(r'\s', redirect_url):
            raise ValueError('Stash redirect target must be one URL/reference token')
    if status_code is not UNSET and (isinstance(status_code, bool) or not isinstance(status_code, int) or status_code not in {302, 307}):
        raise ValueError('Stash URL rewrite status_code must be 302 or 307')
    if reject_type is not UNSET:
        mode = reject_type
        if mode.startswith('reject'):
            if redirect_url is not UNSET or status_code is not UNSET:
                raise ValueError('Stash rejection and redirection results conflict')
            target = '-'
    if redirect_url is not UNSET:
        target = redirect_url
        if mode not in {'302', '307', 'transparent'}:
            mode = '302'
    if status_code is not UNSET:
        mode = str(status_code)
    if mode.startswith('reject') and target != '-':
        raise ValueError('Stash rejection result requires the dash target')
    if mode in {'302', '307', 'transparent'} and (not isinstance(target, str) or not target.strip() or target == '-'):
        raise ValueError('Stash redirection requires a target URL/reference')
    return target, mode


def _render_rewrite(item, target, mode):
    if isinstance(item, dict):
        item['name'] = mode
        if mode.startswith('reject'):
            item.pop('url', None)
        else:
            item['url'] = target
        return item
    match = re.fullmatch(r'(\S+)(\s+)(\S+)(\s+)(\S+)(\s*)', item)
    return match[1] + match[2] + target + match[4] + mode + match[6]


SCRIPT_FIELDS = {'name', 'match', 'type', 'require-body', 'binary-mode', 'timeout', 'argument', 'max-size', 'engine'}


def validate_script_fields(item, *, require_identity=True):
    if not isinstance(item, dict):
        raise ValueError('Stash HTTP script declarations must be mappings')
    if require_identity:
        _one_line(item.get('name'), 'script provider name')
        _one_line(item.get('match'), 'script URL match')
        if 'script' not in item and item.get('type') not in {'request', 'response'}:
            raise ValueError('Stash script type must be request or response')
    for key, value in item.items():
        if key in {'name', 'match', 'script'}:
            _one_line(value, 'script ' + key)
        elif key == 'type' and value not in {'request', 'response'}:
            raise ValueError('Stash script type must be request or response')
        elif key in {'require-body', 'binary-mode', 'requires-body'} and _value_kind(value) is not bool:
            raise ValueError(f'Stash script {key} must be boolean')
        elif key == 'timeout' and (_value_kind(value) is bool or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0):
            raise ValueError('Stash script timeout must be a finite positive number of seconds')
        elif key == 'max-size' and (_value_kind(value) is bool or not isinstance(value, int) or value < 0):
            raise ValueError('Stash script max-size must be a non-negative integer')
        elif key == 'argument' and not isinstance(value, str):
            raise ValueError('Stash script argument must be a string; empty string explicitly clears it')
        elif key == 'engine' and value not in {'auto', 'webkit', 'jsc'}:
            raise ValueError('Stash script engine must be auto, webkit or jsc')


def _mitm_item(host):
    _one_line(host, 'MITM host')
    if ':' in host:
        try:
            address = ipaddress.IPv6Address(host)
        except ValueError:
            pass
        else:
            return '[' + address.compressed + ']'
    match = re.fullmatch(r'([\w*?-]+(?:\.[\w*?-]+)*\.?)(?::([0-9]+|\*))?', host, re.UNICODE)
    if not match:
        raise ValueError('Stash MITM host requires a domain/wildcard with an optional literal/wildcard port')
    if match[2] is not None and match[2] != '*' and not 1 <= int(match[2]) <= 65535:
        raise ValueError('Stash MITM port outside range 1..65535')
    return canonical_domain(match[1]) + (':' + match[2] if match[2] is not None else '')


def _mitm_items(hostnames):
    if isinstance(hostnames, str):
        hostnames = [hostnames]
    if not isinstance(hostnames, (list, tuple)) or not hostnames:
        raise ValueError('Stash MITM operation requires a non-empty hostname list')
    return [(host, _mitm_item(host)) for host in hostnames]


def _changed_entries(original, current, path):
    if _semantic_equal(original, _semantic_snapshot(current)):
        return
    if not isinstance(original, list) or not isinstance(current, list):
        raise ValueError(f'Stash {path} must be a sequence for the required modification')
    operations = SequenceMatcher(a=[_entry_key(value, path) for value in original],
                                 b=[_entry_key(value, path) for value in current], autojunk=False).get_opcodes()
    for operation, first, last, new_first, new_last in operations:
        for offset, new_index in enumerate(range(new_first, new_last)):
            previous = original[first + offset] if first + offset < last else None
            if not _semantic_equal(previous, _semantic_snapshot(current[new_index])):
                yield previous, current[new_index]


HEADER_ACTIONS = {stage + '-' + operation for stage in ('request', 'response')
                  for operation in ('add', 'del', 'replace', 'replace-regex')}


def _header_parts(content):
    _one_line(content, 'header rewrite')
    match = re.fullmatch(r'(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?', content)
    if not match or match[2] not in HEADER_ACTIONS:
        raise ValueError('Cannot recognize required Stash header rewrite')
    result = {'match': match[1], 'action': match[2], 'header': match[3]}
    if match[2].endswith('-replace-regex'):
        parts = (match[4] or '').split(None, 1)
        if len(parts) != 2:
            raise ValueError('Stash header regex rewrite requires regex and replacement')
        result.update(regex=parts[0], replacement=parts[1])
    elif not match[2].endswith('-del'):
        if not match[4]:
            raise ValueError('Stash header rewrite requires a result value')
        result['value'] = match[4]
    elif match[4]:
        raise ValueError('Stash header deletion forbids a result value')
    return result


def _header_identity(item):
    return item['match'], item['action'], item['header'].lower(), item.get('regex')


def _header_fields(item, *, complete=False):
    if not isinstance(item, dict) or set(item) - {'match', 'action', 'header', 'regex', 'replacement', 'value'}:
        raise ValueError('Stash header declaration has unsupported structured fields')
    _one_line(item.get('match'), 'header match')
    if item.get('action') not in HEADER_ACTIONS:
        raise ValueError('Invalid Stash header action/stage')
    if not isinstance(item.get('header'), str) or not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9a-zA-Z]+", item['header']):
        raise ValueError('Stash header name must be one HTTP field-name token')
    action = item['action']
    if action.endswith('-replace-regex'):
        _one_line(item.get('regex'), 'header regex condition')
        if re.search(r'\s', item['regex']):
            raise ValueError('Stash header regex condition must be one token')
        if 'value' in item:
            raise ValueError('Stash header regex uses replacement as its result')
        if 'replacement' in item or complete:
            _one_line(item.get('replacement'), 'header replacement')
    elif action.endswith('-del'):
        if set(item) & {'value', 'regex', 'replacement'}:
            raise ValueError('Stash header deletion has no replacement fields')
    else:
        if set(item) & {'regex', 'replacement'}:
            raise ValueError('Stash header add/replace uses value as its result')
        if 'value' in item or complete:
            _one_line(item.get('value'), 'header value')


def _replace_tail(content, count, result):
    tokens = list(re.finditer(r'\S+', content))
    boundary = tokens[count - 1].end()
    gap = re.match(r'\s*', content[boundary:])[0] or ' '
    return content[:boundary] + gap + result


def _body_jq_parts(content):
    _one_line(content, 'body rewrite')
    match = re.fullmatch(r'(\S+)\s+((?:request|response)-jq)\s+(.+)', content)
    if not match:
        raise ValueError('Structured Stash body generation currently supports request/response jq declarations')
    return {'match': match[1], 'action': match[2], 'expression': match[3]}


def _body_jq_fields(item, *, complete=False):
    if not isinstance(item, dict) or set(item) - {'match', 'action', 'expression'}:
        raise ValueError('Stash jq body declaration has unsupported structured fields')
    _one_line(item.get('match'), 'body match')
    if item.get('action') not in {'request-jq', 'response-jq'}:
        raise ValueError('Structured Stash body generation supports request-jq or response-jq')
    if 'expression' in item or complete:
        _one_line(item.get('expression'), 'jq expression')


def _headers(value, name):
    if not isinstance(value, dict) or any(not isinstance(key, str) or not key.strip() for key in value):
        raise ValueError(f'Stash {name} headers must be a mapping of header names')
    for item in value.values():
        if not isinstance(item, str) and not (isinstance(item, list) and item and all(isinstance(part, str) for part in item)):
            raise ValueError(f'Stash {name} header values must be strings or non-empty string lists')


def _mock_fields(item):
    if not isinstance(item, dict) or set(item) - {'match', 'text', 'base64', 'status-code', 'headers'}:
        raise ValueError('Stash mock declaration has unsupported structured fields')
    _one_line(item.get('match'), 'mock match')
    if 'text' in item and 'base64' in item:
        raise ValueError('Stash mock text and base64 are independent content choices')
    if 'text' in item and not isinstance(item['text'], str):
        raise ValueError('Stash mock text must be a string; empty string clears the body')
    if 'base64' in item:
        if not isinstance(item['base64'], str):
            raise ValueError('Stash mock base64 must be a string')
        try:
            base64.b64decode(item['base64'], validate=True)
        except Exception as error:
            raise ValueError('Invalid Stash mock base64 payload') from error
    if 'status-code' in item:
        status = item['status-code']
        if _value_kind(status) is bool or not isinstance(status, int) or not 100 <= status <= 599:
            raise ValueError('Stash mock status-code must be an integer in 100..599')
    if 'headers' in item:
        _headers(item['headers'], 'mock')


def _provider_fields(item, *, complete=False):
    if not isinstance(item, dict) or set(item) - {'url', 'interval', 'path', 'payload', 'headers'}:
        raise ValueError('Stash script provider has unsupported structured fields')
    if 'url' in item:
        parsed = urlsplit(_one_line(item['url'], 'provider URL'))
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
            raise ValueError('Stash script provider URL requires an explicit HTTP(S) authority')
    if 'path' in item:
        location = _one_line(item['path'], 'provider path').replace('\\', '/')
        if location.startswith('/') or ':' in location or '..' in location.split('/'):
            raise ValueError('Stash provider path must stay inside the configuration directory')
    if 'payload' in item and not isinstance(item['payload'], str):
        raise ValueError('Stash provider payload must be a script source string')
    if 'interval' in item and (_value_kind(item['interval']) is bool or not isinstance(item['interval'], (int, float))
                             or not math.isfinite(item['interval']) or item['interval'] <= 0):
        raise ValueError('Stash provider interval must be a finite positive number')
    if 'headers' in item:
        _headers(item['headers'], 'script-provider')
    if complete and not set(item) & {'url', 'path', 'payload'}:
        raise ValueError('Stash script provider requires url, path or payload')


STASH_SOURCE_RULE_TYPES = STANDARD_TYPES | {'DOMAIN-REGEX', 'MATCH', 'NETWORK', 'PROTOCOL', 'DST-PORT',
                                          'RULE-SET', 'GEOSITE', 'PROCESS-PATH', 'SCRIPT', 'AND', 'OR', 'NOT'}


def stash_domain_references(node, value, location):
    if not isinstance(node, MihomoRuleNode):
        if value is None or value.lower() in node.render().lower():
            raise ReferenceRecognitionError(f'Cannot recognize required domain references in {location}')
        return frozenset()
    if node.type.upper() == 'URL-REGEX':
        return url_host_references(node.value).hosts
    if node.type.upper() not in STASH_SOURCE_RULE_TYPES and (
            value is None or is_parenthesized_payload(node.value) or canonical_domain(node.value) == canonical_domain(value)):
        raise ReferenceRecognitionError(f'Cannot recognize required domain reference in unknown Stash rule {node.type!r}')
    return mihomo_domain_references(node, client='Stash')


class StashMixin:
    def __init__(self, filepath):
        self.filepath = filepath
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.width = 4096
        self.data = CommentedMap()
        self.is_dirty = False
        self.client, self.file_role = 'Stash', 'override'
        self._raw_bytes, self._encoding = b'', 'utf-8'
        self._source_data = {}
        self._source_annotations = ()
        self._native_entries = set()
        self._native_text = False
        self._metadata_stamp = self._metadata_revision = None

    def load(self):
        self._load_bytes(Path(self.filepath).read_bytes())

    def _load_bytes(self, raw_bytes):
        self._raw_bytes = raw_bytes
        self._encoding = 'utf-8-sig' if raw_bytes.startswith(b'\xef\xbb\xbf') else 'utf-8'
        self.data = self.yaml.load(raw_bytes.decode(self._encoding))
        if self.data is None:
            self.data = CommentedMap()
        if not isinstance(self.data, dict):
            raise ValueError('Stash overrides require a YAML mapping root')
        self._source_data = _semantic_snapshot(self.data)
        self._source_annotations = _yaml_annotations(self.data)
        self._native_entries = set()
        self._native_text = False
        self._metadata_stamp = self._metadata_revision = None
        self.is_dirty = False

    def scaffold(self, base_name):
        from rule_framework.fom import _get_now
        _one_line(base_name, 'override name')
        settings = getattr(self, 'settings', {})
        from rule_framework.metadata import resolve_signature
        author, repo = resolve_signature(settings)
        header = (f'# NAME: {base_name}\n# AUTHOR: {author}\n'
                  f'# REPO: {repo}\n'
                  f'# UPDATED: {_get_now(self)}\n# TOTAL: 0\n')
        self._load_bytes((header + yaml_dump(self.yaml, {'name': base_name})).encode('utf-8'))
        self.is_dirty = True

    def add_native_rule(self, content, insert=None):
        from rule_framework.native_input import validate_native_entry
        validate_native_entry(self, content, kind='rule')
        _one_line(content, 'native routing input')
        entries = self._sequence(self.data, 'rules', create=True)
        index = self._rule_insert_index(entries, insert)
        parsed = parse_mihomo_entry(content, 'classical', profile=True)
        recognized = isinstance(parsed, MihomoRuleNode) and parsed.type.upper() in STANDARD_TYPES | {'DOMAIN-REGEX', 'MATCH'}
        if recognized:
            validate_stash_rule(parsed)
            matches = [(position, node) for position, entry in enumerate(entries)
                       if isinstance(node := parse_mihomo_entry(entry, 'classical', profile=True), MihomoRuleNode)
                       and node.identity == parsed.identity]
            if matches:
                modified = 0
                for position, node in matches:
                    node.policy = parsed.policy
                    validate_stash_rule(node)
                    rendered = node.render()
                    if rendered != entries[position]:
                        entries[position] = rendered
                        modified += 1
                self.is_dirty |= bool(modified)
                logger.info('Stash rule update matched=%s modified=%s in %s', len(matches), modified, self.filepath)
                return
        if content in entries:
            return
        if not recognized:
            self._native_entries.add(('rules', content))
        entries.insert(index, content)
        self.is_dirty = True

    def modify(self, search, replace, is_regex=False, count=0):
        from rule_framework.fom import _apply_text_replacement
        previous = self.render_bytes().decode(self._encoding)
        updated, _ = _apply_text_replacement(previous, search, replace, is_regex, count)
        if updated == previous:
            return
        candidate = type(self)(self.filepath)
        candidate.settings = deepcopy(getattr(self, 'settings', {}))
        candidate._load_bytes(updated.encode(self._encoding))
        source = candidate._source_data
        candidate._native_text = True
        candidate._source_data = _semantic_snapshot(self.data)
        for entry in candidate.data.get('rules', []):
            if not isinstance(entry, str):
                continue
            node = parse_mihomo_entry(entry, 'classical', profile=True)
            if not isinstance(node, MihomoRuleNode) or node.type.upper() not in STANDARD_TYPES | {'DOMAIN-REGEX', 'MATCH'}:
                candidate._native_entries.add(('rules', entry))
        candidate.validate()
        native_entries = candidate._native_entries.copy()
        rendered = candidate._apply_metadata(updated)
        candidate._source_data = source
        candidate._load_bytes(rendered.encode(self._encoding))
        candidate._native_entries = native_entries
        candidate.is_dirty = True
        self.restore_state(candidate.snapshot_state())
        logger.info('Native input: preservation=explicit-text-edit; syntax-validation=YAML-syntax+known-changed-fields; '
                    'semantic-validation=known-changed-fields; client-validation=not-run in %s', self.filepath)

    def _metadata_counts(self):
        counts = {kind.lower(): 0 for kind in LOGICAL_TYPES | STANDARD_TYPES}
        counts.update(dict.fromkeys(('reject', 'redirect', 'header-rewrite', 'body-rewrite', 'mock',
                                     'script', 'mitm', 'force-http-engine-hosts', 'always-real-ip'), 0))
        rules = self.data.get('rules', [])
        total = len(rules) if isinstance(rules, list) else 0
        if isinstance(rules, list):
            for entry in rules:
                if isinstance(entry, str):
                    kind = entry.split(',', 1)[0].strip().lower()
                    counts[kind] = counts.get(kind, 0) + 1
        http = self.data.get('http', {})
        if isinstance(http, dict):
            for family in ('rewrite', 'url-rewrite', 'header-rewrite', 'body-rewrite', 'mock', 'script', 'mitm', 'force-http-engine'):
                entries = http.get(family, [])
                if not isinstance(entries, list):
                    continue
                total += len(entries)
                if family in {'rewrite', 'url-rewrite'}:
                    for item in entries:
                        try:
                            _, _, mode = _rewrite_parts(item)
                        except ValueError:
                            continue
                        key = 'reject' if mode.startswith('reject') else 'redirect'
                        counts[key] = counts.get(key, 0) + 1
                else:
                    counts['force-http-engine-hosts' if family == 'force-http-engine' else family] = len(entries)
        dns = self.data.get('dns', {})
        if isinstance(dns, dict) and isinstance(dns.get('fake-ip-filter'), list):
            counts['always-real-ip'] = len(dns['fake-ip-filter'])
            total += counts['always-real-ip']
        counts['total'] = total
        return counts

    def _apply_metadata(self, raw):
        if _semantic_equal(_semantic_snapshot(self.data), self._source_data):
            return raw
        original = self._raw_bytes.decode(self._encoding)
        if not re.search(r'(?im)(?:^|(?<=\r))[ \t]*#[ \t]*(?:author|repo|updated|total):', original):
            return raw
        field = re.compile(r'([ \t]*#[ \t]*)([A-Z0-9_-]+)(:[ \t]*)([^\r\n]*)', re.I)
        original_records, original_comments = _metadata_comment_records(self.yaml, original)
        original_fields = [match for index in original_comments
                           if (match := field.fullmatch(original_records[index].rstrip('\r\n')))]
        signatures = [match for match in original_fields if match[2].lower() in {'author', 'repo'}]
        if not any(match[2].lower() in {'author', 'repo', 'updated', 'total'} for match in original_fields):
            return raw
        records, comments = _metadata_comment_records(self.yaml, raw)
        current_fields = [(index, match) for index in comments
                          if (match := field.fullmatch(records[index].rstrip('\r\n')))]
        counts = self._metadata_counts()
        revision = _token(self.data)
        if revision != self._metadata_revision:
            from rule_framework.fom import _get_now
            self._metadata_stamp, self._metadata_revision = _get_now(self), revision
        def update(match):
            key = match[2].lower()
            if key == 'updated':
                value = self._metadata_stamp
            elif key in counts:
                value = str(counts[key])
            else:
                return match[0]
            return match[1] + match[2] + match[3] + value
        for index, match in current_fields:
            ending = records[index][len(records[index].rstrip('\r\n')):]
            records[index] = update(match) + ending
        if signatures:
            settings = getattr(self, 'settings', {})
            from rule_framework.metadata import resolve_signature
            author, repo = resolve_signature(settings)
            newline = _newline(raw)
            sample = signatures[0]
            prefix = sample[1]
            colon = sample[3]
            author_key = 'AUTHOR' if any(m[2].isupper() for m in signatures) else 'author'
            repo_key = 'REPO' if any(m[2].isupper() for m in signatures) else 'repo'
            author_matches = [m for m in signatures if m[2].lower() == 'author']
            repo_matches = [m for m in signatures if m[2].lower() == 'repo']
            need_author = not any(m[4].strip() == author for m in author_matches)
            need_repo = not any(m[4].strip() == repo for m in repo_matches)
            additions = []
            if need_author:
                additions.append(f'{prefix}{author_key}{colon}{author}{newline}')
            if need_repo:
                additions.append(f'{prefix}{repo_key}{colon}{repo}{newline}')
            if not any(match[2].lower() == 'updated' for _, match in current_fields):
                key = 'UPDATED' if sample[2].isupper() else 'updated'
                additions.append(f'{prefix}{key}{colon}{self._metadata_stamp}{newline}')
            if additions:
                first = next(index for index, match in current_fields if match[2].lower() in {'author', 'repo'})
                records[first:first] = additions
        return ''.join(records)

    def _http(self, *, create=False):
        if 'http' not in self.data:
            if not create:
                return {}
            self.data['http'] = CommentedMap()
        if not isinstance(self.data['http'], dict):
            raise ValueError('Stash http must be a mapping')
        return self.data['http']

    def _sequence(self, owner, key, *, create=False):
        if key not in owner:
            if not create:
                return []
            owner[key] = []
        if not isinstance(owner[key], list):
            raise ValueError(f'Stash {key} must be a sequence')
        return owner[key]

    def _rule_insert_index(self, entries, insert):
        index = calculate_insert_index(entries, insert, is_section=True, section_name='rules')
        if insert is None:
            index = next((index for index, item in enumerate(entries)
                          if isinstance(item, str) and item.split(',', 1)[0].strip().upper() == 'MATCH'), len(entries))
        return index

    def add_rule(self, rule_type, value, policy=UNSET, insert=None, *, conditions=UNSET, options=UNSET):
        entries = self._sequence(self.data, 'rules', create=True)
        index = self._rule_insert_index(entries, insert)
        native = native_rule_type(rule_type, value, client='Stash')
        selected = stash_conditions(conditions) if conditions is not UNSET else UNSET
        supplied_options = stash_options(options, native) if options is not UNSET else UNSET
        wanted = MihomoRuleNode(','.join([native, value, 'DIRECT']), 'classical', profile=True)
        prefix = wanted.identity[:2]
        matches = []
        for position, entry in enumerate(entries):
            node = parse_mihomo_entry(entry, 'classical', profile=True)
            if isinstance(node, MihomoRuleNode) and node.identity[:2] == prefix and (
                    selected is UNSET or tuple(option for option in node.options if option == 'no-resolve') == selected):
                matches.append((position, node))
        modified = 0
        for position, node in matches:
            validate_stash_rule(node)
            if policy is not UNSET:
                node.policy = policy
            if supplied_options is not UNSET:
                node.options = supplied_options
            validate_stash_rule(node)
            rendered = node.render()
            if rendered != entries[position]:
                entries[position] = rendered
                modified += 1
        if not matches:
            new_options = supplied_options if supplied_options is not UNSET else (() if selected is UNSET else selected)
            result = 'DIRECT' if policy is UNSET else policy if isinstance(policy, str) else ''
            candidate = MihomoRuleNode(','.join([native, value, result, *new_options]),
                                       'classical', profile=True)
            validate_stash_rule(candidate)
            satisfied = [node for entry in entries
                         if isinstance(node := parse_mihomo_entry(entry, 'classical', profile=True), MihomoRuleNode)
                         and node.identity == candidate.identity and (policy is UNSET or node.policy == candidate.policy)]
            if satisfied:
                for node in satisfied:
                    validate_stash_rule(node)
                logger.info('Stash rule update already satisfied; matched=%s modified=0 in %s', len(satisfied), self.filepath)
                return
            if policy is UNSET:
                raise ValueError('New Stash routing rules require an explicit policy result')
            entries.insert(index, candidate.render())
            modified = 1
        self.is_dirty |= bool(modified)
        logger.info('Stash rule update matched=%s modified=%s in %s', len(matches), modified, self.filepath)

    def remove_rule(self, rule_type, value=None, *, conditions=UNSET):
        selected_types = select_rule_types(rule_type)
        selected_conditions = stash_conditions(conditions) if conditions is not UNSET else UNSET
        exact_domain = rule_type == 'domain'
        if exact_domain and value is not None:
            validate_domain_selector(value)
        entries = self._sequence(self.data, 'rules')
        removed = []
        for index, entry in enumerate(entries):
            node = parse_mihomo_entry(entry, 'classical', profile=True)
            selected = getattr(node, 'type', '').upper() in selected_types
            if exact_domain:
                try:
                    references = stash_domain_references(node, value, f'rules[{index}]')
                except ReferenceRecognitionError as error:
                    raise ValueError(f'Cannot recognize required domain references in rules[{index}]: {error}') from error
                selected = bool(references) and (value is None or canonical_domain(value) in references)
                if node.type.upper() in LOGICAL_TYPES:
                    selected = select_logical_references(references, value, client=self.client,
                        rule_type=node.type, location=f'{self.filepath}:rules[{index}]')
            elif value is not None:
                selected = selected and getattr(node, 'value', None) == value
            if selected and selected_conditions is not UNSET:
                selected = tuple(option for option in node.options if option == 'no-resolve') == selected_conditions
            if selected:
                removed.append(index)
        for index in reversed(removed):
            del entries[index]
        if exact_domain:
            self._remove_domain_http(value)
        self.is_dirty |= bool(removed)
        logger.info('Stash rule removal matched=%s in %s', len(removed), self.filepath)

    def _rewrite_family(self, http, insert, family):
        if family is UNSET and insert and 'section' in insert:
            section = insert['section']
            if section not in {'http.rewrite', 'http.url-rewrite'}:
                raise ValueError(f'Invalid Stash URL rewrite section: {section!r}')
            family = section.removeprefix('http.')
        if family is UNSET:
            family = 'rewrite' if 'rewrite' in http and 'url-rewrite' not in http else 'url-rewrite'
        if family not in {'rewrite', 'url-rewrite'}:
            raise ValueError('Stash URL rewrite family must be rewrite or url-rewrite')
        return family

    def add_rewrite(self, raw_content=None, url_pattern=None, reject_type=UNSET, redirect_url=UNSET,
                    status_code=UNSET, insert=None, *, family=UNSET):
        if raw_content is not None:
            if url_pattern is not None or any(value is not UNSET for value in (reject_type, redirect_url, status_code)):
                raise ValueError('Native Stash rewrite content conflicts with structured fields')
            url_pattern, native_target, native_mode = _rewrite_parts(raw_content)
            if native_mode.startswith('reject'):
                reject_type = native_mode
            else:
                redirect_url = native_target
                if native_mode == 'transparent':
                    reject_type = native_mode
                else:
                    status_code = int(native_mode)
            logger.info('Native input: preservation=verbatim; syntax-validation=URL-fields; '
                        'semantic-validation=outcome-fields; client-validation=not-run in %s', self.filepath)
        _one_line(url_pattern, 'URL pattern')
        http = self._http(create=True)
        selected_family = self._rewrite_family(http, insert, family)
        destination = self._sequence(http, selected_family, create=True)
        index = calculate_insert_index(destination, insert, is_section=True, section_name='http.' + selected_family)
        matches = []
        families = (selected_family,) if family is not UNSET else ('rewrite', 'url-rewrite')
        for key in families:
            entries = self._sequence(http, key)
            for position, item in enumerate(entries):
                pattern = item.get('match') if isinstance(item, dict) else item.split()[0] if isinstance(item, str) and item.split() else None
                if pattern == url_pattern:
                    matches.append((entries, position, item))
        modified = 0
        for entries, position, item in matches:
            _, target, mode = _rewrite_parts(item)
            target, mode = _rewrite_result(target, mode, reject_type, redirect_url, status_code)
            before = _semantic_snapshot(item)
            updated = _render_rewrite(item, target, mode)
            if not _semantic_equal(_semantic_snapshot(updated), before):
                entries[position] = updated
                modified += 1
        if not matches:
            target, mode = _rewrite_result('-', 'reject', reject_type, redirect_url, status_code)
            if raw_content is not None:
                candidate = raw_content
            elif selected_family == 'rewrite' and destination and all(isinstance(item, dict) for item in destination):
                candidate = {'match': url_pattern, 'name': mode}
                if not mode.startswith('reject'):
                    candidate['url'] = target
            else:
                candidate = f'{url_pattern} {target} {mode}'
            destination.insert(index, candidate)
            modified = 1
        self.is_dirty |= bool(modified)
        logger.info('Stash URL rewrite update matched=%s modified=%s in %s', len(matches), modified, self.filepath)

    def remove_rewrite(self, pattern, *, family=UNSET):
        _one_line(pattern, 'rewrite pattern')
        http = self._http()
        if family is not UNSET and family not in {'rewrite', 'url-rewrite'}:
            raise ValueError('Stash URL rewrite family must be rewrite or url-rewrite')
        families = (family,) if family is not UNSET else ('rewrite', 'url-rewrite')
        removed = 0
        for key in families:
            entries = self._sequence(http, key)
            for index in range(len(entries) - 1, -1, -1):
                item = entries[index]
                match = item.get('match') if isinstance(item, dict) else item.split()[0] if isinstance(item, str) and item.split() else None
                if match == pattern:
                    del entries[index]
                    removed += 1
        self.is_dirty |= bool(removed)
        logger.info('Stash URL rewrite removal matched=%s in %s', removed, self.filepath)

    def add_mitm(self, hostnames, insert=None):
        additions = _mitm_items(hostnames)
        entries = self._sequence(self._http(create=True), 'mitm', create=True)
        index = calculate_insert_index(entries, insert, is_section=True, section_name='http.mitm')
        existing = {_mitm_item(host) for host in entries}
        added = 0
        for host, identity in additions:
            if identity not in existing:
                entries.insert(index, host)
                index += 1
                existing.add(identity)
                added += 1
        self.is_dirty |= bool(added)
        logger.info('Stash MITM addition matched=%s modified=%s', len(additions) - added, added)

    def remove_mitm(self, hostnames):
        wanted = {identity for _, identity in _mitm_items(hostnames)}
        entries = self._sequence(self._http(), 'mitm')
        removed = 0
        for index in range(len(entries) - 1, -1, -1):
            if _mitm_item(entries[index]) in wanted:
                del entries[index]
                removed += 1
        self.is_dirty |= bool(removed)
        logger.info('Stash MITM removal matched=%s', removed)

    def _require_script_provider(self, item):
        if 'script' in item:
            return
        providers = self.data.get('script-providers', {})
        if not isinstance(providers, dict) or item.get('name') not in providers:
            raise ValueError(f'Stash script provider {item.get("name")!r} is undeclared in this managed override')
        if not isinstance(providers[item['name']], dict):
            raise ValueError('Stash script provider declaration must be a mapping')

    def add_script(self, raw_content, insert=None):
        validate_script_fields(raw_content)
        item = deepcopy(raw_content)
        self._require_script_provider(item)
        entries = self._sequence(self._http(create=True), 'script', create=True)
        index = calculate_insert_index(entries, insert, is_section=True, section_name='http.script')
        identity = tuple(item.get(key) for key in ('name', 'match', 'type'))
        matches = [entry for entry in entries if isinstance(entry, dict)
                   and tuple(entry.get(key) for key in ('name', 'match', 'type')) == identity
                   and ('max-size' not in item or entry.get('max-size', UNSET) == item['max-size'])]
        modified = 0
        for entry in matches:
            before = _semantic_snapshot(entry)
            entry.update(item)
            if set(item) - SCRIPT_FIELDS - {'script', 'requires-body'}:
                self._native_entries.add(('script-native', _token(entry)))
            modified += not _semantic_equal(_semantic_snapshot(entry), before)
        if not matches:
            entries.insert(index, item)
            if set(item) - SCRIPT_FIELDS - {'script', 'requires-body'}:
                self._native_entries.add(('script-native', _token(item)))
            modified = 1
        self.is_dirty |= bool(modified)
        if set(item) - SCRIPT_FIELDS:
            logger.info('Native input: preservation=explicit-YAML-fields; syntax-validation=known-script-fields; '
                        'semantic-validation=provider-stage-match; client-validation=not-run in %s', self.filepath)
        logger.info('Stash script update matched=%s modified=%s in %s', len(matches), modified, self.filepath)

    def remove_script(self, name=None, pattern=None, script_path=None, *, stage=UNSET, max_size=UNSET):
        if name is None and pattern is None and script_path is None:
            raise ValueError('Stash script removal requires a provider, pattern or script_path selector')
        for key, value in (('name', name), ('pattern', pattern), ('script_path', script_path)):
            if value is not None:
                _one_line(value, 'script selector ' + key)
        if stage is not UNSET and stage not in {'request', 'response'}:
            raise ValueError('Stash script stage must be request or response')
        entries = self._sequence(self._http(), 'script')
        removed = 0
        for index in range(len(entries) - 1, -1, -1):
            item = entries[index]
            if not isinstance(item, dict):
                raise ValueError('Cannot recognize required Stash script removal identity')
            selected = (name is None or item.get('name') == name) and (pattern is None or item.get('match') == pattern)
            selected &= script_path is None or item.get('script') == script_path
            selected &= stage is UNSET or item.get('type') == stage
            selected &= max_size is UNSET or item.get('max-size', UNSET) == max_size
            if selected:
                del entries[index]
                removed += 1
        self.is_dirty |= bool(removed)
        logger.info('Stash script removal matched=%s in %s', removed, self.filepath)

    def add_header_rewrite(self, declaration, insert=None):
        _header_fields(declaration)
        entries = self._sequence(self._http(create=True), 'header-rewrite', create=True)
        index = calculate_insert_index(entries, insert, is_section=True, section_name='http.header-rewrite')
        identity = _header_identity(declaration)
        matches = []
        for position, entry in enumerate(entries):
            try:
                parsed = _header_parts(entry)
            except ValueError:
                if isinstance(entry, str) and entry.split()[:1] == [declaration['match']]:
                    raise
                continue
            if _header_identity(parsed) == identity:
                matches.append((position, entry, parsed))
        modified = 0
        for position, entry, parsed in matches:
            parsed.update(declaration)
            _header_fields(parsed, complete=True)
            if parsed['action'].endswith('-del'):
                rendered = entry
            else:
                regex = parsed['action'].endswith('-replace-regex')
                rendered = _replace_tail(entry, 4 if regex else 3,
                                         parsed['replacement'] if regex else parsed['value'])
            if rendered != entry:
                entries[position] = rendered
                modified += 1
        if not matches:
            _header_fields(declaration, complete=True)
            fields = [declaration['match'], declaration['action'], declaration['header']]
            if declaration['action'].endswith('-replace-regex'):
                fields.extend([declaration['regex'], declaration['replacement']])
            elif not declaration['action'].endswith('-del'):
                fields.append(declaration['value'])
            entries.insert(index, ' '.join(fields))
            modified = 1
        self.is_dirty |= bool(modified)
        logger.info('Stash header rewrite update matched=%s modified=%s', len(matches), modified)

    def add_body_rewrite(self, declaration, insert=None):
        _body_jq_fields(declaration)
        entries = self._sequence(self._http(create=True), 'body-rewrite', create=True)
        index = calculate_insert_index(entries, insert, is_section=True, section_name='http.body-rewrite')
        identity = declaration['match'], declaration['action']
        matches = []
        for position, entry in enumerate(entries):
            try:
                parsed = _body_jq_parts(entry)
            except ValueError:
                continue
            if (parsed['match'], parsed['action']) == identity:
                matches.append((position, entry, parsed))
        modified = 0
        for position, entry, parsed in matches:
            parsed.update(declaration)
            _body_jq_fields(parsed, complete=True)
            rendered = _replace_tail(entry, 2, parsed['expression'])
            if rendered != entry:
                entries[position] = rendered
                modified += 1
        if not matches:
            _body_jq_fields(declaration, complete=True)
            entries.insert(index, declaration['match'] + ' ' + declaration['action'] + ' ' + declaration['expression'])
            modified = 1
        self.is_dirty |= bool(modified)
        logger.info('Stash jq body rewrite update matched=%s modified=%s', len(matches), modified)

    def add_mock(self, declaration, insert=None):
        _mock_fields(declaration)
        entries = self._sequence(self._http(create=True), 'mock', create=True)
        index = calculate_insert_index(entries, insert, is_section=True, section_name='http.mock')
        matches = [item for item in entries if isinstance(item, dict) and item.get('match') == declaration['match']]
        modified = 0
        for item in matches:
            before = _semantic_snapshot(item)
            if 'text' in declaration:
                item.pop('base64', None)
            if 'base64' in declaration:
                item.pop('text', None)
            item.update(deepcopy(declaration))
            modified += not _semantic_equal(_semantic_snapshot(item), before)
        if not matches:
            entries.insert(index, deepcopy(declaration))
            modified = 1
        self.is_dirty |= bool(modified)
        logger.info('Stash mock update matched=%s modified=%s', len(matches), modified)

    def add_script_provider(self, name, fields):
        _one_line(name, 'script provider name')
        _provider_fields(fields)
        providers = self.data.setdefault('script-providers', CommentedMap())
        if not isinstance(providers, dict):
            raise ValueError('Stash script-providers must be a mapping')
        current = providers.get(name, {})
        if not isinstance(current, dict):
            raise ValueError('Stash script provider entry must be a mapping')
        candidate = dict(current, **deepcopy(fields))
        # Keep unknown original provider fields while checking known source/result fields.
        _provider_fields({key: value for key, value in candidate.items() if key in {'url', 'interval', 'path', 'payload', 'headers'}}, complete=True)
        if not _semantic_equal(_semantic_snapshot(current), _semantic_snapshot(candidate)) or name not in providers:
            if name in providers:
                current.update(deepcopy(fields))
            else:
                providers[name] = candidate
            self.is_dirty = True
        logger.info('Stash script provider update name=%s', name)

    def _remove_domain_http(self, value):
        http = self._http()
        for family in ('rewrite', 'url-rewrite', 'header-rewrite', 'body-rewrite', 'mock', 'script'):
            entries = self._sequence(http, family)
            removed = []
            for index, item in enumerate(entries):
                if family == 'body-rewrite' and isinstance(item, str):
                    from rule_framework.native_input import declaration_scope
                    if declaration_scope(self, item, 'http.body-rewrite')[1] == 'unknown':
                        raise ValueError(f'Cannot recognize required Stash domain reference in opaque native http.body-rewrite[{index}]')
                if isinstance(item, dict):
                    if family == 'script':
                        from rule_framework.native_input import guard_required_script_fields
                        guard_required_script_fields(self, item)
                    pattern = item.get('match')
                elif isinstance(item, str):
                    pattern = item.split()[0] if item.split() else None
                else:
                    pattern = None
                try:
                    references = url_host_references(pattern)
                except ReferenceRecognitionError as error:
                    raise ValueError(f'Cannot recognize required domain references in http.{family}[{index}]: {error}') from error
                if value is None or references.contains(value):
                    removed.append(index)
            for index in reversed(removed):
                del entries[index]
            self.is_dirty |= bool(removed)
            if removed:
                logger.info('Stash domain cleanup http.%s matched=%s', family, len(removed))
        entries = self._sequence(http, 'mitm')
        removed = []
        for index, host in enumerate(entries):
            identity = _mitm_item(host)
            reference = None if identity.startswith('[') else canonical_domain(host.split(':', 1)[0])
            if value is None or reference == canonical_domain(value):
                removed.append(index)
        for index in reversed(removed):
            del entries[index]
        self.is_dirty |= bool(removed)

    def _validate_changes(self):
        current = _semantic_snapshot(self.data)
        original = self._source_data
        if _semantic_equal(current, original):
            return
        known = {'rules', 'http', 'script-providers', 'name', 'desc', 'author', 'homepage', 'openUrl',
                 'icon', 'category', 'date', 'version'}
        if not self._native_text:
            for key in original.keys() | current.keys():
                if key not in known and not _semantic_equal(original.get(key, UNSET), current.get(key, UNSET)):
                    raise ValueError(f'Cannot reliably recognize changed Stash field {key!r}; use explicit native text input')
        if 'rules' in current:
            for _, entry in _changed_entries(original.get('rules', []), self.data['rules'], '$.rules'):
                if ('rules', entry) not in self._native_entries:
                    validate_stash_rule(parse_mihomo_entry(entry, 'classical', profile=True))
        if not _semantic_equal(original.get('http', {}), current.get('http', {})):
            http = self._http()
            source_http = original.get('http', {})
            if not isinstance(source_http, dict):
                raise ValueError('Cannot recognize required source Stash http mapping')
            if not self._native_text:
                known_http = {'rewrite', 'url-rewrite', 'header-rewrite', 'body-rewrite', 'mock', 'script', 'mitm'}
                for key in source_http.keys() | http.keys():
                    if key not in known_http and not _semantic_equal(source_http.get(key, UNSET), _semantic_snapshot(http.get(key, UNSET))):
                        raise ValueError(f'Cannot reliably recognize changed Stash http.{key}; use explicit native text input')
            for family in ('rewrite', 'url-rewrite'):
                for _, entry in _changed_entries(source_http.get(family, []), http.get(family, []), '$.http.' + family):
                    _, target, mode = _rewrite_parts(entry)
                    _rewrite_result(target, mode, UNSET, UNSET, UNSET)
            for previous, entry in _changed_entries(source_http.get('script', []), http.get('script', []), '$.http.script'):
                if not isinstance(entry, dict):
                    raise ValueError('Stash HTTP script declarations must be mappings')
                current_entry = _semantic_snapshot(entry)
                before = previous if isinstance(previous, dict) else {}
                unknown_changed = {key for key in before.keys() | current_entry.keys()
                                   if key not in SCRIPT_FIELDS | {'script', 'requires-body'}
                                   and not _semantic_equal(before.get(key, UNSET), current_entry.get(key, UNSET))}
                if unknown_changed and not self._native_text and ('script-native', _token(entry)) not in self._native_entries:
                    raise ValueError('Cannot reliably recognize changed Stash script fields; use explicit native input')
                changed = {key: value for key, value in entry.items()
                           if key not in before or not _semantic_equal(before[key], current_entry[key])}
                identity = {key: entry[key] for key in ('name', 'match', 'type', 'script') if key in entry}
                validate_script_fields(dict(changed, **identity))
                self._require_script_provider(entry)
            for _, host in _changed_entries(source_http.get('mitm', []), http.get('mitm', []), '$.http.mitm'):
                _mitm_item(host)
            for _, entry in _changed_entries(source_http.get('header-rewrite', []), http.get('header-rewrite', []), '$.http.header-rewrite'):
                _header_fields(_header_parts(entry), complete=True)
            for _, entry in _changed_entries(source_http.get('body-rewrite', []), http.get('body-rewrite', []), '$.http.body-rewrite'):
                parts = entry.split(None, 2) if isinstance(entry, str) else []
                if ('http.body-rewrite', entry) in self._native_entries and len(parts) == 3 and parts[1] not in {'request-jq', 'response-jq'}:
                    _one_line(entry, 'native body rewrite')
                    continue
                if self._native_text and len(parts) == 3 and parts[1] not in {'request-jq', 'response-jq'}:
                    _one_line(entry, 'native body rewrite')
                    logger.info('Native body input: syntax-validation=YAML-scalar+URL-action-expression-boundary; '
                                'semantic-validation=unknown; client-validation=not-run in %s', self.filepath)
                    continue
                _body_jq_fields(_body_jq_parts(entry), complete=True)
            for previous, entry in _changed_entries(source_http.get('mock', []), http.get('mock', []), '$.http.mock'):
                if not isinstance(entry, dict):
                    raise ValueError('Stash mock declarations must be mappings')
                changed = {key: value for key, value in entry.items()
                           if not isinstance(previous, dict) or key not in previous or not _semantic_equal(previous[key], _semantic_snapshot(value))}
                _mock_fields(dict(changed, match=entry.get('match')))
        if not _semantic_equal(original.get('script-providers', {}), current.get('script-providers', {})):
            providers = self.data.get('script-providers', {})
            previous = original.get('script-providers', {})
            if not isinstance(providers, dict) or not isinstance(previous, dict):
                raise ValueError('Stash script-providers must be a mapping')
            for name, item in providers.items():
                if _semantic_equal(previous.get(name, UNSET), _semantic_snapshot(item)):
                    continue
                if not isinstance(item, dict):
                    raise ValueError('Stash script provider must be a mapping')
                before = previous.get(name, {})
                delta = {key: value for key, value in item.items() if key not in before or not _semantic_equal(before[key], _semantic_snapshot(value))}
                _provider_fields(delta)
                _provider_fields({key: value for key, value in item.items()
                                  if key in {'url', 'interval', 'path', 'payload', 'headers'}}, complete=True)
        for key in ('name', 'desc', 'author', 'homepage', 'openUrl', 'icon', 'category', 'date', 'version'):
            if key in current and not _semantic_equal(original.get(key, UNSET), current[key]):
                _one_line(self.data[key], key)

    def validate(self):
        super().validate()
        if not isinstance(self.data, dict):
            raise ValueError('Stash overrides require a YAML mapping root')
        if self.client != 'Stash' or self.file_role != 'override':
            raise ValueError('Invalid managed Stash client/file role')
        self._validate_changes()

    def _validate_annotations(self):
        current = _yaml_annotations(self.data)
        for kind in ('comment', 'anchor', 'tag'):
            original_values = Counter(item[-1] for item in self._source_annotations if item[0] == kind)
            current_values = Counter(item[-1] for item in current if item[0] == kind)
            if current_values - original_values:
                raise ValueError('Changed YAML annotations require an explicit text modification')
            if kind == 'comment' and any('#!replace' in value for value in (original_values - current_values)):
                raise ValueError('Removing executable YAML annotations requires an explicit text modification')

    def render_bytes(self):
        self.validate()
        self._validate_annotations()
        if _semantic_equal(_semantic_snapshot(self.data), self._source_data):
            if _yaml_annotations(self.data) != self._source_annotations:
                raise ValueError('Changed YAML annotations require an explicit text modification')
            return self._raw_bytes
        raw = self._raw_bytes.decode(self._encoding)
        root = self.yaml.compose(raw)
        patches = _yaml_patches(raw, root, self._source_data, self.data, '$')
        for first, last, replacement in sorted(patches, key=lambda patch: (patch[0], patch[1]), reverse=True):
            raw = raw[:first] + replacement + raw[last:]
        parsed = self.yaml.load(raw)
        if not _semantic_equal(_semantic_snapshot(parsed), _semantic_snapshot(self.data)):
            raise ValueError('Rendered Stash YAML differs from current managed state')
        return self._apply_metadata(raw).encode(self._encoding)

    def validate_complete(self):
        self.render_bytes()

    def save(self):
        Path(self.filepath).write_bytes(self.render_bytes())

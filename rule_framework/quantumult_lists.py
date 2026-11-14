"""Client-specific maintenance for Quantumult X routing lists."""

import logging
import re
from pathlib import Path

from rule_framework.ast import RuleNode, CommentNode, BlankNode, ASTNode, parse_line
from rule_framework.domain_refs import canonical_domain
from rule_framework.rule_helpers import (
    native_rule_type, select_rule_types, SEMANTIC_TYPES, UNSET,
    rule_identity, validate_domain_selector, calculate_insert_index, validate_standard_value,
)

logger = logging.getLogger('RuleFramework')


def is_quantumult_path(filepath):
    """Client components or a named asset identify QX, with checkout names excluded."""
    normalized = str(filepath).replace('\\', '/').lower()
    parts = normalized.split('/')
    if any(part in {'quantumultx', 'quantumult-x', 'quantumult x', 'quanx'} for part in parts[:-1]):
        return True
    return bool(re.match(r'^(?:quantumultx|quantumult-x|quanx)(?:[._ -]|$)', parts[-1]))


def quantumult_native_type(rule_type, value):
    try:
        native = native_rule_type(rule_type, value)
    except ValueError as error:
        field = 'value' if rule_type == 'ip' else 'type'
        raise ValueError(f'Invalid Quantumult X rule {field}: {error}') from error
    if native.startswith('DOMAIN'):
        native = native.replace('DOMAIN', 'HOST', 1)
    return 'IP6-CIDR' if native == 'IP-CIDR6' else native


QUANTUMULT_TYPES = {
    'HOST', 'HOST-SUFFIX', 'HOST-WILDCARD', 'HOST-KEYWORD', 'USER-AGENT',
    'IP-CIDR', 'IP6-CIDR', 'IP-ASN', 'GEOIP', 'FINAL',
}


def validate_quantumult_value(rule_type, value):
    if rule_type not in QUANTUMULT_TYPES:
        raise ValueError(f'Unsupported structured Quantumult X rule type: {rule_type}; use explicit native input')
    if rule_type == 'FINAL':
        if value is not None:
            raise ValueError('Quantumult X FINAL rule value must be absent (None)')
        return
    standard_type = rule_type.replace('HOST', 'DOMAIN', 1) if rule_type.startswith('HOST') else rule_type
    if standard_type == 'IP6-CIDR':
        standard_type = 'IP-CIDR6'
    try:
        validate_standard_value(standard_type, value)
        if value != value.strip() or ',' in value:
            raise ValueError('Rule fields require values without surrounding whitespace or commas')
        if rule_type == 'HOST-WILDCARD' and not re.fullmatch(r'[\w.*?-]+', value):
            raise ValueError('Host wildcard values support literal labels with * and ?')
        if rule_type == 'GEOIP' and not re.fullmatch(r'[A-Za-z]{2}', value):
            raise ValueError('GEOIP value must be a two-letter country code')
    except ValueError as error:
        raise ValueError(f'Invalid Quantumult X rule value: {error}') from error


def validate_quantumult_policy(policy):
    if (not isinstance(policy, str) or not policy.strip() or policy != policy.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in policy)
            or ',' in policy or '#' in policy):
        raise ValueError('Quantumult X policy must be a non-empty single-line result without commas or comment markers; omission preserves an existing policy')


def validate_quantumult_conditions(conditions):
    if not isinstance(conditions, dict) or conditions:
        raise ValueError('Quantumult X conditions currently require an empty dictionary; additional matching conditions are unverified')


def validate_quantumult_options(options):
    if not isinstance(options, (tuple, list)) or any(not isinstance(option, str) for option in options):
        raise ValueError('Quantumult X options must be a list of strings; [] clears options')
    for option in options:
        if option not in {'force-cellular', 'multi-interface', 'multi-interface-balance'} and not re.fullmatch(r'via-interface=[A-Za-z][A-Za-z0-9_.-]*', option):
            raise ValueError(f'Unsupported Quantumult X result options: {option!r}; use explicit native input')
    if len(options) > 1:
        raise ValueError('Quantumult X structured options support one interface mode per rule; combinations are unverified')
    return tuple(options)


class QuantumultRuleNode(RuleNode):
    """Matching value, policy and routing result options retain their own fields."""

    def __init__(self, line):
        comment = re.search(r'\s+#', line)
        self.inline_comment = line[comment.start():] if comment else ''
        content = line[:comment.start()] if comment else line
        self.raw_fields = content.split(',')
        fields = [field.strip() for field in self.raw_fields]
        final = fields[0].upper() == 'FINAL'
        super().__init__(fields[0], None if final else fields[1], fields[1] if final else fields[2])
        self.raw_fields = content.split(',')
        self.options = tuple(fields[2:] if final else fields[3:])
        self.original = line
        self._original_line = line
        self._original_fields = (self.type, self.value, self.policy, self.options)

    @property
    def identity(self):
        return rule_identity(self.type, self.value)

    def render(self):
        if (self.type, self.value, self.policy, self.options) == self._original_fields:
            return self.original
        final = self.type.upper() == 'FINAL'
        original_final = self._original_fields[0].upper() == 'FINAL'
        current_fields = (self.type, self.policy) if final else (self.type, self.value, self.policy)
        original_fields = (self._original_fields[0], self._original_fields[2]) if original_final else self._original_fields[:3]
        fields = []
        if final != original_final:
            fields = list(current_fields)
        else:
            for raw, current, original in zip(self.raw_fields, current_fields, original_fields):
                if current == original:
                    fields.append(raw)
                else:
                    leading = raw[:len(raw) - len(raw.lstrip())]
                    trailing = raw[len(raw.rstrip()):]
                    fields.append(leading + current + trailing)
        option_index = 2 if original_final else 3
        tail = ',' + ','.join(self.raw_fields[option_index:]) if len(self.raw_fields) > option_index else ''
        if self.options != self._original_fields[3]:
            tail = ',' + ','.join(self.options) if self.options else ''
        return ','.join(fields) + tail + self.inline_comment


def parse_quantumult_line(line):
    final = line.split(',', 1)[0].strip().upper() == 'FINAL'
    if line.strip() and not line.lstrip().startswith(('#', '//', ';')) and (line.count(',') >= 2 or final and ',' in line):
        return QuantumultRuleNode(line)
    node = CommentNode(line) if line.lstrip().startswith(('#', '//', ';')) else parse_line(line)
    node.original = line
    node._original_line = line
    return node


class QuantumultListMixin:
    def __init__(self, filepath):
        super().__init__(filepath)
        self.file_role = 'rule-set'
        self.client = 'QuantumultX'
        self._raw_bytes = b''
        self._metadata_baseline = b''
        self._encoding = 'utf-8'
        self._newline = '\n'
        self.ends_with_newline = True

    def load(self):
        from rule_framework.text_json import split_physical_records
        self._raw_bytes = Path(self.filepath).read_bytes()
        self._metadata_baseline = self._raw_bytes
        self._encoding = 'utf-8-sig' if self._raw_bytes.startswith(b'\xef\xbb\xbf') else 'utf-8'
        text = self._raw_bytes.decode(self._encoding)
        records = split_physical_records(text)
        self.nodes = []
        for line, ending in records:
            node = parse_quantumult_line(line)
            node.line_ending = ending
            self.nodes.append(node)
        self._newline = next((node.line_ending for node in self.nodes if node.line_ending), '\n')
        self.ends_with_newline = bool(re.search(r'(\r\n|\r|\n)$', text))
        from rule_framework.metadata import mark_list_header
        mark_list_header(self)
        self.is_dirty = False

    def render_bytes(self):
        from rule_framework.text_json import serialize_physical_nodes
        encoding = getattr(self, '_encoding', 'utf-8')
        bom = b'\xef\xbb\xbf' if encoding == 'utf-8-sig' else b''
        return serialize_physical_nodes(self.nodes, newline=getattr(self, '_newline', '\n'),
            ends_with_newline=getattr(self, 'ends_with_newline', True), encoding='utf-8', bom=bom)

    def save(self):
        self.validate()
        self.validate_complete()
        Path(self.filepath).write_bytes(self.render_bytes())

    def validate_complete(self):
        if self.render_bytes() != self._metadata_baseline:
            self.is_dirty = True
            self.update_metadata(only_if_changed=True)
            from rule_framework.metadata import remember_list_baseline
            remember_list_baseline(self)

    def add_rule(self, rule_type, value, policy=UNSET, insert=None, *, conditions=UNSET, options=UNSET):
        if conditions is not UNSET:
            validate_quantumult_conditions(conditions)
        if options is not UNSET:
            options = validate_quantumult_options(options)
        if policy is not UNSET:
            validate_quantumult_policy(policy)
        rule_type = quantumult_native_type(rule_type, value)
        validate_quantumult_value(rule_type, value)
        index = calculate_insert_index(self.nodes, insert)
        identity = rule_identity(rule_type, value)
        matching = [node for node in self.nodes if isinstance(node, RuleNode)
                    and rule_identity(node.type, node.value) == identity]
        if matching:
            modified = 0
            for node in matching:
                if ((policy is not UNSET and node.policy != policy)
                        or (options is not UNSET and getattr(node, 'options', ()) != options)):
                    validate_quantumult_options(getattr(node, 'options', ()))
                changed = False
                if policy is not UNSET and node.policy != policy:
                    node.policy = policy
                    changed = True
                if options is not UNSET and node.options != options:
                    node.options = options
                    changed = True
                modified += changed
            logger.info('Rule update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self.is_dirty = True
                self.update_metadata(only_if_changed=True)
            return
        if policy is UNSET:
            raise ValueError('A new Quantumult X rule requires an explicit non-empty policy result')
        fields = [rule_type, policy] if rule_type == 'FINAL' else [rule_type, value, policy]
        node = QuantumultRuleNode(','.join([*fields, *(options if options is not UNSET else ())]))
        self.nodes.insert(index, node)
        self.is_dirty = True
        self.update_metadata(only_if_changed=True)

    def modify(self, search, replace, is_regex=False, count=0):
        from rule_framework.rule_helpers import _modify_physical_list
        _modify_physical_list(self, search, replace, is_regex, count,
                              lambda line: parse_quantumult_line(line))

    def validate(self):
        if self.file_role != 'rule-set':
            raise ValueError('Invalid Quantumult X list file role')
        if self.client != 'QuantumultX':
            raise ValueError('Invalid Quantumult X list client')
        if self._newline not in ('\n', '\r\n', '\r'):
            raise ValueError('Managed Quantumult X newline must be LF, CRLF or CR')
        if self._encoding not in ('utf-8', 'utf-8-sig'):
            raise ValueError('Unsupported Quantumult X list encoding')
        if not isinstance(self._raw_bytes, bytes):
            raise ValueError('Original Quantumult X content must be bytes')
        if not isinstance(self._metadata_baseline, bytes):
            raise ValueError('Quantumult X metadata baseline must be bytes')
        if not isinstance(self.ends_with_newline, bool):
            raise ValueError('Managed Quantumult X trailing newline flag must be a boolean')
        if not isinstance(self.is_dirty, bool):
            raise ValueError('Managed Quantumult X dirty state must be a boolean')
        if not isinstance(self.nodes, list):
            raise ValueError('Managed Quantumult X nodes must be a list')
        for node in self.nodes:
            if not isinstance(node, ASTNode):
                raise ValueError('Managed Quantumult X nodes must be AST nodes')
            if getattr(node, 'line_ending', '\n') not in ('', '\n', '\r\n', '\r'):
                raise ValueError('Managed Quantumult X node newline must be LF, CRLF or CR')
            changed = getattr(node, 'needs_validation', False)
            if isinstance(node, QuantumultRuleNode):
                if not isinstance(node.type, str):
                    raise ValueError('Quantumult X rule type must be a string')
                if not isinstance(node.policy, str):
                    raise ValueError('Quantumult X policy must be a string')
                if not isinstance(node.options, tuple) or any(not isinstance(option, str) for option in node.options):
                    raise ValueError('Managed Quantumult X options must be a tuple of strings')
                changed = changed or (node.type, node.value, node.policy, node.options) != node._original_fields
            rendered = node.render()
            changed = changed or rendered != getattr(node, '_original_line', None)
            if changed and isinstance(node, RuleNode):
                if not isinstance(node.type, str):
                    raise ValueError('Quantumult X rule type must be a string')
                validate_quantumult_value(node.type.upper(), node.value)
                validate_quantumult_policy(node.policy)
                validate_quantumult_options(getattr(node, 'options', ()))
                if isinstance(node, QuantumultRuleNode):
                    validate_quantumult_options(node._original_fields[3])
                parsed = parse_quantumult_line(rendered)
                if (not isinstance(parsed, QuantumultRuleNode)
                        or (parsed.type, parsed.value, parsed.policy, parsed.options) !=
                        (node.type, node.value, node.policy, getattr(node, 'options', ()))):
                    raise ValueError('Changed Quantumult X node has inconsistent rendered syntax')
            elif changed:
                if isinstance(node, BlankNode):
                    valid = not rendered.strip()
                else:
                    valid = isinstance(node, CommentNode) and rendered.lstrip().startswith(('#', '//', ';'))
                if not valid:
                    raise ValueError('Changed Quantumult X list content has unrecognized structured syntax')
            if changed and any(char in rendered for char in '\r\n\0'):
                raise ValueError('Changed Quantumult X node syntax must occupy one line')
        super().validate()

    def add_native_rule(self, content, insert=None):
        from rule_framework.native_input import validate_native_entry
        validate_native_entry(self, content, kind='rule')
        if not isinstance(content, str) or not content.strip() or any(char in content for char in '\r\n\0'):
            raise ValueError('Native rule input must be one non-empty line')
        index = calculate_insert_index(self.nodes, insert)
        node = parse_quantumult_line(content)
        identity = None
        if isinstance(node, QuantumultRuleNode):
            try:
                validate_quantumult_value(node.type.upper(), node.value)
                validate_quantumult_policy(node.policy)
                validate_quantumult_options(node.options)
                identity = node.identity
            except ValueError:
                pass
        if identity is not None and any(getattr(item, 'identity', None) == identity for item in self.nodes):
            self.add_rule(node.type, node.value, policy=node.policy, insert=insert, options=node.options)
            return
        if any(item.render() == content for item in self.nodes):
            logger.info('Native input already present; matched=1 modified=0 in %s', self.filepath)
            return
        self.nodes.insert(index, node)
        self.is_dirty = True
        self.update_metadata(only_if_changed=True)

    def _get_rule_count(self):
        count = 0
        for node in self.nodes:
            if isinstance(node, RuleNode):
                try:
                    validate_quantumult_value(node.type.upper(), node.value)
                    validate_quantumult_policy(node.policy)
                except ValueError:
                    continue
                count += 1
        return count

    def update_metadata(self, *, only_if_changed=False):
        metadata_before = self.render_bytes() if not only_if_changed else None
        from rule_framework.standard_lists import StandardListMixin
        StandardListMixin.update_metadata(self, only_if_changed=only_if_changed)
        from rule_framework.metadata import list_header_nodes
        from collections import Counter
        counts = Counter()
        for node in self.nodes:
            if isinstance(node, RuleNode):
                try:
                    validate_quantumult_value(node.type.upper(), node.value)
                    validate_quantumult_policy(node.policy)
                except ValueError:
                    continue
                counts[node.type.upper()] += 1
        for node in list_header_nodes(self):
            if isinstance(node, CommentNode):
                match = re.fullmatch(r'(\s*#\s+)([A-Z0-9_-]+)(:\s*)(.*?)([ \t]*)', node.render())
                if match and match.group(2) in QUANTUMULT_TYPES:
                    node.content = match.group(1) + match.group(2) + match.group(3) + str(counts[match.group(2)]) + match.group(5)
        from rule_framework.metadata import metadata_key, list_header_nodes
        from rule_framework.rule_helpers import STANDARD_TYPES
        owned = STANDARD_TYPES | QUANTUMULT_TYPES | {'AUTHOR', 'REPO', 'UPDATED', 'TOTAL', 'AND', 'OR', 'NOT'}
        from rule_framework.metadata import finish_generated_metadata
        finish_generated_metadata(self, only_if_changed, tuple((node.render(), getattr(node, 'line_ending', self._newline)) for node in list_header_nodes(self) if metadata_key(node.render(), owned)), before=metadata_before)

    def remove_rule(self, rule_type, value=None, *, conditions=UNSET):
        if conditions is not UNSET:
            validate_quantumult_conditions(conditions)
        types = ({quantumult_native_type(rule_type, value)} if rule_type in {'domain_suffix', 'domain_wildcard'}
                 else {quantumult_native_type(item, value) for item in select_rule_types(rule_type)})
        if rule_type == 'domain' and value is not None:
            validate_domain_selector(value)
        kept = []
        removed = 0
        for line_number, node in enumerate(self.nodes, 1):
            if (rule_type == 'domain' and isinstance(node, RuleNode)
                    and node.type.upper() not in QUANTUMULT_TYPES
                    and (value is None or canonical_domain(node.value) == canonical_domain(value))):
                raise ValueError(f'Cannot recognize required domain reference at {self.filepath}:{line_number}: '
                                 f'unknown rule type {node.type!r}')
            selected = isinstance(node, RuleNode) and node.type.upper() in types
            if selected and value is not None:
                if node.type.upper() in SEMANTIC_TYPES['domain']:
                    selected = canonical_domain(node.value) == canonical_domain(value)
                else:
                    selected = node.value == value
            if selected:
                removed += 1
            else:
                kept.append(node)
        if removed:
            self.nodes = kept
            self.is_dirty = True
            self.update_metadata(only_if_changed=True)
        logger.info('Removed %s matching rules from %s', removed, self.filepath)

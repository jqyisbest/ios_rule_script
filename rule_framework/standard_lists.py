"""Role-aware maintenance for external standard routing lists."""

from rule_framework.logical_refs import is_parenthesized_payload

from pathlib import Path
import logging
import re

from rule_framework.ast import RuleNode, CommentNode, BlankNode, parse_line, split_by_comma_at_depth_0, get_comma_indices_at_depth_0
from rule_framework.rule_helpers import native_rule_type, select_rule_types, UNSET, condition_options, validate_options, validate_standard_value, rule_identity, validate_domain_selector

logger = logging.getLogger('RuleFramework')


class DomainSetNode(RuleNode):
    """A typeless domain reference whose leading dot carries suffix semantics."""

    def __init__(self, line):
        value = line.strip()
        rule_type = 'DOMAIN-WILDCARD' if any(token in value for token in '*?[') else (
            'DOMAIN-SUFFIX' if value.startswith('.') else 'DOMAIN'
        )
        reference = value if rule_type == 'DOMAIN-WILDCARD' else (value[1:] if value.startswith('.') else value)
        super().__init__(rule_type, reference)
        self.original = line
        self._original_fields = (self.type, self.value)

    @property
    def identity(self):
        return rule_identity(self.type, self.value)

    def render(self):
        if (self.type, self.value) == self._original_fields:
            return self.original
        leading = self.original[:len(self.original) - len(self.original.lstrip())]
        trailing = self.original[len(self.original.rstrip()):]
        return leading + ('.' if self.type == 'DOMAIN-SUFFIX' else '') + self.value + trailing


class StandardRuleNode(RuleNode):
    """External rule options are matching conditions, with an absent policy."""

    def __init__(self, line):
        match = re.search(r'\s+#', line)
        self.inline_comment = line[match.start():] if match else ''
        content = line[:match.start()] if match else line
        prefix, tail = content.split(',', 1)
        unquoted_regex = prefix.strip().upper() == 'URL-REGEX' and not tail.lstrip().startswith(('"', "'"))
        parts = content.split(',', 1) if unquoted_regex else split_by_comma_at_depth_0(content)
        parts = [part.strip() for part in parts]
        super().__init__(parts[0], parts[1])
        self.options = tuple(parts[2:])
        self.original = line
        self._original_fields = (self.type, self.value, self.options)
        comma_indices = get_comma_indices_at_depth_0(content)
        value_end = len(content) if unquoted_regex or len(parts) < 3 else comma_indices[1]
        self.raw_prefix = [content[:comma_indices[0]], content[comma_indices[0] + 1:value_end]]
        self.raw_options_tail = content[value_end:]

    @property
    def identity(self):
        return rule_identity(self.type, self.value, self.options)

    def render(self):
        if (self.type, self.value, self.options) == self._original_fields:
            return self.original
        fields = []
        for raw, current, original in zip(self.raw_prefix, (self.type, self.value), self._original_fields):
            if current == original:
                fields.append(raw)
            else:
                leading = raw[:len(raw) - len(raw.lstrip())]
                trailing = raw[len(raw.rstrip()):]
                fields.append(leading + current + trailing)
        tail = self.raw_options_tail if self.options == self._original_fields[2] else (',' + ','.join(self.options) if self.options else '')
        return ','.join(fields) + tail + self.inline_comment


def domain_set_role(filepath, lines):
    active = [line.strip() for line in lines
              if line.strip() and not line.lstrip().startswith(('#', '//', ';'))]
    if any(',' in line or line.startswith('[') for line in active):
        return False
    named = Path(filepath).stem.lower().endswith('_domain')
    shaped = bool(active) and all(re.fullmatch(r'[\w.*?\[\]-]+', line) for line in active)
    return named or shaped


class StandardListMixin:
    """Shared syntax; client identity and the external-list role stay explicit."""

    def __init__(self, filepath):
        super().__init__(filepath)
        self.file_role = 'domain-set' if domain_set_role(filepath, []) else 'rule-set'
        from rule_framework.client_paths import client_for_path
        self.client = client_for_path(filepath)
        self._newline = '\n'
        self._encoding = 'utf-8'
        self._raw_bytes = b''
        self._metadata_baseline = b''

    def load(self):
        from rule_framework.text_json import split_physical_records
        self._raw_bytes = Path(self.filepath).read_bytes()
        self._metadata_baseline = self._raw_bytes
        self._encoding = 'utf-8-sig' if self._raw_bytes.startswith(b'\xef\xbb\xbf') else 'utf-8'
        raw = self._raw_bytes.decode(self._encoding)
        records = split_physical_records(raw)
        lines = [line for line, _ in records]
        self._newline = next((ending for _, ending in records if ending), '\n')
        self.ends_with_newline = bool(re.search(r'(\r\n|\r|\n)$', raw))
        self.file_role = 'domain-set' if domain_set_role(self.filepath, lines) else 'rule-set'
        from rule_framework.client_paths import client_for_path
        self.client = client_for_path(self.filepath, base_dir=getattr(self, 'settings', {}).get('base_dir'))
        self.nodes = []
        for line, ending in records:
            node = self.parse_standard_line(line)
            if isinstance(node, (CommentNode, BlankNode)):
                node._standard_baseline_line = line
            node.line_ending = ending
            self.nodes.append(node)
        from rule_framework.metadata import mark_list_header
        mark_list_header(self)
        self.is_dirty = False

    def parse_standard_line(self, line):
        node = parse_line(line)
        if line.lstrip().startswith(('#', '//', ';')):
            return CommentNode(line)
        if isinstance(node, BlankNode):
            return node
        if getattr(self, 'file_role', 'rule-set') == 'domain-set':
            return DomainSetNode(line)
        if isinstance(node, RuleNode):
            return StandardRuleNode(line)
        return node

    def render_bytes(self):
        from rule_framework.text_json import serialize_physical_nodes
        encoding = getattr(self, '_encoding', 'utf-8')
        bom = b'\xef\xbb\xbf' if encoding == 'utf-8-sig' else b''
        return serialize_physical_nodes(self.nodes, newline=getattr(self, '_newline', '\n'),
            ends_with_newline=getattr(self, 'ends_with_newline', True), encoding='utf-8', bom=bom)

    def validate_complete(self):
        if self.render_bytes() != self._metadata_baseline:
            self.update_metadata(only_if_changed=True)
            from rule_framework.metadata import remember_list_baseline
            remember_list_baseline(self)

    def save(self):
        self.validate()
        self.validate_complete()
        with open(self.filepath, 'wb') as output:
            output.write(self.render_bytes())

    def remove_rule(self, rule_type, value=None, *, conditions=UNSET):
        from rule_framework.native_input import guard_required_rule_semantics
        guard_required_rule_semantics(self, rule_type, value)
        from rule_framework.domain_refs import canonical_domain, url_host_references, ReferenceRecognitionError
        from rule_framework.rule_helpers import STANDARD_TYPES
        target_types = select_rule_types(rule_type)
        if rule_type == 'domain' and value is not None:
            validate_domain_selector(value)
        selected_conditions = self._condition_options(conditions) if conditions is not UNSET else UNSET
        new_nodes = []
        removed = 0
        for line_number, node in enumerate(self.nodes, 1):
            selected = False
            if (rule_type == 'domain' and self.file_role == 'rule-set' and isinstance(node, CommentNode)
                    and re.match(r'^(?:AND|OR|NOT)(?:$|[\s,(])', node.render().lstrip(), re.IGNORECASE)):
                raise ValueError(f'Cannot recognize required logical domain references at {self.filepath}:{line_number}: malformed logical rule')
            if isinstance(node, RuleNode) and node.type.upper() in target_types:
                actual = node.value
                expected = value
                if rule_type == 'domain' and value is not None:
                    actual, expected = canonical_domain(actual), canonical_domain(value)
                selected = value is None or actual == expected
            elif rule_type == 'domain' and isinstance(node, RuleNode) and node.type.upper() in {'AND', 'OR', 'NOT'}:
                from rule_framework.logical_refs import logical_reference_matches
                selected = logical_reference_matches(node.type, node.value, value, client=self.client,
                    location=f'{self.filepath}:{line_number}')
            elif rule_type == 'domain' and isinstance(node, RuleNode) and node.type.upper() == 'URL-REGEX':
                try:
                    references = url_host_references(node.value)
                except ReferenceRecognitionError as error:
                    raise ValueError(f'Cannot recognize URL host reference at {self.filepath}:{line_number}: {error}') from error
                selected = value is None or references.contains(value)
            elif rule_type == 'domain' and isinstance(node, RuleNode) and node.type.upper() not in STANDARD_TYPES | {'AND', 'OR', 'NOT'}:
                if value is None or is_parenthesized_payload(node.value) or canonical_domain(node.value) == canonical_domain(value):
                    raise ValueError(f'Cannot recognize required domain reference at {self.filepath}:{line_number}: '
                                     f'unknown rule type {node.type!r}')
            if selected and selected_conditions is not UNSET:
                selected = self._rule_identity(node.type, node.value, getattr(node, 'options', ()))[2] == self._rule_identity(node.type, node.value, selected_conditions)[2]
            if selected:
                removed += 1
            else:
                new_nodes.append(node)
        if removed:
            self.nodes = new_nodes
            self.is_dirty = True
            self.update_metadata(only_if_changed=True)
        logger.info('Removed %s matching rules from %s', removed, self.filepath)

    def add_rule(self, rule_type, value, policy=UNSET, insert=None, *, conditions=UNSET, options=UNSET):
        if policy is not UNSET and policy not in (None, ''):
            raise ValueError('External standard list has no inline policy result; select a complete-profile adapter')
        rule_type = native_rule_type(rule_type, value, client=self.client)
        validate_standard_value(rule_type, value, client=self.client)
        from rule_framework.rule_helpers import calculate_insert_index
        index = calculate_insert_index(self.nodes, insert)
        selected_conditions = self._condition_options(conditions) if conditions is not UNSET else UNSET
        if selected_conditions is not UNSET:
            self._validate_options(selected_conditions, rule_type, getattr(self, 'client', 'unknown'))
        if options is not UNSET:
            options = self._validate_options(options, rule_type, getattr(self, 'client', 'unknown'))
        identity_prefix = self._rule_identity(rule_type, value)[:2]
        matching = [node for node in self.nodes if isinstance(node, RuleNode)
                    and self._rule_identity(node.type, node.value)[:2] == identity_prefix
                    and (selected_conditions is UNSET or
                         self._rule_identity(node.type, node.value, getattr(node, 'options', ()))[2] == self._rule_identity(node.type, node.value, selected_conditions)[2])]
        if matching:
            modified = 0
            for node in matching:
                if options is not UNSET and tuple(getattr(node, 'options', ())) != options:
                    self._validate_options(node.options, rule_type, getattr(self, 'client', 'unknown'))
                    node.options = options
                    modified += 1
            logger.info('Rule update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self.is_dirty = True
                self.update_metadata(only_if_changed=True)
            return
        new_options = options if options is not UNSET else (() if selected_conditions is UNSET else selected_conditions)
        already_satisfied = [node for node in self.nodes if isinstance(node, RuleNode)
                             and self._rule_identity(node.type, node.value)[:2] == identity_prefix
                             and self._rule_identity(node.type, node.value, getattr(node, 'options', ()))[2] == self._rule_identity(rule_type, value, new_options)[2]]
        if already_satisfied:
            logger.info('Rule update already satisfied; matched=%s modified=0 in %s', len(already_satisfied), self.filepath)
            return
        if getattr(self, 'file_role', 'rule-set') == 'domain-set':
            if rule_type not in {'DOMAIN', 'DOMAIN-SUFFIX'} or new_options:
                raise ValueError('Domain-set generation requires verified literal/suffix entries without rule options; use explicit native input for unverified expressions')
            node = DomainSetNode(('.' if rule_type == 'DOMAIN-SUFFIX' else '') + value)
        else:
            node = StandardRuleNode(','.join([rule_type, value, *new_options]))
        self.nodes.insert(index, node)
        self.is_dirty = True
        self.update_metadata(only_if_changed=True)

    def add_native_rule(self, content, insert=None):
        from rule_framework.native_input import validate_native_entry
        _, semantic = validate_native_entry(self, content, kind='rule')
        from rule_framework.rule_helpers import calculate_insert_index
        if not isinstance(content, str) or not content.strip() or any(char in content for char in '\r\n\0'):
            raise ValueError('Native rule input must be one non-empty line')
        index = calculate_insert_index(self.nodes, insert)
        node = self.parse_standard_line(content)
        if semantic == 'unknown':
            node._opaque_native_line = content
        identity = None
        if isinstance(node, RuleNode):
            try:
                validate_standard_value(node.type.upper(), node.value, client=self.client)
                self._validate_options(getattr(node, 'options', ()), node.type.upper(), self.client)
                identity = self._rule_identity(node.type, node.value, getattr(node, 'options', ()))
            except ValueError:
                # Unknown native field semantics require exact-text repeat detection.
                pass
        existing = [item for item in self.nodes if (identity is not None and isinstance(item, RuleNode) and self._rule_identity(item.type, item.value, getattr(item, 'options', ())) == identity)
                    or item.render() == content]
        if existing:
            logger.info('Native input already present; matched=%s modified=0', len(existing))
            return
        self.nodes.insert(index, node)
        self.is_dirty = True
        self.update_metadata(only_if_changed=True)

    def modify(self, search, replace, is_regex=False, count=0):
        from rule_framework.rule_helpers import _modify_physical_list
        _modify_physical_list(self, search, replace, is_regex, count,
                              lambda line: self.parse_standard_line(line))

    def validate(self):
        from rule_framework.ast import ASTNode
        from rule_framework.managed_validation import validate_passive_node
        super().validate()
        if getattr(self, 'file_role', 'rule-set') not in ('rule-set', 'domain-set'):
            raise ValueError('Invalid standard-list file role')
        if getattr(self, '_newline', '\n') not in ('\n', '\r\n', '\r'):
            raise ValueError('Managed newline must be LF, CRLF or CR')
        if getattr(self, '_encoding', 'utf-8') not in ('utf-8', 'utf-8-sig'):
            raise ValueError('Unsupported standard-list encoding')
        if not isinstance(self.is_dirty, bool):
            raise ValueError('Managed dirty state must be a boolean')
        for node in self.nodes:
            if not isinstance(node, ASTNode):
                raise ValueError('Managed standard-list nodes must be AST nodes')
            if getattr(node, 'line_ending', '\n') not in ('', '\n', '\r\n', '\r'):
                raise ValueError('Managed node newline must be LF, CRLF or CR')
            if isinstance(node, StandardRuleNode) and (not isinstance(node.options, tuple) or
                    any(not isinstance(option, str) for option in node.options)):
                raise ValueError('Managed rule options must be a tuple of strings')
            changed = getattr(node, 'needs_validation', False)
            if isinstance(node, (CommentNode, BlankNode)):
                changed = changed or node.render() != getattr(node, '_standard_baseline_line', None)
                if not hasattr(node, '_opaque_native_line'):
                    validate_passive_node(node, changed=changed)
            if isinstance(node, StandardRuleNode):
                changed = changed or (node.type, node.value, node.options) != node._original_fields
                if node.policy not in (None, ''):
                    raise ValueError('External standard list has no inline policy result')
            elif isinstance(node, DomainSetNode):
                changed = changed or (node.type, node.value) != node._original_fields
                if node.policy not in (None, ''):
                    raise ValueError('Domain-set entries cannot represent a policy result')
                options = getattr(node, 'options', ())
                if not isinstance(options, (tuple, list)) or options:
                    raise ValueError('Domain-set entries cannot represent rule options; an empty sequence clears them')
            elif isinstance(node, RuleNode):
                changed = True
            if changed and isinstance(node, RuleNode):
                validate_standard_value(node.type.upper(), node.value, client=self.client)
                self._validate_options(getattr(node, 'options', ()), node.type.upper(), getattr(self, 'client', 'unknown'))
                if self.file_role == 'domain-set' and node.type.upper() not in {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-WILDCARD'}:
                    raise ValueError('Domain-set files require typeless domain entries')
            elif changed and isinstance(node, CommentNode) and not hasattr(node, '_opaque_native_line') and not node.render().lstrip().startswith(('#', '//', ';')):
                raise ValueError('Changed standard-list content has unrecognized structured syntax')
            if not isinstance(node.render(), str):
                raise ValueError('Managed standard-list rendering must be a string')

    def update_metadata(self, *, only_if_changed=False):
        metadata_before = self.render_bytes() if not only_if_changed else None
        from rule_framework.metadata import metadata_key, list_header_nodes, resolve_signature
        from rule_framework.rule_helpers import STANDARD_TYPES
        owned = STANDARD_TYPES | {'AUTHOR', 'REPO', 'UPDATED', 'TOTAL', 'AND', 'OR', 'NOT'}
        if self.client == 'QuantumultX':
            from rule_framework.quantumult_lists import QUANTUMULT_TYPES
            owned |= QUANTUMULT_TYPES
        from rule_framework.metadata import restore_unchanged_list_metadata, finish_generated_metadata
        if only_if_changed and restore_unchanged_list_metadata(self, owned):
            return
        from rule_framework.fom import _get_now
        settings = getattr(self, 'settings', {})
        author, repo = resolve_signature(settings)
        desired = {'AUTHOR': author, 'REPO': repo}
        from collections import Counter
        from rule_framework.rule_helpers import STANDARD_TYPES
        counts = Counter(node.type.upper() for node in self.nodes if isinstance(node, RuleNode))
        statistic_types = STANDARD_TYPES | {'AND', 'OR', 'NOT'} | counts.keys()
        fields = {}
        for index, node in enumerate(list_header_nodes(self)):
            if isinstance(node, CommentNode):
                match = re.fullmatch(r'(\s*#\s+)([A-Z0-9_-]+)(:\s*)(.*?)([ \t]*)', node.render())
                if match:
                    fields.setdefault(match.group(2), []).append((index, node, match))
        metadata_values = [('TOTAL', str(self._get_rule_count())), ('UPDATED', _get_now(self))]
        metadata_values.extend((key, str(counts[key])) for key in fields if key in statistic_types)
        for key, value in metadata_values:
            if key in fields:
                for _, node, match in fields[key]:
                    node.content = match.group(1) + key + match.group(3) + value + match.group(5)
            else:
                self.nodes.insert(0, CommentNode(f'# {key}: {value}'))
        for key, value in desired.items():
            if any(match.group(4) == value for _, _, match in fields.get(key, ())):
                continue
            index = next((index for index, node in enumerate(list_header_nodes(self))
                          if isinstance(node, CommentNode) and re.match(rf'\s*#\s+{key}:', node.render())),
                         0 if key == 'AUTHOR' else 1)
            self.nodes.insert(index, CommentNode(f'# {key}: {value}'))

        records = tuple((node.render(), getattr(node, 'line_ending', self._newline)) for node in list_header_nodes(self) if metadata_key(node.render(), owned))
        if self.client == 'QuantumultX':
            self._generated_metadata = records
        else:
            finish_generated_metadata(self, only_if_changed, records, before=metadata_before)

    def _condition_options(self, conditions):
        if self.client == 'Shadowrocket':
            from rule_framework.shadowrocket import condition_options as shadowrocket_conditions
            return shadowrocket_conditions(conditions)
        return condition_options(conditions)

    def _validate_options(self, options, rule_type, client=None):
        if self.client == 'Shadowrocket':
            from rule_framework.shadowrocket import validate_options as shadowrocket_options
            return shadowrocket_options(options, rule_type)
        return validate_options(options, rule_type, self.client if client is None else client)

    def _rule_identity(self, rule_type, value, options=()):
        if self.client == 'Shadowrocket':
            from rule_framework.shadowrocket import shadowrocket_rule_identity
            return shadowrocket_rule_identity(rule_type, value, options)
        return rule_identity(rule_type, value, options)

"""Maintenance of the repository's basic AdGuard domain-filter lists."""

import logging
import re
from pathlib import Path

from rule_framework.ast import ASTNode, AdGuardRuleNode, BlankNode, CommentNode
from rule_framework.domain_refs import canonical_domain
from rule_framework.rule_helpers import UNSET, calculate_insert_index, validate_domain_selector
from rule_framework.text_json import decode_text, encode_text

logger = logging.getLogger('RuleFramework')


class BasicDomainFilterNode(AdGuardRuleNode):
    """A literal ||host^ block, retaining its original text until edited."""

    type = 'ADGUARD-DOMAIN'

    def __init__(self, line, domain):
        trailing = line[len(line.rstrip(' \t')):]
        super().__init__(domain, '', trailing_whitespace=trailing, raw_value=line.rstrip(' \t'))
        self.original = line
        self._original_domain = domain

    @property
    def value(self):
        return self.core_domain

    @value.setter
    def value(self, value):
        self.core_domain = value

    @property
    def identity(self):
        return self.type, canonical_domain(self.core_domain), ()

    def render(self):
        if self.core_domain == self._original_domain:
            return self.original
        return '||' + self.core_domain + '^' + self.trailing_whitespace


class OpaqueFilterNode(ASTNode):
    """Untouched native content retains its bytes and an explicit recognition bound."""

    def __init__(self, line):
        self.content = line
        self._original_line = line

    def render(self):
        return self.content


def parse_filter_line(line):
    if not line.strip():
        return BlankNode(line)
    if line.startswith(('!', '#')):
        return CommentNode(line)
    match = re.fullmatch(r'\|\|([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?)\^([ \t]*)', line)
    if match:
        return BasicDomainFilterNode(line, match.group(1))
    return OpaqueFilterNode(line)


def opaque_domain_reference(line):
    """Recognize only a finite reference identity, without validating other fields."""
    match = re.fullmatch(r'(?:@@)?\|\|([A-Za-z0-9_.*?\[\]-]+)(?:\^.*|[/|$].*|)', line.rstrip(' \t'))
    if match:
        return canonical_domain(match.group(1))
    if re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?[ \t]*', line):
        return canonical_domain(line.rstrip(' \t'))
    return None


def validate_filter_value(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?', value):
        raise ValueError('AdGuard basic-filter value must be a literal domain reference; structured wildcard, URL and modifier generation exceeds the current scope')


def validate_filter_fields(policy=UNSET, conditions=UNSET, options=UNSET):
    if policy is not UNSET:
        raise ValueError('AdGuard basic-filter policy cannot be represented; omit policy for a domain block')
    if conditions is not UNSET and (not isinstance(conditions, dict) or conditions):
        raise ValueError('AdGuard basic-filter conditions require an empty dictionary; additional matching conditions exceed the current scope')
    if options is not UNSET and (not isinstance(options, (tuple, list)) or options):
        raise ValueError('AdGuard basic-filter options require an empty list; modifier generation exceeds the current scope')


def filter_records(text):
    records = re.findall(r'[^\r\n]*(?:\r\n|\r|\n|$)', text)
    return records[:-1] if records and records[-1] == '' else records


class AdGuardFilterMixin:
    """Client-specific basic filtering; maintenance selection uses exact identity."""

    def __init__(self, filepath):
        super().__init__(filepath)
        self.client = 'AdGuard'
        self.file_role = 'basic-domain-filter-list'
        self._encoding = 'utf-8'
        self._bom = b''
        self._newline = '\n'
        self._metadata_baseline = b''
        self._native_opaque = {}
        self.ends_with_newline = True

    def get_comment_prefix(self):
        return '! '

    def scaffold(self, base_name):
        from rule_framework.fom import _get_now
        settings = getattr(self, 'settings', {})
        from rule_framework.metadata import resolve_signature
        author, repo = resolve_signature(settings)
        self.nodes = [
            CommentNode(f'! Title: {base_name}'),
            CommentNode(f'! Author: {author}'),
            CommentNode(f'! Homepage: {repo}'),
            CommentNode(f'! Updated: {_get_now(self)}'),
            CommentNode('! Total: 0'), BlankNode(),
        ]
        self._native_opaque = {}
        self.ends_with_newline = True
        self.is_dirty = True

    def load(self):
        raw = Path(self.filepath).read_bytes()
        text, self._encoding, self._bom = decode_text(raw)
        self._metadata_baseline = raw
        self._native_opaque = {}
        self.nodes = []
        records = filter_records(text)
        for record in records:
            line = record.rstrip('\r\n')
            node = parse_filter_line(line)
            node.line_ending = record[len(line):]
            self.nodes.append(node)
            if isinstance(node, OpaqueFilterNode):
                self._native_opaque[node] = line
        self._newline = next((node.line_ending for node in self.nodes if node.line_ending), '\n')
        self.ends_with_newline = text.endswith(('\r', '\n'))
        from rule_framework.metadata import mark_list_header
        mark_list_header(self)
        self.is_dirty = False

    def render_bytes(self):
        from rule_framework.text_json import serialize_physical_nodes
        return serialize_physical_nodes(self.nodes, newline=self._newline,
            ends_with_newline=self.ends_with_newline, encoding=self._encoding, bom=self._bom)

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
        if rule_type != 'domain':
            raise ValueError(f'AdGuard basic-filter type must be domain; received {rule_type!r}')
        validate_filter_value(value)
        validate_filter_fields(policy, conditions, options)
        index = calculate_insert_index(self.nodes, insert)
        identity = ('ADGUARD-DOMAIN', canonical_domain(value), ())
        for line_number, node in enumerate(self.nodes, 1):
            if isinstance(node, OpaqueFilterNode):
                reference = opaque_domain_reference(node.render())
                if reference is None or reference == canonical_domain(value):
                    raise ValueError(f'Cannot recognize required AdGuard update identity at '
                                     f'{self.filepath}:{line_number}: unknown matching/result fields '
                                     f'{node.render()!r}; the complete Task must roll back')
        matching = [node for node in self.nodes if getattr(node, 'identity', None) == identity]
        logger.info('AdGuard domain intent: traffic=domain-and-subdomains; maintenance=exact-reference; '
                    'runtime-validation=not-run in %s', self.filepath)
        if matching:
            logger.info('AdGuard rule update matched=%s modified=0 in %s', len(matching), self.filepath)
            return
        self.nodes.insert(index, BasicDomainFilterNode('||' + value + '^', value))
        self.is_dirty = True
        self.update_metadata(only_if_changed=True)

    def add_native_rule(self, content, insert=None):
        from rule_framework.native_input import validate_native_entry
        validate_native_entry(self, content, kind='rule')
        if (not isinstance(content, str) or not content.strip()
                or any((ord(char) < 32 and char != '\t') or char in '\x85\u2028\u2029' for char in content)):
            raise ValueError('AdGuard native rule input must be one non-empty line without control characters')
        index = calculate_insert_index(self.nodes, insert)
        node = parse_filter_line(content)
        recognition = 'basic-literal-domain' if isinstance(node, BasicDomainFilterNode) else 'recognition-only'
        semantic = 'basic-domain-shape-only' if isinstance(node, BasicDomainFilterNode) else 'not-run'
        identity = node.identity if isinstance(node, BasicDomainFilterNode) else None
        matching = [item for item in self.nodes if item.render() == content or
                    (identity is not None and getattr(item, 'identity', None) == identity)]
        if matching:
            logger.info('AdGuard native update matched=%s modified=0 in %s', len(matching), self.filepath)
            return
        self.nodes.insert(index, node)
        if isinstance(node, OpaqueFilterNode):
            self._native_opaque[node] = content
        self.is_dirty = True
        self.update_metadata(only_if_changed=True)

    def remove_rule(self, rule_type, value=None, *, conditions=UNSET):
        if rule_type != 'domain':
            raise ValueError(f'AdGuard basic-filter removal type must be domain; received {rule_type!r}')
        validate_filter_fields(conditions=conditions)
        if value is not None:
            validate_domain_selector(value)
        selected = canonical_domain(value) if value is not None else None
        nodes = []
        removed = 0
        for line_number, node in enumerate(self.nodes, 1):
            if isinstance(node, OpaqueFilterNode):
                reference = opaque_domain_reference(node.render())
                if selected is None or reference is None or reference == selected:
                    raise ValueError(f'Cannot recognize required AdGuard domain reference at '
                                     f'{self.filepath}:{line_number}: unsupported basic-filter structure '
                                     f'{node.render()!r}; the complete Task must roll back')
            if isinstance(node, BasicDomainFilterNode) and (selected is None or
                    canonical_domain(node.core_domain) == selected):
                removed += 1
            else:
                nodes.append(node)
        if removed:
            self.nodes = nodes
            self.is_dirty = True
            self.update_metadata(only_if_changed=True)
        logger.info('Removed %s matching AdGuard filters from %s; maintenance=exact-reference',
                    removed, self.filepath)

    def modify(self, search, replace, is_regex=False, count=0):
        from difflib import SequenceMatcher
        from rule_framework.fom import _apply_text_replacement
        original, _, _ = decode_text(self.render_bytes())
        updated, _ = _apply_text_replacement(original, search, replace, is_regex, count)
        if updated == original:
            return
        old_records, new_records = filter_records(original), filter_records(updated)
        nodes = []
        for kind, first, end, changed, changed_end in SequenceMatcher(
                a=old_records, b=new_records, autojunk=False).get_opcodes():
            if kind == 'equal':
                nodes.extend(self.nodes[first:end])
                continue
            if any(isinstance(node, OpaqueFilterNode) for node in self.nodes[first:end]):
                raise ValueError('AdGuard text edit requires changing unsupported filter structure; the complete Task must roll back')
            for offset, record in enumerate(new_records[changed:changed_end]):
                line = record.rstrip('\r\n')
                node = parse_filter_line(line)
                if isinstance(node, OpaqueFilterNode):
                    raise ValueError(f'Changed AdGuard content has unsupported structured syntax: {line!r}; use explicit native input for preservation')
                node.line_ending = record[len(line):]
                previous = self.nodes[min(first + offset, end - 1)] if first < end else None
                node._metadata_header = getattr(previous, '_metadata_header', False)
                nodes.append(node)
        self.nodes = nodes
        self.ends_with_newline = updated.endswith(('\r', '\n'))
        self.is_dirty = True
        self.validate()
        self.update_metadata(only_if_changed=True)

    def validate(self):
        if self.client != 'AdGuard' or self.file_role != 'basic-domain-filter-list':
            raise ValueError('AdGuard managed file must retain its client and basic-domain-filter-list role')
        if self._newline not in ('\n', '\r\n', '\r'):
            raise ValueError('AdGuard managed newline must be LF, CRLF or CR')
        if not isinstance(self.ends_with_newline, bool) or not isinstance(self.is_dirty, bool):
            raise ValueError('AdGuard managed newline and dirty states must be booleans')
        if not isinstance(self._metadata_baseline, bytes):
            raise ValueError('AdGuard metadata baseline must be bytes')
        if not isinstance(self.nodes, list):
            raise ValueError('AdGuard nodes must be a list')
        if not isinstance(self._native_opaque, dict) or any(node not in self.nodes for node in self._native_opaque):
            raise ValueError('AdGuard unsupported native structures require preserved registered nodes; direct deletion exceeds the current scope')
        for node in self.nodes:
            if getattr(node, 'line_ending', self._newline) not in ('', '\n', '\r\n', '\r'):
                raise ValueError('AdGuard node newline must be LF, CRLF or CR')
            if isinstance(node, BasicDomainFilterNode):
                validate_filter_value(node.core_domain)
                if node.type != 'ADGUARD-DOMAIN':
                    raise ValueError('AdGuard basic-filter node type must be ADGUARD-DOMAIN')
                if node.options != '' or node.prepended_instruction != '' or hasattr(node, 'policy'):
                    raise ValueError('AdGuard basic-filter nodes cannot represent options, instruction or policy fields')
                parsed = parse_filter_line(node.render())
                if not isinstance(parsed, BasicDomainFilterNode) or parsed.core_domain != node.core_domain:
                    raise ValueError('AdGuard basic-filter rendering must agree with its domain value')
            elif isinstance(node, OpaqueFilterNode):
                if node not in self._native_opaque or node.render() != self._native_opaque[node]:
                    raise ValueError('Changed AdGuard content has unsupported structured syntax')
            elif isinstance(node, CommentNode):
                if not isinstance(node.content, str) or not node.content.startswith(('!', '#')):
                    raise ValueError('AdGuard comments must start with ! or #')
            elif isinstance(node, BlankNode):
                if not isinstance(node.content, str) or node.content.strip():
                    raise ValueError('AdGuard blank nodes must contain only whitespace')
            else:
                raise ValueError('AdGuard nodes require recognized filters/comments or explicit native input')
            rendered = node.render()
            if not isinstance(rendered, str) or any(char in rendered for char in '\r\n'):
                raise ValueError('AdGuard nodes must render a single text line')
        super().validate()
        self.render_bytes()

    def _get_rule_count(self):
        return sum(isinstance(node, (BasicDomainFilterNode, OpaqueFilterNode)) for node in self.nodes)

    def update_metadata(self, *, only_if_changed=False):
        metadata_before = self.render_bytes() if not only_if_changed else None
        from rule_framework.metadata import metadata_key, list_header_nodes
        owned = {'AUTHOR', 'REPO', 'HOMEPAGE', 'UPDATED', 'TOTAL'}
        from rule_framework.metadata import restore_unchanged_list_metadata, finish_generated_metadata
        if only_if_changed and restore_unchanged_list_metadata(self, owned):
            return
        from rule_framework.fom import _get_now
        settings = getattr(self, 'settings', {})
        aliases = {'HOMEPAGE': 'REPO'}
        fields = {}
        for index, node in enumerate(list_header_nodes(self)):
            if isinstance(node, CommentNode):
                match = re.fullmatch(r'([!#]\s*)([A-Za-z]+)(:\s*)(.*?)([ \t]*)', node.render())
                if match:
                    key = aliases.get(match.group(2).upper(), match.group(2).upper())
                    fields.setdefault(key, []).append((index, node, match))
        for key, value in (('TOTAL', str(self._get_rule_count())), ('UPDATED', _get_now(self))):
            if key in fields:
                for _, node, match in fields[key]:
                    node.content = match.group(1) + match.group(2) + match.group(3) + value + match.group(5)
            else:
                self.nodes.insert(0, CommentNode(f'! {key}: {value}'))
        from rule_framework.metadata import resolve_signature
        author, repo = resolve_signature(settings)
        for key, value in (('AUTHOR', author), ('REPO', repo)):
            if any(match.group(4) == value for _, _, match in fields.get(key, ())):
                continue
            if key in fields:
                _, reference, match = fields[key][0]
                index = self.nodes.index(reference)
                node = CommentNode(match.group(1) + match.group(2) + match.group(3) + value)
                node.line_ending = getattr(reference, 'line_ending', self._newline)
            else:
                index = 0 if key == 'AUTHOR' else 1
                node = CommentNode(f'! {key}: {value}')
            self.nodes.insert(index, node)
        records = tuple((node.render(), getattr(node, 'line_ending', self._newline)) for node in list_header_nodes(self) if metadata_key(node.render(), owned))
        finish_generated_metadata(self, only_if_changed, records, before=metadata_before)

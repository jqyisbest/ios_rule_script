from rule_framework.text_json import split_physical_lines
from pathlib import Path
import re
import logging
from collections import Counter

from rule_framework.ast import ASTNode, BlankNode, CommentNode, SectionNode, RewriteNode
from rule_framework.fom import INIFileFOM, _apply_text_replacement, _get_now
from rule_framework.text_json import decode_text, encode_text, serialize_physical_nodes
from rule_framework.surge import SurgeRuleNode, SurgeScriptNode, SurgeMITMNode, validate_cron, single_line, native_value, split_comment, token_spans, unquote, validate_new_regex
from rule_framework.surge import unknown_script_requires_identity
from rule_framework.domain_refs import canonical_domain, url_host_references, ReferenceRecognitionError
from rule_framework.rule_helpers import (UNSET, calculate_insert_index, native_rule_type,
    validate_standard_value, rule_identity, select_rule_types, validate_domain_selector, STANDARD_TYPES)

logger = logging.getLogger('RuleFramework')
REJECTS = {'reject', 'reject-200', 'reject-img', 'reject-tinygif', 'reject-dict',
           'reject-array', 'reject-video', 'reject-drop', 'reject-no-drop'}
REWRITE_MODES = REJECTS | {'header', '302', '307'}


class ShadowrocketRewriteNode(RewriteNode):
    """Pattern/replacement/result layout observed in Shadowrocket modules."""

    def __init__(self, line):
        content, self.inline_comment = split_comment(line)
        self.spans = token_spans(content)
        values = [unquote(item.group()) for item in self.spans]
        if len(values) != 3 or values[2].lower() not in REWRITE_MODES:
            raise ValueError('Unrecognizable Shadowrocket URL Rewrite fields')
        super().__init__(content, values[0])
        self.replacement, self.mode = values[1:]
        self._baseline = (self.match_pattern, self.replacement, self.mode)

    def render(self):
        result, cursor = '', 0
        for item, value in zip(self.spans, (self.match_pattern, self.replacement, self.mode)):
            result += self.content[cursor:item.start()]
            old = item.group()
            result += old if unquote(old) == value else native_value(value, quoted=old.startswith(('"', "'")))
            cursor = item.end()
        return result + self.content[cursor:] + self.inline_comment


OPTION_CONDITIONS = {'no_resolve': 'no-resolve', 'extended_matching': 'extended-matching',
                     'pre_matching': 'pre-matching'}


def condition_options(conditions):
    if not isinstance(conditions, dict) or any(type(value) is not bool for value in conditions.values()):
        raise ValueError('Shadowrocket matching conditions require a dictionary of booleans')
    unknown = set(conditions) - OPTION_CONDITIONS.keys()
    if unknown:
        raise ValueError(f'Unsupported Shadowrocket matching conditions: {sorted(unknown)}')
    if conditions.get('extended_matching') is False:
        raise ValueError('Shadowrocket extended_matching=False has no verified native disabling syntax')
    return tuple(sorted(OPTION_CONDITIONS[key] for key, enabled in conditions.items() if enabled))


def validate_options(options, rule_type):
    if not isinstance(options, (list, tuple)) or any(not isinstance(option, str) for option in options):
        raise ValueError('Shadowrocket options require a list of strings')
    if len(set(options)) != len(options):
        raise ValueError('Duplicate Shadowrocket matching options')
    for option in options:
        if option not in OPTION_CONDITIONS.values():
            raise ValueError(f'Unrecognized Shadowrocket matching option: {option}')
        if option == 'no-resolve' and rule_type not in {'IP-CIDR', 'IP-ASN', 'GEOIP'}:
            raise ValueError('Shadowrocket no-resolve requires an IP rule')
        if option in {'extended-matching', 'pre-matching'} and rule_type not in {
            'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-WILDCARD', 'DOMAIN-KEYWORD'}:
            raise ValueError('Shadowrocket extended/pre matching requires a domain rule')
    return tuple(options)


def matching_options(rule_type, options):
    fields = set(options)
    # Community manual reports SNI extended matching as enabled by default.
    # This normalizes semantic identity while preserving each native token layout.
    if rule_type in {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'}:
        fields.add('extended-matching')
    return tuple(sorted(fields))


def shadowrocket_rule_identity(rule_type, value, options=()):
    native, value, _ = rule_identity(rule_type, value)
    return native, value, matching_options(native, options)


class ShadowrocketRuleNode(SurgeRuleNode):
    """Shared comma layout with Shadowrocket default matching identity."""

    @property
    def identity(self):
        return shadowrocket_rule_identity(self.type, self.value, self.options)


SCRIPT_FIELDS = {'type', 'pattern', 'cronexp', 'script-path', 'requires-body', 'engine'}


class ShadowrocketScriptNode(SurgeScriptNode):
    """Named assignment tokenization with verified whole-field quote boundaries."""

    def __init__(self, line):
        super().__init__(line)
        for start, end in self.field_spans.values():
            raw = self.content[start:end]
            if raw.startswith(('"', "'")):
                escaped = False
                closing = None
                for index, char in enumerate(raw[1:], 1):
                    if escaped:
                        escaped = False
                    elif char == '\\':
                        escaped = True
                    elif char == raw[0]:
                        closing = index
                        break
                if closing != len(raw) - 1:
                    raise ValueError('Unrecognizable Shadowrocket quoted script field')


def validate_script(fields):
    if not isinstance(fields, dict) or any(not isinstance(v, str) for v in fields.values()):
        raise ValueError('Shadowrocket script fields require strings')
    unknown = set(fields) - SCRIPT_FIELDS
    if unknown:
        raise ValueError(f'Unrecognized Shadowrocket script fields required by mutation: {sorted(unknown)}')
    stage = fields.get('type')
    if stage not in ('http-request', 'http-response', 'cron'):
        raise ValueError('Structured Shadowrocket scripts require HTTP request/response or cron type')
    single_line(fields.get('script-path'), 'Shadowrocket script_path')
    if stage == 'cron':
        validate_cron(fields.get('cronexp'))
        if set(fields) & {'pattern', 'requires-body'}:
            raise ValueError('Shadowrocket cron scripts have conflicting HTTP fields')
    else:
        single_line(fields.get('pattern'), 'Shadowrocket pattern')
        if 'cronexp' in fields:
            raise ValueError('Shadowrocket HTTP scripts have conflicting cron fields')
    if 'requires-body' in fields and fields['requires-body'] not in ('true', 'false', '1', '0'):
        raise ValueError('Shadowrocket requires-body must be Boolean')
    if 'engine' in fields and fields['engine'] not in ('auto', 'jsc', 'webview'):
        raise ValueError('Shadowrocket engine must be auto, jsc or webview')


class ShadowrocketMITMNode(SurgeMITMNode):
    """Hostname assignment token layout; Shadowrocket operators remain explicit."""


def mitm_reference(value):
    single_line(value, 'Shadowrocket MITM hostname')
    if re.search(r'[\s,%{}=/:#]', value):
        raise ValueError('Unrecognizable Shadowrocket MITM hostname reference')
    return canonical_domain(value)


class ShadowrocketUnknownNode(CommentNode):
    """Opaque native declarations retain their original spelling."""


class ShadowrocketFile(INIFileFOM):
    """Shadowrocket configuration purposes with per-record byte preservation."""

    transaction_fields = INIFileFOM.transaction_fields + (
        'client', 'file_role', 'text_encoding', 'text_bom', '_newline', '_section_names',
    )

    def __init__(self, filepath):
        super().__init__(filepath)
        self.client = 'Shadowrocket'
        self.file_role = 'module' if Path(filepath).suffix.lower() == '.sgmodule' else 'configuration-fragment'
        self.text_encoding, self.text_bom = 'utf-8', b''
        self._newline = '\n'
        self._section_names = {}
        self.ends_with_newline = True

    @property
    def is_module(self):
        return self.file_role == 'module'

    def load(self):
        text, self.text_encoding, self.text_bom = decode_text(Path(self.filepath).read_bytes())
        self._parse_text(text)
        self._metadata_baseline = self.render_bytes()
        self.is_dirty = False

    def _parse_text(self, text):
        self.header_nodes, self.sections, self.section_order, self._section_names = [], {}, [], {}
        records = split_physical_lines(text)
        self.ends_with_newline = text.endswith(('\n', '\r'))
        self._newline = next((record[len(record.rstrip('\r\n')):] for record in records
                              if record.endswith(('\n', '\r'))), self._newline)
        section = None
        for record in records:
            line = record.rstrip('\r\n')
            match = re.fullmatch(r'\s*\[([^\]]+)\][ \t]*', line)
            if match:
                name, section = match.group(1), match.group(1)
                while section in self.sections:
                    section += '\0'
                self.sections[section] = []
                self.section_order.append(section)
                self._section_names[section] = name
                node = SectionNode(name)
                node.raw_section_line = line
            else:
                node = self._parse_line(line, self._section_names.get(section))
            node.line_ending = record[len(line):]
            node._shadowrocket_loaded = True
            node._shadowrocket_baseline_line = line
            (self.header_nodes if section is None else self.sections[section]).append(node)
        if not self.is_module:
            names = set(self._section_names.values())
            has_final = any(isinstance(node, ShadowrocketRuleNode) and node.type.upper() == 'FINAL'
                            for key in self._section_keys('Rule') for node in self.sections[key])
            self.file_role = ('full-profile' if names & {'General', 'Proxy', 'Proxy Group'} or has_final
                              else ('mitm-fragment' if names == {'MITM'} else 'configuration-fragment'))

    def _parse_line(self, line, section):
        if not line.strip():
            return BlankNode(line)
        if line.lstrip().startswith(('#', ';', '//')):
            return CommentNode(line)
        if section == 'MITM' and re.match(r'\s*hostname(?:-disabled)?\s*=', line):
            try:
                return ShadowrocketMITMNode(line)
            except ValueError:
                return ShadowrocketUnknownNode(line)
        if section == 'URL Rewrite':
            try:
                return ShadowrocketRewriteNode(line)
            except ValueError:
                pass
        if section == 'Script':
            try:
                return ShadowrocketScriptNode(line)
            except ValueError:
                pass
        if section == 'Rule':
            try:
                return ShadowrocketRuleNode(line)
            except ValueError:
                pass
        return ShadowrocketUnknownNode(line) if section in {
            None, 'Rule', 'URL Rewrite', 'Script', 'Map Local', 'Header Rewrite', 'Body Rewrite'} else CommentNode(line)

    def render_bytes(self):
        nodes = self.header_nodes + [node for key in self.section_order for node in self.sections[key]]
        return serialize_physical_nodes(nodes, newline=self._newline,
            ends_with_newline=self.ends_with_newline, encoding=self.text_encoding, bom=self.text_bom)

    def save(self):
        self.validate()
        self.validate_complete()
        Path(self.filepath).write_bytes(self.render_bytes())

    def modify(self, search, replace, is_regex=False, count=0):
        original, _, _ = decode_text(self.render_bytes())
        updated, _ = _apply_text_replacement(original, search, replace, is_regex, count)
        if updated == original:
            return
        unchanged = Counter((self._section_names.get(key), node.render(), getattr(node, 'line_ending', self._newline))
            for key, nodes in [(None, self.header_nodes)] + [(key, self.sections[key]) for key in self.section_order]
            for node in nodes)
        self._parse_text(updated)
        for key, nodes in [(None, self.header_nodes)] + [(key, self.sections[key]) for key in self.section_order]:
            for node in nodes:
                identity = self._section_names.get(key), node.render(), node.line_ending
                if unchanged[identity]:
                    unchanged[identity] -= 1
                else:
                    node._shadowrocket_loaded = False
        self.validate()
        self._changed()

    def validate_complete(self):
        self.validate()
        super().validate_complete()

    def _section_keys(self, name):
        return [key for key in self.section_order if self._section_names[key] == name]

    def _ensure_section(self, name):
        if name not in self.sections:
            self.sections[name] = [SectionNode(name)]
            self.section_order.append(name)
            self._section_names[name] = name

    def _insert_index(self, section, insert):
        self._ensure_section(section)
        index = calculate_insert_index(self.sections[section], insert, True, section)
        if section == 'Rule':
            final = next((i for i, node in enumerate(self.sections[section])
                          if isinstance(node, ShadowrocketRuleNode) and node.type.upper() == 'FINAL'), None)
            if final is not None:
                if insert is None:
                    index = final
                elif index > final:
                    raise ValueError('Shadowrocket routing insertion must remain before FINAL')
        return index

    def _changed(self):
        self.is_dirty = True
        self.update_metadata(only_if_changed=True)

    def update_metadata(self, *, only_if_changed=False):
        metadata_before = self.render_bytes() if not only_if_changed else None
        counts = Counter()
        for key in self.section_order:
            for node in self.sections[key]:
                if isinstance(node, ShadowrocketRuleNode):
                    counts[node.type.lower()] += 1
                elif isinstance(node, ShadowrocketMITMNode) and node.key == 'hostname':
                    counts['mitm'] += len(node.hostnames)
                elif isinstance(node, ShadowrocketScriptNode):
                    counts[node.fields.get('type', 'generic') + '-script'] += 1
                elif isinstance(node, ShadowrocketRewriteNode):
                    counts['reject' if node.mode.lower() in REJECTS else 'redirect'] += 1
                elif self._section_names[key] == 'General':
                    match = re.fullmatch(r'\s*force-http-engine-hosts\s*=\s*(.*)', split_comment(node.render())[0])
                    if match:
                        value = re.sub(r'^%(APPEND|INSERT)%\s*', '', match.group(1))
                        counts['force-http-engine-hosts'] += sum(bool(host.strip()) for host in value.split(','))
        from rule_framework.metadata import restore_unchanged_ini_metadata, remember_ini_metadata
        if only_if_changed and restore_unchanged_ini_metadata(self, counts):
            return
        now = _get_now(self)
        for node in self.header_nodes:
            if not isinstance(node, CommentNode):
                continue
            match = (re.fullmatch(r'(\s*#!([\w-]+)\s*=\s*)(.*?)([ \t]*)', node.render())
                     or re.fullmatch(r'(\s*#\s+([\w-]+):\s*)(.*?)([ \t]*)', node.render()))
            if match:
                key, value = match.group(2).lower(), UNSET
                if key == 'total':
                    value = str(sum(counts.values()))
                elif key in counts or key in {'and', 'or', 'not', 'domain', 'domain-suffix', 'domain-wildcard', 'domain-keyword', 'url-regex', 'ip-cidr', 'ip-asn', 'reject', 'redirect', 'mitm', 'http-request-script', 'http-response-script', 'cron-script', 'force-http-engine-hosts'}:
                    value = str(counts[key])
                elif key == 'updated':
                    value = now
                elif key == 'desc' and re.fullmatch(r'最后更新时间 \d{4}-\d\d-\d\d \d\d:\d\d:\d\d', match.group(3)):
                    value = '最后更新时间 ' + now
                if value is not UNSET:
                    node.content = match.group(1) + value + match.group(4)
        settings = getattr(self, 'settings', {})
        from rule_framework.metadata import resolve_signature
        author, repo = resolve_signature(settings)
        author_re = re.compile(r'^\s*#!author\s*=\s*(.*?)\s*$' if self.is_module else r'^\s*#\s*AUTHOR:\s*(.*?)\s*$')
        repo_re = re.compile(r'^\s*#!homepage\s*=\s*(.*?)\s*$' if self.is_module else r'^\s*#\s*REPO:\s*(.*?)\s*$')
        authors = [(i, author_re.fullmatch(n.render())) for i, n in enumerate(self.header_nodes)]
        own = next((i for i, match in authors if match and match.group(1) == author), None)
        additions = []
        if own is None:
            additions.append(CommentNode(f'#!author= {author}' if self.is_module else f'# AUTHOR: {author}'))
        if not any((m := repo_re.fullmatch(n.render())) and m.group(1) == repo for n in self.header_nodes):
            additions.append(CommentNode(f'#!homepage= {repo}' if self.is_module else f'# REPO: {repo}'))
        if additions:
            index = own + 1 if own is not None else next((i for i, match in authors if match), 0)
            self.header_nodes[index:index] = additions
        remember_ini_metadata(self, counts, only_if_changed, before=metadata_before)


    def add_url_rewrite(self, raw_content=UNSET, url_pattern=UNSET, reject_type=UNSET,
                        redirect_url=UNSET, status_code=UNSET, insert=None):
        if raw_content is not UNSET:
            single_line(raw_content, 'Shadowrocket raw_content')
            if url_pattern is not UNSET or any(v is not UNSET for v in (reject_type, redirect_url, status_code)):
                raise ValueError('Shadowrocket native and structured rewrite fields conflict')
            self._add_native('URL Rewrite', raw_content, insert)
            return
        single_line(url_pattern, 'Shadowrocket url_pattern')
        self._require_known_header()
        pattern = unquote(url_pattern)
        index = self._insert_index('URL Rewrite', insert)
        if reject_type is not UNSET and reject_type not in REJECTS | {'header'}:
            raise ValueError('Unsupported Shadowrocket rewrite result')
        if reject_type in REJECTS and (redirect_url is not UNSET or status_code is not UNSET):
            raise ValueError('Shadowrocket reject and redirect results conflict')
        if reject_type == 'header' and status_code is not UNSET:
            raise ValueError('Shadowrocket header and redirect status conflict')
        if redirect_url is not UNSET:
            single_line(redirect_url, 'Shadowrocket redirect_url')
        if status_code is not UNSET and (type(status_code) is not int or status_code not in (302, 307)):
            raise ValueError('Shadowrocket redirect status_code must be 302 or 307')
        matching = []
        for key in self._section_keys('URL Rewrite'):
            for node in self.sections[key]:
                if isinstance(node, ShadowrocketRewriteNode) and node.match_pattern == pattern:
                    matching.append(node)
                elif isinstance(node, ShadowrocketUnknownNode):
                    tokens = token_spans(split_comment(node.render())[0])
                    if tokens and unquote(tokens[0].group()) == pattern:
                        raise ValueError('Cannot recognize required Shadowrocket rewrite identity')
        modified = 0
        for node in matching:
            before = node.render()
            if redirect_url is not UNSET:
                node.replacement = redirect_url
                if node.mode.lower() in REJECTS:
                    node.mode = '302'
            if reject_type is not UNSET:
                node.mode = reject_type
                if reject_type in REJECTS:
                    node.replacement = '-'
            if status_code is not UNSET:
                node.mode = str(status_code)
            if node.mode.lower() not in REJECTS and node.replacement in ('_', '-', 'reject'):
                raise ValueError('Shadowrocket redirect/header requires a replacement URL')
            modified += node.render() != before
        if matching:
            logger.info('Shadowrocket rewrite update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self._changed()
            return
        mode = ('302' if redirect_url is not UNSET else 'reject') if reject_type is UNSET else reject_type
        if status_code is not UNSET:
            mode = str(status_code)
        replacement = '-' if mode in REJECTS else redirect_url
        if replacement is UNSET:
            raise ValueError('New Shadowrocket redirect/header requires redirect_url')
        validate_new_regex(pattern)
        self.sections['URL Rewrite'].insert(index, ShadowrocketRewriteNode(
            f'{native_value(pattern)} {native_value(replacement)} {mode}'))
        self._changed()

    add_rewrite = add_url_rewrite

    def add_rule(self, rule_type, value, policy=UNSET, insert=None, *, conditions=UNSET, options=UNSET):
        rule_type = native_rule_type(rule_type, value, client='Shadowrocket')
        validate_standard_value(rule_type, value, client='Shadowrocket')
        self._require_known_header()
        index = self._insert_index('Rule', insert)
        for key in self._section_keys('Rule'):
            for node in self.sections[key]:
                if isinstance(node, ShadowrocketUnknownNode):
                    parts = split_comment(node.render())[0].split(',', 2)
                    if parts[0].strip().upper() == rule_type:
                        if len(parts) < 2 or rule_identity(rule_type, unquote(parts[1].strip()))[:2] == rule_identity(rule_type, value)[:2]:
                            raise ValueError('Cannot recognize required Shadowrocket routing identity')
        selected = condition_options(conditions) if conditions is not UNSET else UNSET
        if selected is not UNSET:
            validate_options(selected, rule_type)
        if options is not UNSET:
            options = validate_options(options, rule_type)
        if policy is not UNSET:
            single_line(policy, 'Shadowrocket policy')
            if any(char in policy for char in ',\r\n\0'):
                raise ValueError('Invalid Shadowrocket policy field')
        candidates = [node for key in self._section_keys('Rule') for node in self.sections[key]
                      if isinstance(node, ShadowrocketRuleNode)
                      and rule_identity(node.type, node.value)[:2] == rule_identity(rule_type, value)[:2]]
        if selected is not UNSET or options is not UNSET:
            for node in candidates:
                validate_options(node.options, rule_type)
        matching = [node for node in candidates if selected is UNSET or node.identity[2] == matching_options(rule_type, selected)]
        modified = 0
        for node in matching:
            before = node.render()
            if policy is not UNSET:
                node.policy = policy
            if options is not UNSET:
                node.options = options
            modified += node.render() != before
        if matching:
            logger.info('Shadowrocket rule update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self._changed()
            return
        actual_options = options if options is not UNSET else (() if selected is UNSET else selected)
        if any(node.identity == shadowrocket_rule_identity(rule_type, value, actual_options)
               and (policy is UNSET or node.policy == policy) for node in candidates):
            return
        if rule_type == 'URL-REGEX':
            validate_new_regex(value)
        node = ShadowrocketRuleNode(','.join([rule_type, native_value(value),
                                             native_value('DIRECT' if policy is UNSET else policy), *actual_options]))
        self.sections['Rule'].insert(index, node)
        self._changed()

    def add_script(self, script, insert=None):
        if isinstance(script, str):
            self._add_native('Script', script, insert)
            return
        if not isinstance(script, dict):
            raise ValueError('Shadowrocket script entries must be dictionaries or native strings')
        unknown = set(script) - {'name'} - {key.replace('-', '_') for key in SCRIPT_FIELDS}
        if unknown:
            raise ValueError(f'Unsupported structured Shadowrocket script fields: {sorted(unknown)}')
        fields = {}
        for key, value in script.items():
            if key == 'name':
                single_line(value, 'Shadowrocket script name')
                if '=' in value:
                    raise ValueError('Shadowrocket script name contains an assignment delimiter')
                continue
            native = key.replace('_', '-')
            if native == 'requires-body':
                if type(value) is not bool:
                    raise ValueError('Shadowrocket requires_body must be a Boolean')
                value = str(value).lower()
            else:
                single_line(value, 'Shadowrocket ' + key)
            fields[native] = value.replace('_', '-') if native == 'type' else value
        stage = fields.get('type')
        if stage not in ('http-request', 'http-response', 'cron'):
            raise ValueError('Structured Shadowrocket script type requires HTTP request/response or cron')
        condition = 'cronexp' if stage == 'cron' else 'pattern'
        single_line(fields.get(condition), 'Shadowrocket ' + condition)
        fields[condition] = unquote(fields[condition])
        self._require_known_header()
        index = self._insert_index('Script', insert)
        for key in self._section_keys('Script'):
            for node in self.sections[key]:
                if isinstance(node, ShadowrocketUnknownNode):
                    raise ValueError('Cannot recognize required Shadowrocket script identity')
                if isinstance(node, ShadowrocketScriptNode) and node.fields.get(condition) == fields[condition] and node.fields.get('type') not in ('http-request', 'http-response', 'cron'):
                    raise ValueError('Cannot recognize required Shadowrocket script matching semantics')
        matching = [node for key in self._section_keys('Script') for node in self.sections[key]
                    if isinstance(node, ShadowrocketScriptNode) and node.identity == (stage, fields[condition])]
        modified = 0
        for node in matching:
            updated = dict(node.fields, **fields)
            validate_script(updated)
            before = node.render()
            node.fields = updated
            if 'name' in script:
                node.name = script['name']
            modified += node.render() != before
        if matching:
            logger.info('Shadowrocket script update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self._changed()
            return
        validate_script(fields)
        if stage != 'cron':
            validate_new_regex(fields['pattern'])
        name = script.get('name') or Path(fields['script-path'].split('?', 1)[0]).name
        single_line(name, 'Shadowrocket script name')
        node = ShadowrocketScriptNode(name + ' = ' + ','.join(key + '=' + native_value(value) for key, value in fields.items()))
        self.sections['Script'].insert(index, node)
        self._changed()

    def _host_match(self, pattern, value, section, index):
        try:
            references = url_host_references(pattern)
        except ReferenceRecognitionError as error:
            raise ValueError(f'Cannot recognize required Shadowrocket URL host reference at {self.filepath} [{section}]:{index}: {error}') from error
        return value is None or references.contains(value)

    def remove_rule(self, rule_type, value=None, *, conditions=UNSET):
        from rule_framework.native_input import guard_required_rule_semantics
        guard_required_rule_semantics(self, rule_type, value)
        self._require_known_header()
        types = select_rule_types(rule_type)
        if rule_type == 'domain' and value is not None:
            validate_domain_selector(value)
        selected_conditions = condition_options(conditions) if conditions is not UNSET else UNSET
        removed = 0
        for key in self.section_order:
            section = self._section_names[key]
            retained = []
            for index, node in enumerate(self.sections[key], 1):
                selected = False
                if section == 'Rule' and isinstance(node, ShadowrocketRuleNode):
                    if node.type.upper() in types:
                        selected = value is None or (canonical_domain(node.value) == canonical_domain(value)
                                                     if rule_type == 'domain' else node.value == value)
                    elif rule_type == 'domain' and node.type.upper() == 'URL-REGEX':
                        selected = self._host_match(unquote(node.value), value, section, index)
                    elif rule_type == 'domain' and node.type.upper() in {'AND', 'OR', 'NOT'}:
                        from rule_framework.logical_refs import logical_reference_matches
                        selected = logical_reference_matches(node.type, node.value, value, client=self.client,
                            location=f'{self.filepath} [{section}]:{index}')
                    elif rule_type == 'domain' and node.type.upper() not in STANDARD_TYPES | {'FINAL', 'RULE-SET', 'DOMAIN-SET', 'SCRIPT', 'DST-PORT'}:
                        raise ValueError(f'Cannot recognize required Shadowrocket routing reference in {node.type!r}')
                    if selected and selected_conditions is not UNSET:
                        validate_options(node.options, node.type.upper())
                        selected = node.identity[2] == matching_options(node.type.upper(), selected_conditions)
                elif rule_type == 'domain':
                    if isinstance(node, ShadowrocketRewriteNode):
                        selected = self._host_match(node.match_pattern, value, section, index)
                    elif isinstance(node, ShadowrocketScriptNode):
                        stage = node.fields.get('type')
                        if stage in ('http-request', 'http-response'):
                            from rule_framework.native_input import guard_required_script_fields
                            guard_required_script_fields(self, node.fields)
                            selected = self._host_match(node.fields.get('pattern'), value, section, index)
                        elif stage not in ('cron', 'event', 'rule', 'dns') or 'pattern' in node.fields:
                            raise ValueError(f'Cannot recognize required Shadowrocket script matching semantics at {self.filepath} [{section}]:{index}')
                    elif isinstance(node, ShadowrocketMITMNode):
                        hosts = [host for host in node.hostnames if value is not None and mitm_reference(host) != canonical_domain(value)]
                        if hosts != node.hostnames:
                            removed += len(node.hostnames) - len(hosts)
                            node.hostnames = hosts
                        selected = not hosts
                    elif isinstance(node, ShadowrocketUnknownNode):
                        raise ValueError(f'Cannot recognize required Shadowrocket domain reference at {self.filepath} [{section}]:{index}: {node.render()!r}')
                    elif node.render().lstrip().startswith('#!include') and section in ('Rule', 'URL Rewrite', 'Script', 'MITM', 'Map Local', 'Header Rewrite', 'Body Rewrite'):
                        raise ValueError(f'External Shadowrocket include domain references are unknown at {self.filepath} [{section}]:{index}')
                elif isinstance(node, ShadowrocketUnknownNode) and section == 'Rule':
                    first = node.render().split(',', 1)[0].strip().upper()
                    if first in types:
                        raise ValueError('Cannot recognize required Shadowrocket rule selector')
                if selected:
                    removed += 1
                else:
                    retained.append(node)
            self.sections[key] = retained
        if removed:
            self._changed()
        logger.info('Shadowrocket domain/rule removal matched=%s in %s', removed, self.filepath)

    def add_mitm(self, hostnames, insert=None):
        self._require_known_header()
        if not isinstance(hostnames, list) or not hostnames:
            raise ValueError('Shadowrocket MITM hostnames require a non-empty list')
        for host in hostnames:
            mitm_reference(host)
        index = self._insert_index('MITM', insert)
        nodes = [node for key in self._section_keys('MITM') for node in self.sections[key]]
        if any(isinstance(node, ShadowrocketUnknownNode) for node in nodes):
            raise ValueError('Cannot recognize required Shadowrocket MITM declaration')
        matching = [node for node in nodes if isinstance(node, ShadowrocketMITMNode) and node.key == 'hostname']
        existing = {canonical_domain(host) for node in matching for host in node.hostnames}
        added = []
        for host in hostnames:
            if canonical_domain(host) not in existing:
                added.append(host)
                existing.add(canonical_domain(host))
        if not added:
            return
        if matching:
            node = matching[0]
            separator = ', ' if ', ' in node.raw_content else ','
            node.hostnames.extend(added)
            node.raw_hosts.extend(separator[1:] + host for host in added)
        else:
            prefix = 'hostname = %APPEND% ' if self.is_module else 'hostname = '
            self.sections['MITM'].insert(index, ShadowrocketMITMNode(prefix + ', '.join(added)))
        self._changed()

    def remove_mitm(self, hostnames):
        self._require_known_header()
        if isinstance(hostnames, str):
            hostnames = [hostnames]
        if not isinstance(hostnames, list) or not hostnames:
            raise ValueError('Shadowrocket MITM selectors require a non-empty list')
        selectors = {mitm_reference(host) for host in hostnames}
        removed = 0
        for key in self._section_keys('MITM'):
            retained = []
            for node in self.sections[key]:
                if isinstance(node, ShadowrocketUnknownNode):
                    raise ValueError('Cannot recognize required Shadowrocket MITM declaration')
                if isinstance(node, ShadowrocketMITMNode):
                    hosts = [host for host in node.hostnames if mitm_reference(host) not in selectors]
                    removed += len(node.hostnames) - len(hosts)
                    node.hostnames = hosts
                    if not hosts:
                        continue
                retained.append(node)
            self.sections[key] = retained
        if removed:
            self._changed()

    def remove_rewrite(self, pattern):
        self._require_known_header()
        single_line(pattern, 'Shadowrocket rewrite pattern selector')
        pattern = unquote(pattern)
        removed = 0
        for key in self._section_keys('URL Rewrite'):
            retained = []
            for node in self.sections[key]:
                if isinstance(node, ShadowrocketRewriteNode) and node.match_pattern == pattern:
                    removed += 1
                    continue
                if isinstance(node, ShadowrocketUnknownNode):
                    first = token_spans(split_comment(node.render())[0])
                    if first and unquote(first[0].group()) == pattern:
                        raise ValueError('Cannot recognize required Shadowrocket rewrite selector')
                retained.append(node)
            self.sections[key] = retained
        if removed:
            self._changed()
        logger.info('Shadowrocket rewrite removal matched=%s in %s', removed, self.filepath)

    def remove_script(self, name=None, pattern=None, script_path=None):
        self._require_known_header()
        if all(value is None for value in (name, pattern, script_path)):
            raise ValueError('Shadowrocket script removal requires a name, pattern or script_path selector')
        for field, value in (('name', name), ('pattern', pattern), ('script_path', script_path)):
            if value is not None:
                single_line(value, 'Shadowrocket ' + field)
        removed = 0
        for key in self._section_keys('Script'):
            retained = []
            for node in self.sections[key]:
                if isinstance(node, ShadowrocketScriptNode):
                    selected = ((name is None or node.name == name)
                                and (pattern is None or node.fields.get('pattern') == unquote(pattern))
                                and (script_path is None or node.fields.get('script-path') == script_path))
                    if selected:
                        removed += 1
                        continue
                elif isinstance(node, ShadowrocketUnknownNode):
                    label = node.render().split('=', 1)[0].strip()
                    if name is None or label == name:
                        raise ValueError('Cannot recognize required Shadowrocket script selector')
                retained.append(node)
            self.sections[key] = retained
        if removed:
            self._changed()
        logger.info('Shadowrocket script removal matched=%s in %s', removed, self.filepath)

    def _add_native(self, section, content, insert=None):
        from rule_framework.native_input import validate_native_entry
        native_scope = validate_native_entry(self, content, kind='declaration', section=section)
        single_line(content, 'Shadowrocket native input')
        if re.match(r'\s*\[', content):
            raise ValueError('Shadowrocket native section headers require a text/Hook operation')
        index = self._insert_index(section, insert)
        node = self._parse_line(content, section)
        if native_scope == ('known-fields', 'known-fields'):
            if isinstance(node, ShadowrocketRuleNode):
                matching = [item for key in self._section_keys('Rule') for item in self.sections[key]
                            if isinstance(item, ShadowrocketRuleNode) and item.identity == node.identity]
                modified = 0
                for item in matching:
                    before = item.render()
                    item.policy = node.policy
                    modified += item.render() != before
                if matching:
                    logger.info('Shadowrocket rule update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
            elif isinstance(node, ShadowrocketRewriteNode):
                matching = []
                for key in self._section_keys('URL Rewrite'):
                    for item in self.sections[key]:
                        if isinstance(item, ShadowrocketRewriteNode) and item.match_pattern == node.match_pattern:
                            matching.append(item)
                        elif isinstance(item, ShadowrocketUnknownNode):
                            tokens = token_spans(split_comment(item.render())[0])
                            if tokens and unquote(tokens[0].group()) == node.match_pattern:
                                raise ValueError('Cannot recognize required Shadowrocket rewrite identity')
                modified = 0
                for item in matching:
                    before = item.render()
                    item.replacement = node.replacement
                    item.mode = node.mode
                    modified += item.render() != before
                if matching:
                    logger.info('Shadowrocket rewrite update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
            elif isinstance(node, ShadowrocketScriptNode):
                for key in self._section_keys('Script'):
                    for item in self.sections[key]:
                        if isinstance(item, ShadowrocketUnknownNode) and unknown_script_requires_identity(item.render(), node.identity):
                            raise ValueError('Cannot recognize the required Shadowrocket script identity')
                matching = [item for key in self._section_keys('Script') for item in self.sections[key]
                            if isinstance(item, ShadowrocketScriptNode) and item.identity == node.identity]
                modified = 0
                for item in matching:
                    updated = dict(item.fields, **node.fields)
                    validate_script(updated)
                    before = item.render()
                    item.fields = updated
                    item.name = node.name
                    modified += item.render() != before
                if matching:
                    logger.info('Shadowrocket script update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
        if any(item.render() == content for key in self._section_keys(section) for item in self.sections[key]):
            return
        node._native_input = native_scope[1] != 'known-fields'
        if native_scope[1] == 'unknown':
            node._opaque_native_line = content
        node._shadowrocket_native_line = content
        self.sections[section].insert(index, node)
        self._changed()

    def add_native_rule(self, content, insert=None):
        self._add_native('Rule', content, insert)

    def validate(self):
        super().validate()
        from rule_framework.managed_validation import validate_passive_node
        if self.client != 'Shadowrocket' or self.file_role not in {
            'module', 'full-profile', 'configuration-fragment', 'mitm-fragment'}:
            raise ValueError('Invalid managed Shadowrocket client/file role')
        if self._newline not in ('\n', '\r\n', '\r') or type(self.is_dirty) is not bool:
            raise ValueError('Invalid managed Shadowrocket newline/dirty state')
        if not isinstance(self._section_names, dict) or set(self._section_names) != set(self.sections):
            raise ValueError('Shadowrocket section identity must match the managed section map')
        if len(self.section_order) != len(set(self.section_order)) or set(self.section_order) != set(self.sections):
            raise ValueError('Shadowrocket section order must include every section exactly once')
        for node in self.header_nodes:
            changed = not getattr(node, '_shadowrocket_loaded', False) or node.render() != getattr(node, '_shadowrocket_baseline_line', None)
            if isinstance(node, ShadowrocketUnknownNode) and changed:
                raise ValueError('Changed Shadowrocket opaque header requires recognizable syntax')
            validate_passive_node(node, changed=changed)
        for key in self.section_order:
            section = self._section_names[key]
            nodes = self.sections[key]
            headers = [node for node in nodes if isinstance(node, SectionNode)]
            if (len(headers) != 1 or not nodes or nodes[0] is not headers[0]
                    or headers[0].name != section
                    or not re.fullmatch(r'\s*\[' + re.escape(section) + r'\][ \t]*', getattr(headers[0], 'raw_section_line', headers[0].render()))):
                raise ValueError('Shadowrocket section header must match its managed section and appear first')
            for node in nodes:
                if not isinstance(node, ASTNode):
                    raise ValueError('Managed Shadowrocket sections require AST nodes')
                if getattr(node, 'line_ending', self._newline) not in ('', '\n', '\r\n', '\r'):
                    raise ValueError('Invalid managed Shadowrocket node newline')
                if isinstance(node, SectionNode) and node.name != section:
                    raise ValueError('Shadowrocket section header and identity differ')
                changed = not getattr(node, '_shadowrocket_loaded', False) or node.render() != getattr(node, '_shadowrocket_baseline_line', None)
                if not changed:
                    continue
                if getattr(node, '_native_input', False) and node.render() == getattr(node, '_shadowrocket_native_line', None):
                    continue
                validate_passive_node(node, changed=changed)
                if isinstance(node, ShadowrocketRewriteNode):
                    single_line(node.match_pattern, 'Shadowrocket URL Rewrite pattern')
                    single_line(node.replacement, 'Shadowrocket URL Rewrite replacement')
                    if node.mode not in REWRITE_MODES:
                        raise ValueError('Invalid Shadowrocket URL Rewrite mode')
                    if node.mode not in REJECTS and node.replacement in ('_', '-', 'reject'):
                        raise ValueError('Shadowrocket redirect/header requires replacement URL')
                    if node.match_pattern != node._baseline[0] or not getattr(node, '_shadowrocket_loaded', False):
                        validate_new_regex(node.match_pattern)
                elif isinstance(node, ShadowrocketScriptNode):
                    single_line(node.name, 'Shadowrocket script name')
                    if '=' in node.name:
                        raise ValueError('Invalid Shadowrocket script name')
                    validate_script(node.fields)
                    if node.fields['type'].startswith('http-') and (node.fields['pattern'] != node._baseline.get('pattern') or not getattr(node, '_shadowrocket_loaded', False)):
                        validate_new_regex(node.fields['pattern'])
                elif isinstance(node, ShadowrocketRuleNode):
                    if (node.type.upper() == 'FINAL') != (node._baseline[0].upper() == 'FINAL'):
                        raise ValueError('Shadowrocket FINAL and condition rules require separate native layouts')
                    single_line(node.policy, 'Shadowrocket policy')
                    if any(token in node.policy for token in ',\r\n\0'):
                        raise ValueError('Invalid Shadowrocket policy field')
                    if node.type.upper() != 'FINAL':
                        validate_standard_value(node.type.upper(), unquote(node.value), client='Shadowrocket')
                        if node.type.upper() == 'URL-REGEX' and (node.value != node._baseline[1] or not getattr(node, '_shadowrocket_loaded', False)):
                            validate_new_regex(unquote(node.value))
                    if tuple(node.options) != node._baseline[3] or not getattr(node, '_shadowrocket_loaded', False):
                        validate_options(node.options, node.type.upper())
                elif isinstance(node, ShadowrocketMITMNode):
                    if not isinstance(node.hostnames, list):
                        raise ValueError('Shadowrocket MITM hostnames require a list')
                    for host in node.hostnames:
                        mitm_reference(host)
                elif isinstance(node, ShadowrocketUnknownNode):
                    raise ValueError(f'Changed Shadowrocket content requires recognizable syntax in [{section}]')
        encode_text('', self.text_encoding, self.text_bom)

    def _require_known_header(self):
        if any(isinstance(node, ShadowrocketUnknownNode) or node.render().lstrip().startswith('#!include')
               for node in self.header_nodes):
            raise ValueError(f'Cannot recognize required Shadowrocket sectionless/external context in {self.filepath}')

    def scaffold(self, base_name):
        single_line(base_name, 'Shadowrocket file name')
        now = _get_now(self)
        if self.is_module:
            self._parse_text(f'#!name={base_name}\n#!desc=最后更新时间 {now}\n#!total=0\n')
        else:
            self._parse_text(f'# NAME: {base_name}\n# UPDATED: {now}\n# TOTAL: 1\n[Rule]\nFINAL,DIRECT\n')
            self.file_role = 'full-profile'
        self._changed()

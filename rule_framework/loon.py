"""Lossless Loon configuration, plugin and script declaration maintenance."""
from rule_framework.text_json import split_physical_lines
from pathlib import Path
import re
import logging

from rule_framework.ast import BlankNode, CommentNode, SectionNode, RewriteNode, ScriptNode, get_comma_indices_at_depth_0
from rule_framework.fom import PluginFile, _get_now
from rule_framework.text_json import decode_text, encode_text, serialize_physical_nodes
from rule_framework.surge import SurgeRuleNode, SurgeMITMNode, single_line, native_value, validate_new_regex, split_comment, token_spans, unquote, validate_cron
from rule_framework.rule_helpers import (UNSET, native_rule_type, validate_standard_value,
    condition_options, validate_options, rule_identity, calculate_insert_index, select_rule_types,
    validate_domain_selector, STANDARD_TYPES)
from rule_framework.domain_refs import canonical_domain, url_host_references, ReferenceRecognitionError

logger = logging.getLogger('RuleFramework')


class LoonRuleNode(SurgeRuleNode):
    """Shared comma layout; plugin policy omission means DIRECT in Loon."""

    def __init__(self, line, *, allow_implicit_policy=False):
        content, comment = split_comment(line)
        fields = get_comma_indices_at_depth_0(content)
        self._implicit_raw = None
        if len(fields) == 1 and content.split(',', 1)[0].strip().upper() != 'FINAL' and allow_implicit_policy:
            self._implicit_raw = line
            super().__init__(content + ',DIRECT' + comment)
        else:
            super().__init__(line)

    def render(self):
        if self._implicit_raw is not None and (self.type, self.value, self.policy, tuple(self.options)) == self._baseline:
            return self._implicit_raw
        return super().render()



REJECTS = {'reject', 'reject-200', 'reject-img', 'reject-dict', 'reject-array'}
REWRITE_MODES = REJECTS | {'header', '302', '307'}


class LoonUnknownNode(CommentNode):
    """Untouched content whose required structured meaning is unknown."""


class LoonRewriteNode(RewriteNode):
    def __init__(self, line):
        content, self.inline_comment = split_comment(line)
        self.spans = token_spans(content)
        values = [unquote(item.group()) for item in self.spans]
        if len(values) == 3 and values[2] in REWRITE_MODES:
            self.layout, self.replacement, self.mode = 'corpus', values[1], values[2]
        elif len(values) == 3 and values[1] in {'302', '307', 'header'}:
            self.layout, self.replacement, self.mode = 'documented', values[2], values[1]
        elif len(values) == 2 and values[1] in REJECTS:
            self.layout, self.replacement, self.mode = 'documented', '', values[1]
        else:
            raise ValueError('Unrecognizable Loon legacy rewrite fields')
        super().__init__(content, values[0])
        self._baseline = (self.match_pattern, self.replacement, self.mode)

    def render(self):
        if (self.match_pattern, self.replacement, self.mode) == self._baseline:
            return self.content + self.inline_comment
        fields = ([self.match_pattern, self.replacement, self.mode] if self.layout == 'corpus'
                  else [self.match_pattern, self.mode] + ([] if self.mode in REJECTS else [self.replacement]))
        result = self.content[:self.spans[0].start()]
        for index, value in enumerate(fields):
            if index:
                result += (self.content[self.spans[index-1].end():self.spans[index].start()]
                           if index < len(self.spans) else ' ')
            old = self.spans[index].group() if index < len(self.spans) else ''
            result += old if unquote(old) == value else native_value(value, quoted=old.startswith(('"', "'")))
        return result + self.content[self.spans[-1].end():] + self.inline_comment


class LoonMITMNode(SurgeMITMNode):
    """Comma layout only; Loon generation uses its direct hostname assignment."""


def mitm_reference(value):
    single_line(value, 'Loon MITM hostname')
    host = value[1:] if value.startswith('-') else value
    if not host or re.search(r'[\s,%{}=/:#]', host):
        raise ValueError('Unrecognizable Loon MITM hostname reference')
    return canonical_domain(host)


SCRIPT_FIELDS = {'type', 'pattern', 'cronexp', 'script-path', 'tag', 'timeout',
                 'argument', 'requires-body', 'binary-body-mode', 'enable', 'img-url'}
SCRIPT_BOOLS = {'requires-body', 'binary-body-mode', 'enable'}


class LoonScriptNode(ScriptNode):
    def __init__(self, line):
        content, self.inline_comment = split_comment(line)
        spans = token_spans(content)
        if len(spans) < 3 or spans[0].group() not in ('http-request', 'http-response', 'cron'):
            raise ValueError('Unrecognizable Loon positional script')
        self.stage_span, self.condition_span = spans[0].span(), spans[1].span()
        stage, condition = spans[0].group(), unquote(spans[1].group())
        condition_key = 'cronexp' if stage == 'cron' else 'pattern'
        self.fields = {'type': stage, condition_key: condition}
        self.field_spans = {}
        start = spans[1].end()
        self.option_start = start
        options = content[start:]
        boundaries = [-1, *get_comma_indices_at_depth_0(options), len(options)]
        for index in range(len(boundaries) - 1):
            offset, end = boundaries[index] + 1, boundaries[index + 1]
            raw = options[offset:end]
            match = re.fullmatch(r'(\s*)([\w-]+)(\s*=\s*)(.*?)([ \t]*)', raw)
            if not match or not match.group(4):
                raise ValueError('Unrecognizable Loon script option')
            key, value = match.group(2), match.group(4)
            if value.startswith(('"', "'")):
                quote, escaped, closed = value[0], False, False
                for position, char in enumerate(value[1:], 1):
                    if escaped:
                        escaped = False
                    elif char == '\\':
                        escaped = True
                    elif char == quote:
                        if position != len(value) - 1:
                            raise ValueError('Unexpected text after quoted Loon script option')
                        closed = True
                        break
                if not closed:
                    raise ValueError('Unclosed quoted Loon script option')
            if key in self.fields:
                raise ValueError('Duplicate Loon script option')
            self.fields[key] = unquote(value)
            self.field_spans[key] = (start + offset + match.start(4), start + offset + match.end(4))
        super().__init__(content, None if stage == 'cron' else condition, name=self.fields.get('tag'))
        self._baseline = dict(self.fields)

    @property
    def identity(self):
        enabled = self.fields.get('enable', 'true')
        if enabled not in ('true', 'false', '1', '0'):
            raise ValueError('Loon enable execution condition requires a Boolean')
        return (self.fields['type'], self.fields.get('cronexp' if self.fields['type'] == 'cron' else 'pattern'),
                enabled in ('true', '1'))

    def render(self):
        result = self.content
        spans = dict(self.field_spans, type=self.stage_span)
        condition = 'cronexp' if self.fields['type'] == 'cron' else 'pattern'
        spans[condition] = self.condition_span
        for key, (start, end) in sorted(spans.items(), key=lambda item: item[1][0], reverse=True):
            value = self.fields[key]
            if value == self._baseline.get(key):
                continue
            old = self.content[start:end]
            result = result[:start] + native_value(value, quoted=old.startswith(('"', "'"))) + result[end:]
        for key, value in self.fields.items():
            if key not in spans:
                result = result.rstrip() + ',' + key + '=' + native_value(value)
        return result + self.inline_comment


def validate_script(fields):
    if not isinstance(fields, dict) or any(not isinstance(value, str) for value in fields.values()):
        raise ValueError('Loon script fields must be string values')
    unknown = set(fields) - SCRIPT_FIELDS
    if unknown:
        raise ValueError(f'Unrecognized Loon script options required by mutation: {sorted(unknown)}')
    stage = fields.get('type')
    if stage not in ('http-request', 'http-response', 'cron'):
        raise ValueError('Loon structured script type requires HTTP request/response or cron')
    single_line(fields.get('script-path'), 'script_path')
    if stage == 'cron':
        validate_cron(fields.get('cronexp'))
        if set(fields) & {'pattern', 'requires-body', 'binary-body-mode'}:
            raise ValueError('Loon cron scripts cannot contain HTTP match/body options')
    else:
        single_line(fields.get('pattern'), 'pattern')
        if 'cronexp' in fields:
            raise ValueError('Loon HTTP scripts cannot contain a cron schedule')
    for key in SCRIPT_BOOLS & fields.keys():
        if fields[key] not in ('1', '0', 'true', 'false'):
            raise ValueError(f'Loon {key} requires a Boolean')
    if 'timeout' in fields:
        import math
        try:
            timeout = float(fields['timeout'])
        except (ValueError, TypeError) as error:
            raise ValueError('Loon timeout must be positive and finite') from error
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('Loon timeout must be positive and finite')
    for key in ('tag', 'argument', 'img-url'):
        if key in fields:
            single_line(fields[key], key, empty=key == 'argument')


class LoonFile(PluginFile):
    transaction_fields = PluginFile.transaction_fields + (
        'client', 'file_role', 'text_encoding', 'text_bom', '_newline',
        '_section_names', '_baseline_text',
    )

    def __init__(self, filepath):
        super().__init__(filepath)
        self.client = 'Loon'
        suffix = Path(filepath).suffix.lower()
        self.file_role = ('script-declarations' if suffix == '.lnscript' else
                          'plugin' if suffix in ('.plugin', '.lnplugin') else 'configuration-fragment')
        self.text_encoding, self.text_bom = 'utf-8', b''
        self._newline = '\n'
        self._section_names = {}
        self._baseline_text = ''
        self.ends_with_newline = True

    @property
    def is_module(self):
        return self.file_role == 'plugin'

    def load(self):
        text, self.text_encoding, self.text_bom = decode_text(Path(self.filepath).read_bytes())
        self._parse_text(text)
        self._baseline_text = text
        self._metadata_baseline = self.render_bytes()
        self.is_dirty = False

    def _parse_text(self, text):
        self.header_nodes, self.sections, self.section_order, self._section_names = [], {}, [], {}
        self.ends_with_newline = text.endswith(('\n', '\r'))
        records = split_physical_lines(text)
        self._newline = next((record[len(record.rstrip('\r\n')):] for record in records
                              if record.endswith(('\n', '\r'))), self._newline)
        section = None
        for record in records:
            line = record.rstrip('\r\n')
            match = re.fullmatch(r'\s*\[([^\]]+)\][ \t]*', line)
            if match:
                name = match.group(1)
                section = name
                while section in self.sections:
                    section += '\0'
                node = SectionNode(name)
                node.raw_section_line = line
                self.sections[section] = []
                self.section_order.append(section)
                self._section_names[section] = name
            else:
                node = self._parse_line(line, self._section_names.get(section))
            node.line_ending = record[len(line):]
            node._loon_loaded = True
            node._loon_baseline_line = line
            if section is None:
                self.header_nodes.append(node)
            else:
                self.sections[section].append(node)

        if self.file_role not in ('plugin', 'script-declarations'):
            names = {name.lower() for name in self._section_names.values()}
            self.file_role = 'full-profile' if names & {'general', 'proxy', 'proxy group'} or any(
                isinstance(node, LoonRuleNode) and node.type.upper() == 'FINAL'
                for nodes in self.sections.values() for node in nodes) else 'configuration-fragment'

    def _parse_line(self, line, section):
        if not line.strip():
            return BlankNode(line)
        if line.lstrip().startswith(('#', ';', '//')):
            return CommentNode(line)
        if section is None and self.file_role == 'script-declarations' and re.match(r'\s*(?:request|response)\s+if\b', line):
            return LoonUnknownNode(line)
        if section and section.lower() == 'rule':
            try:
                return LoonRuleNode(line, allow_implicit_policy=self.is_module)
            except ValueError:
                pass
        if (section and section.lower() == 'mitm') or (section is None and self.file_role == 'script-declarations'):
            if re.match(r'\s*hostname\s*=', line):
                try:
                    return LoonMITMNode(line)
                except ValueError:
                    return LoonUnknownNode(line)
        if (section and section.lower() == 'script') or (section is None and self.file_role == 'script-declarations'
                and line.lstrip().startswith(('http-', 'cron '))):
            try:
                return LoonScriptNode(line)
            except ValueError:
                return LoonUnknownNode(line)
        if section and section.lower() in ('rewrite', 'url rewrite'):
            try:
                return LoonRewriteNode(line)
            except ValueError:
                pass
        return LoonUnknownNode(line) if section and section.lower() in ('rule', 'rewrite', 'url rewrite', 'script') else CommentNode(line)

    def render_bytes(self):
        nodes = self.header_nodes + [node for key in self.section_order for node in self.sections[key]]
        return serialize_physical_nodes(nodes, newline=self._newline,
            ends_with_newline=self.ends_with_newline, encoding=self.text_encoding, bom=self.text_bom)

    def save(self):
        self.validate()
        self.validate_complete()
        Path(self.filepath).write_bytes(self.render_bytes())


    def _keys(self, section):
        names = {'rewrite', 'url rewrite'} if section.lower() == 'rewrite' else {section.lower()}
        return [key for key in self.section_order if self._section_names[key].lower() in names]

    def _insert_index(self, section, insert):
        if self.file_role == 'script-declarations':
            if section not in ('Script', 'MITM'):
                raise ValueError('Sectionless Loon script declarations require Script/MITM operations')
            index = calculate_insert_index(self.header_nodes, insert)
            if insert is None and section == 'Script':
                index = next((i for i, node in enumerate(self.header_nodes)
                              if re.match(r'\s*hostname\s*=', node.render())), len(self.header_nodes))
            return self.header_nodes, index
        keys = self._keys(section)
        key = keys[0] if keys else section
        if isinstance(insert, dict) and isinstance(insert.get('section'), str):
            specified = [candidate for candidate in keys
                         if self._section_names[candidate].lower() == insert['section'].lower()]
            if specified:
                key = specified[0]
                from copy import copy
                insert = copy(insert)
                insert['section'] = self._section_names[key]
        if not keys:
            self.sections[key] = [SectionNode(section)]
            self.section_order.append(key)
            self._section_names[key] = section
        nodes = self.sections[key]
        index = calculate_insert_index(nodes, insert, True, self._section_names[key])
        if section == 'Rule':
            terminal = next((i for i, node in enumerate(nodes) if isinstance(node, LoonRuleNode)
                             and node.type.upper() == 'FINAL'), None)
            if terminal is not None:
                if insert is None:
                    index = terminal
                elif index > terminal:
                    raise ValueError('Loon routing insertion must remain before FINAL')
        return nodes, index

    def _changed(self):
        self.is_dirty = True
        self.update_metadata(only_if_changed=True)

    def update_metadata(self, *, only_if_changed=False):
        metadata_before = self.render_bytes() if not only_if_changed else None
        from collections import Counter
        counts = Counter()
        for _, _, nodes in self._collections():
            for node in nodes:
                if isinstance(node, LoonRuleNode):
                    counts[node.type.lower()] += 1
                elif isinstance(node, LoonRewriteNode):
                    counts['reject' if node.mode in REJECTS else 'redirect'] += 1
                elif isinstance(node, LoonScriptNode):
                    counts[node.fields['type'] + '-script'] += 1
                elif isinstance(node, LoonMITMNode):
                    counts['mitm'] += len(node.hostnames)
                elif isinstance(node, LoonUnknownNode) and getattr(node, '_native_input', False):
                    counts['native'] += 1
        total = sum(counts.values())
        from rule_framework.metadata import restore_unchanged_ini_metadata, remember_ini_metadata
        if only_if_changed and restore_unchanged_ini_metadata(self, counts):
            return
        now = _get_now(self)
        for node in self.header_nodes:
            if not isinstance(node, CommentNode):
                continue
            line = node.render()
            match = (re.fullmatch(r'(\s*#!([\w-]+)\s*=\s*)(.*?)([ \t]*)', line) or
                     re.fullmatch(r'(\s*#(?:!)?\s+([\w-]+):\s*)(.*?)([ \t]*)', line))
            if not match:
                continue
            key = match.group(2).lower()
            value = UNSET
            if key == 'total':
                value = str(total)
            elif key in counts or key in {'and','or','not','domain','domain-suffix','url-regex','reject','redirect','mitm',
                                         'http-request-script','http-response-script','cron-script'}:
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
        prefix = '#!author=' if self.is_module else '# AUTHOR:'
        homepage = '#!homepage=' if self.is_module else '# REPO:'
        author_re = re.compile(r'^\s*#!author\s*=\s*(.*?)\s*$' if self.is_module else r'^\s*#\s*AUTHOR:\s*(.*?)\s*$')
        repo_re = re.compile(r'^\s*#!homepage\s*=\s*(.*?)\s*$' if self.is_module else r'^\s*#\s*REPO:\s*(.*?)\s*$')
        authors = [(i, author_re.fullmatch(node.render())) for i, node in enumerate(self.header_nodes)]
        own = next((i for i, match in authors if match and match.group(1) == author), None)
        additions = []
        if own is None:
            additions.append(CommentNode(f'{prefix} {author}'))
        if not any((match := repo_re.fullmatch(node.render())) and match.group(1) == repo for node in self.header_nodes):
            additions.append(CommentNode(f'{homepage} {repo}'))
        if additions:
            index = own + 1 if own is not None else next((i for i, match in authors if match), 0)
            self.header_nodes[index:index] = additions
        remember_ini_metadata(self, counts, only_if_changed, before=metadata_before)


    def add_rule(self, rule_type, value, policy=UNSET, insert=None, *, conditions=UNSET, options=UNSET):
        rule_type = native_rule_type(rule_type, value, client='Loon')
        validate_standard_value(rule_type, value, client='Loon')
        nodes, index = self._insert_index('Rule', insert)
        selected = condition_options(conditions) if conditions is not UNSET else UNSET
        if selected is not UNSET:
            validate_options(selected, rule_type, 'Loon')
        if options is not UNSET:
            options = validate_options(options, rule_type, 'Loon')
        if policy is not UNSET:
            single_line(policy, 'Loon policy')
            if ',' in policy:
                raise ValueError('Loon policy contains a field delimiter')
            if self.is_module and policy not in {'DIRECT', 'PROXY', 'REJECT', 'REJECT-DROP', 'REJECT-IMG', 'REJECT-DICT', 'REJECT-ARRAY'}:
                raise ValueError('Loon plugin rules require DIRECT, PROXY or a supported REJECT policy')
        matching = [node for key in self._keys('Rule') for node in self.sections[key]
                    if isinstance(node, LoonRuleNode)
                    and rule_identity(node.type, node.value)[:2] == rule_identity(rule_type, value)[:2]
                    and (selected is UNSET or node.identity[2] == selected)]
        modified = 0
        for node in matching:
            before = node.render()
            if policy is not UNSET:
                node.policy = policy
            if options is not UNSET:
                node.options = options
            modified += node.render() != before
        if matching:
            logger.info('Rule update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self._changed()
            return
        actual_policy = 'DIRECT' if policy is UNSET else policy
        actual_options = options if options is not UNSET else (() if selected is UNSET else selected)
        satisfied = [node for node in nodes if isinstance(node, LoonRuleNode)
                     and node.identity == rule_identity(rule_type, value, actual_options)
                     and (policy is UNSET or node.policy == policy)]
        if satisfied:
            return
        if rule_type == 'URL-REGEX':
            validate_new_regex(value)
        node = LoonRuleNode(','.join([rule_type, native_value(value), native_value(actual_policy), *actual_options]))
        nodes.insert(index, node)
        self._changed()


    def add_rewrite(self, raw_content=None, url_pattern=None, reject_type=UNSET,
                    redirect_url=UNSET, status_code=UNSET, insert=None):
        if raw_content is not None:
            if url_pattern is not None or any(value is not UNSET for value in (reject_type, redirect_url, status_code)):
                raise ValueError('Native and structured Loon rewrite inputs are separate')
            self._add_native('Rewrite', raw_content, insert)
            return
        single_line(url_pattern, 'url_pattern')
        pattern = unquote(url_pattern)
        if reject_type is not UNSET and reject_type not in REJECTS | {'header'}:
            raise ValueError('Unsupported Loon legacy rewrite result')
        if redirect_url is not UNSET:
            single_line(redirect_url, 'redirect_url')
        if status_code is not UNSET and (type(status_code) is not int or status_code not in (302, 307)):
            raise ValueError('Loon legacy rewrite status_code must be 302 or 307')
        if reject_type in REJECTS and (redirect_url is not UNSET or status_code is not UNSET):
            raise ValueError('Reject and redirect results conflict')
        if reject_type == 'header' and status_code is not UNSET:
            raise ValueError('Header rewrite and redirect status conflict')
        nodes, index = self._insert_index('Rewrite', insert)
        matching = []
        for key in self._keys('Rewrite'):
            for node in self.sections[key]:
                if isinstance(node, LoonRewriteNode) and node.match_pattern == pattern:
                    matching.append(node)
                elif isinstance(node, LoonUnknownNode):
                    spans = token_spans(split_comment(node.render())[0])
                    if spans and unquote(spans[0].group()) == pattern:
                        raise ValueError('Cannot recognize the required Loon rewrite identity')
        modified = 0
        for node in matching:
            before = node.render()
            if redirect_url is not UNSET:
                node.replacement = redirect_url
                if node.mode in REJECTS:
                    node.mode = '302'
            if reject_type is not UNSET:
                node.mode = reject_type
                if node.mode in REJECTS:
                    node.replacement = '-' if node.layout == 'corpus' else ''
            if status_code is not UNSET:
                node.mode = str(status_code)
            if node.mode not in REJECTS and node.replacement in ('', '-', '_'):
                raise ValueError('Loon redirect/header rewrite requires a replacement')
            modified += before != node.render()
        if matching:
            logger.info('Rewrite update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self._changed()
            return
        validate_new_regex(pattern)
        if any(char.isspace() for char in pattern):
            raise ValueError('Loon legacy pattern requires escaped whitespace')
        mode = ('302' if redirect_url is not UNSET else 'reject') if reject_type is UNSET else reject_type
        if status_code is not UNSET:
            mode = str(status_code)
        if mode not in REJECTS and redirect_url is UNSET:
            raise ValueError('A new Loon redirect/header rewrite requires redirect_url')
        replacement = '' if mode in REJECTS else ' ' + redirect_url
        if any(char.isspace() for char in replacement.strip()):
            raise ValueError('Loon legacy replacement requires escaped whitespace')
        nodes.insert(index, LoonRewriteNode(pattern + ' ' + mode + replacement))
        self._changed()


    def _script_nodes(self):
        if self.file_role == 'script-declarations':
            return self.header_nodes
        return [node for key in self._keys('Script') for node in self.sections[key]]

    def add_script(self, script, insert=None):
        if isinstance(script, str):
            self._add_native('Script', script, insert)
            return
        if not isinstance(script, dict):
            raise ValueError('Loon scripts require a structured dictionary')
        unknown = set(script) - {'name', 'conditions'} - {key.replace('-', '_') for key in SCRIPT_FIELDS}
        if unknown:
            raise ValueError(f'Unsupported Loon structured script fields: {sorted(unknown)}')
        if 'name' in script and 'tag' in script and script['name'] != script['tag']:
            raise ValueError('Loon script name and tag conflict')
        conditions = script.get('conditions', UNSET)
        selected_enable = UNSET
        if conditions is not UNSET:
            if not isinstance(conditions, dict) or set(conditions) - {'enable'}:
                raise ValueError('Loon script conditions support an enable Boolean selector')
            if 'enable' in conditions:
                if type(conditions['enable']) is not bool:
                    raise ValueError('Loon enable condition requires a Boolean')
                selected_enable = conditions['enable']
        fields = {}
        for key, value in script.items():
            if key == 'conditions':
                continue
            native = 'tag' if key == 'name' else key.replace('_', '-')
            if native in SCRIPT_BOOLS:
                if type(value) is not bool:
                    raise ValueError(f'{key} requires a Boolean')
                value = str(value).lower()
            elif native == 'timeout':
                if type(value) not in (int, float):
                    raise ValueError('Loon timeout requires a number')
                value = str(value)
            else:
                single_line(value, key, empty=native == 'argument')
            fields[native] = value.replace('_', '-') if native == 'type' else value
        stage = fields.get('type')
        if stage not in ('http-request', 'http-response', 'cron'):
            raise ValueError('Loon script type requires HTTP request/response or cron')
        condition_key = 'cronexp' if stage == 'cron' else 'pattern'
        single_line(fields.get(condition_key), condition_key)
        fields[condition_key] = unquote(fields[condition_key])
        nodes, index = self._insert_index('Script', insert)
        identity = stage, fields[condition_key]
        for node in self._script_nodes():
            if isinstance(node, LoonUnknownNode) and self._unknown_script_required(node, stage=stage, pattern=fields[condition_key]):
                raise ValueError('Cannot recognize the required Loon script identity')
        matching = [node for node in self._script_nodes() if isinstance(node, LoonScriptNode)
                    and node.fields.get('type') == stage and node.fields.get(condition_key) == fields[condition_key]
                    and (selected_enable is UNSET or node.identity[2] == selected_enable)]
        modified = 0
        for node in matching:
            updated = dict(node.fields, **fields)
            validate_script(updated)
            before = node.render()
            node.fields = updated
            node.name = node.fields.get('tag')
            modified += before != node.render()
        if matching:
            logger.info('Script update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self._changed()
            return
        if selected_enable is not UNSET and 'enable' not in fields:
            fields['enable'] = str(selected_enable).lower()
        actual_enable = fields.get('enable', 'true') in ('true', '1')
        satisfied = [node for node in self._script_nodes() if isinstance(node, LoonScriptNode)
                     and node.fields.get('type') == stage and node.fields.get(condition_key) == fields[condition_key]
                     and node.identity[2] == actual_enable
                     and all((node.fields.get(key) in ('true', '1')) == (value in ('true', '1'))
                             if key in SCRIPT_BOOLS and key in node.fields else node.fields.get(key) == value
                             for key, value in fields.items())]
        if satisfied:
            logger.info('Script update already satisfied; matched=%s modified=0 in %s', len(satisfied), self.filepath)
            return
        validate_script(fields)
        if stage != 'cron':
            validate_new_regex(fields['pattern'])
            if any(char.isspace() for char in fields['pattern']):
                raise ValueError('Loon legacy HTTP match requires escaped whitespace')
        options = ','.join(key + '=' + native_value(value) for key, value in fields.items()
                           if key not in ('type', 'pattern', 'cronexp'))
        raw = stage + ' ' + native_value(fields[condition_key], quoted=stage == 'cron') + ' ' + options
        nodes.insert(index, LoonScriptNode(raw))
        self._changed()


    def _collections(self):
        return [(None, None, self.header_nodes)] + [
            (key, self._section_names[key], self.sections[key]) for key in self.section_order]

    def _host_match(self, pattern, value, section, line_number):
        try:
            references = url_host_references(pattern)
        except ReferenceRecognitionError as error:
            raise ValueError(f'Cannot recognize Loon URL host reference at {self.filepath} [{section}]:{line_number}: {error}') from error
        return value is None or references.contains(value)

    def remove_rule(self, rule_type, value=None, *, conditions=UNSET):
        from rule_framework.native_input import guard_required_rule_semantics
        guard_required_rule_semantics(self, rule_type, value)
        types = select_rule_types(rule_type)
        if rule_type == 'domain' and value is not None:
            validate_domain_selector(value)
        selected_conditions = condition_options(conditions) if conditions is not UNSET else UNSET
        removed = 0
        for key, section, nodes in self._collections():
            retained = []
            for index, node in enumerate(nodes, 1):
                selected = False
                if isinstance(node, LoonRuleNode):
                    if node.type.upper() in types:
                        selected = value is None or (canonical_domain(node.value) == canonical_domain(value)
                                    if rule_type == 'domain' else node.value == value)
                    elif rule_type == 'domain' and node.type.upper() == 'URL-REGEX':
                        selected = self._host_match(node.value, value, section, index)
                    elif rule_type == 'domain' and node.type.upper() in {'AND', 'OR', 'NOT'}:
                        from rule_framework.logical_refs import logical_reference_matches
                        selected = logical_reference_matches(node.type, node.value, value, client=self.client,
                            location=f'{self.filepath} [{section}]:{index}')
                    elif rule_type == 'domain' and node.type.upper() not in STANDARD_TYPES | {'FINAL', 'RULE-SET'}:
                        raise ValueError(f'Cannot recognize required Loon routing reference: {node.type}')
                    if selected and selected_conditions is not UNSET:
                        selected = node.identity[2] == selected_conditions
                elif rule_type == 'domain':
                    if isinstance(node, LoonRewriteNode):
                        selected = self._host_match(node.match_pattern, value, section, index)
                    elif isinstance(node, LoonScriptNode):
                        if node.fields['type'] in ('http-request', 'http-response'):
                            from rule_framework.native_input import guard_required_script_fields
                            guard_required_script_fields(self, node.fields)
                            selected = self._host_match(node.fields.get('pattern'), value, section, index)
                    elif isinstance(node, LoonMITMNode):
                        if node.operator:
                            raise ValueError('Unknown Loon MITM list operator requires explicit native maintenance')
                        hosts = [host for host in node.hostnames
                                 if value is not None and mitm_reference(host) != canonical_domain(value)]
                        removed += len(node.hostnames) - len(hosts)
                        node.hostnames = hosts
                        if not hosts:
                            continue
                    elif isinstance(node, LoonUnknownNode):
                        raise ValueError(f'Cannot recognize required Loon domain reference at {self.filepath} [{section}]:{index}: {node.render()!r}')
                if selected:
                    removed += 1
                else:
                    retained.append(node)
            if key is None:
                self.header_nodes = retained
            else:
                self.sections[key] = retained
        if removed:
            self._changed()
        logger.info('Domain/rule removal matched=%s in %s', removed, self.filepath)

    def _mitm_nodes(self):
        if self.file_role == 'script-declarations':
            return self.header_nodes
        return [node for key in self._keys('MITM') for node in self.sections[key]]

    def add_mitm(self, hostnames, insert=None):
        if not isinstance(hostnames, list) or not hostnames:
            raise ValueError('Loon MITM hostnames must be a non-empty list')
        for host in hostnames:
            mitm_reference(host)
        nodes, index = self._insert_index('MITM', insert)
        matching = [node for node in self._mitm_nodes() if isinstance(node, LoonMITMNode)]
        if any(isinstance(node, LoonUnknownNode) for node in self._mitm_nodes()):
            raise ValueError('Cannot recognize the required Loon MITM declaration')
        modified = 0
        for node in matching:
            if node.operator:
                raise ValueError('Unknown Loon MITM list operator requires explicit native maintenance')
            existing = {canonical_domain(host) for host in node.hostnames}
            separator = ', ' if ', ' in node.raw_content else ','
            for host in hostnames:
                if canonical_domain(host) not in existing:
                    node.hostnames.append(host)
                    node.raw_hosts.append(separator[1:] + host)
                    existing.add(canonical_domain(host))
                    modified += 1
        if matching:
            if modified:
                self._changed()
            return
        unique = []
        seen = set()
        for host in hostnames:
            if canonical_domain(host) not in seen:
                unique.append(host)
                seen.add(canonical_domain(host))
        nodes.insert(index, LoonMITMNode('hostname = ' + ', '.join(unique)))
        self._changed()

    def remove_mitm(self, hostnames):
        if isinstance(hostnames, str):
            hostnames = [hostnames]
        if not isinstance(hostnames, list) or not hostnames:
            raise ValueError('Loon MITM hostnames must be a non-empty list')
        selectors = set()
        for host in hostnames:
            mitm_reference(host)
            selectors.add(canonical_domain(host))
        removed = 0
        for key, section, nodes in self._collections():
            if section is not None and section.lower() != 'mitm':
                continue
            retained = []
            for node in nodes:
                if isinstance(node, LoonMITMNode):
                    if node.operator:
                        raise ValueError('Unknown Loon MITM list operator requires explicit native maintenance')
                    hosts = [host for host in node.hostnames if canonical_domain(host) not in selectors]
                    removed += len(node.hostnames) - len(hosts)
                    node.hostnames = hosts
                    if not hosts:
                        continue
                elif isinstance(node, LoonUnknownNode) and re.match(r'\s*hostname\s*=', node.render()):
                    raise ValueError('Cannot recognize required Loon MITM references')
                retained.append(node)
            if key is None:
                self.header_nodes = retained
            else:
                self.sections[key] = retained
        if removed:
            self._changed()

    def validate(self):
        super().validate()
        from rule_framework.managed_validation import validate_passive_node
        if self.client != 'Loon' or self.file_role not in ('plugin', 'script-declarations', 'full-profile', 'configuration-fragment'):
            raise ValueError('Invalid managed Loon client/file purpose')
        if self._newline not in ('\n', '\r\n', '\r') or type(self.is_dirty) is not bool:
            raise ValueError('Invalid managed Loon newline/dirty state')
        if not isinstance(self._section_names, dict) or set(self._section_names) != set(self.sections):
            raise ValueError('Loon section identities must match the managed section map')
        if self.file_role == 'script-declarations' and self.sections:
            raise ValueError('Sectionless Loon script declarations cannot carry INI sections')
        for key, section, nodes in self._collections():
            if section is not None and (not nodes or not isinstance(nodes[0], SectionNode)
                    or nodes[0].name != section):
                raise ValueError('Loon section must retain its corresponding section header')
            for node in nodes:
                if getattr(node, 'line_ending', self._newline) not in ('', '\n', '\r\n', '\r'):
                    raise ValueError('Invalid managed Loon node newline')
                changed = not getattr(node, '_loon_loaded', False) or node.render() != getattr(node, '_loon_baseline_line', None)
                section_lower = section.lower() if section else None
                if isinstance(node, LoonRuleNode) and section_lower != 'rule':
                    raise ValueError('Loon routing entries require the Rule section')
                if isinstance(node, LoonRewriteNode) and section_lower not in ('rewrite', 'url rewrite'):
                    raise ValueError('Loon rewrites require their corresponding rewrite section')
                if isinstance(node, LoonScriptNode) and not (section_lower == 'script' or section is None and self.file_role == 'script-declarations'):
                    raise ValueError('Loon scripts require Script section or sectionless declaration purpose')
                if isinstance(node, LoonMITMNode) and not (section_lower == 'mitm' or section is None and self.file_role == 'script-declarations'):
                    raise ValueError('Loon MITM hosts require MITM section or sectionless declaration purpose')
                if not changed or getattr(node, '_native_input', False):
                    continue
                validate_passive_node(node, changed=changed)
                if isinstance(node, LoonScriptNode):
                    validate_script(node.fields)
                elif isinstance(node, LoonRewriteNode):
                    single_line(node.match_pattern, 'Loon rewrite pattern')
                    single_line(node.replacement, 'Loon rewrite replacement', empty=node.mode in REJECTS)
                    if node.mode not in REWRITE_MODES:
                        raise ValueError('Unrecognized Loon rewrite result')
                    if node.mode not in REJECTS and node.replacement in ('', '-', '_'):
                        raise ValueError('Loon redirect/header rewrite requires a replacement')
                elif isinstance(node, LoonRuleNode):
                    single_line(node.policy, 'Loon policy')
                    if ',' in node.policy:
                        raise ValueError('Loon policy contains a field delimiter')
                    if self.is_module and node.policy not in {'DIRECT', 'PROXY', 'REJECT', 'REJECT-DROP', 'REJECT-IMG', 'REJECT-DICT', 'REJECT-ARRAY'}:
                        raise ValueError('Loon plugin rules require DIRECT, PROXY or a supported REJECT policy')
                    if node.type.upper() != 'FINAL':
                        validate_standard_value(node.type, node.value, client='Loon')
                    validate_options(node.options, node.type, 'Loon')
                elif isinstance(node, LoonMITMNode):
                    if not isinstance(node.hostnames, list) or not node.hostnames:
                        raise ValueError('Loon MITM hosts must be a non-empty list')
                    if node.operator:
                        raise ValueError('Unknown Loon MITM list operator requires explicit native maintenance')
                    for host in node.hostnames:
                        mitm_reference(host)
                elif isinstance(node, LoonUnknownNode):
                    raise ValueError(f'Changed Loon content requires recognizable syntax in [{section}]')
        encode_text('', self.text_encoding, self.text_bom)

    def validate_complete(self):
        self.validate()
        super().validate_complete()

    def _unknown_script_required(self, node, *, stage=None, pattern=None):
        spans = token_spans(split_comment(node.render())[0])
        if spans:
            native_stage = spans[0].group()
            if native_stage in ('http-request', 'http-response', 'cron'):
                if stage is not None and native_stage != stage:
                    return False
                if pattern is not None and (native_stage == 'cron' or len(spans) >= 2 and unquote(spans[1].group()) != pattern):
                    return False
        return True

    def remove_script(self, name=None, pattern=None, script_path=None):
        if all(value is None for value in (name, pattern, script_path)):
            raise ValueError('Loon script removal requires a name, pattern or script_path selector')
        for key, value in (('name', name), ('pattern', pattern), ('script_path', script_path)):
            if value is not None:
                single_line(value, key)
        pattern = unquote(pattern) if pattern is not None else None
        removed = 0
        for key, section, nodes in self._collections():
            if not (section and section.lower() == 'script' or key is None and self.file_role == 'script-declarations'):
                continue
            retained = []
            for node in nodes:
                if isinstance(node, LoonScriptNode):
                    selected = ((name is None or node.fields.get('tag') == name)
                                and (pattern is None or node.fields.get('pattern') == pattern)
                                and (script_path is None or node.fields.get('script-path') == script_path))
                    if selected:
                        removed += 1
                        continue
                elif isinstance(node, LoonUnknownNode) and self._unknown_script_required(node, pattern=pattern):
                    raise ValueError('Cannot recognize the required Loon script selector')
                retained.append(node)
            if key is None:
                self.header_nodes = retained
            else:
                self.sections[key] = retained
        if removed:
            self._changed()
        logger.info('Script removal matched=%s in %s', removed, self.filepath)

    def remove_rewrite(self, url_pattern):
        single_line(url_pattern, 'url_pattern')
        pattern = unquote(url_pattern)
        removed = 0
        for key in self._keys('Rewrite'):
            retained = []
            for node in self.sections[key]:
                if isinstance(node, LoonRewriteNode) and node.match_pattern == pattern:
                    removed += 1
                    continue
                if isinstance(node, LoonUnknownNode):
                    spans = token_spans(split_comment(node.render())[0])
                    if spans and unquote(spans[0].group()) == pattern:
                        raise ValueError('Cannot recognize the required Loon rewrite identity')
                retained.append(node)
            self.sections[key] = retained
        if removed:
            self._changed()
        logger.info('Rewrite removal matched=%s in %s', removed, self.filepath)


    def _add_native(self, section, content, insert=None):
        from rule_framework.native_input import validate_native_entry
        native_scope = validate_native_entry(self, content, kind='declaration', section=section)
        single_line(content, 'Loon native input')
        if content.strip().startswith('['):
            raise ValueError('Native Loon entries cannot insert section headers')
        if re.match(r'\s*hostname\s*=', content) and section != 'MITM':
            raise ValueError('Native Loon hostname declarations require the MITM section')
        nodes, index = self._insert_index(section, insert)
        node = self._parse_line(content, section)
        if native_scope == ('known-fields', 'known-fields'):
            if isinstance(node, LoonRuleNode):
                matching = [item for key in self._keys('Rule') for item in self.sections[key]
                            if isinstance(item, LoonRuleNode) and item.identity == node.identity]
                modified = 0
                for item in matching:
                    before = item.render()
                    item.policy = node.policy
                    modified += item.render() != before
                if matching:
                    logger.info('Rule update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
            elif isinstance(node, LoonRewriteNode):
                matching = []
                for key in self._keys(section):
                    for item in self.sections[key]:
                        if isinstance(item, LoonRewriteNode) and item.match_pattern == node.match_pattern:
                            matching.append(item)
                        elif isinstance(item, LoonUnknownNode):
                            spans = token_spans(split_comment(item.render())[0])
                            if spans and unquote(spans[0].group()) == node.match_pattern:
                                raise ValueError('Cannot recognize the required Loon rewrite identity')
                modified = 0
                for item in matching:
                    before = item.render()
                    item.mode = node.mode
                    if node.mode in REJECTS:
                        item.replacement = (node.replacement or '-') if item.layout == 'corpus' else ''
                    else:
                        item.replacement = node.replacement
                    modified += item.render() != before
                if matching:
                    logger.info('Rewrite update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
            elif isinstance(node, LoonScriptNode):
                stage = node.fields.get('type')
                condition_key = 'cronexp' if stage == 'cron' else 'pattern'
                for item in self._script_nodes():
                    if isinstance(item, LoonUnknownNode) and self._unknown_script_required(
                            item, stage=stage, pattern=node.fields.get(condition_key)):
                        raise ValueError('Cannot recognize the required Loon script identity')
                matching = [item for item in self._script_nodes()
                            if isinstance(item, LoonScriptNode)
                            and item.fields.get('type') == stage
                            and item.fields.get(condition_key) == node.fields.get(condition_key)
                            and item.identity == node.identity]
                modified = 0
                for item in matching:
                    updated = dict(item.fields, **node.fields)
                    validate_script(updated)
                    before = item.render()
                    item.fields = updated
                    item.name = item.fields.get('tag')
                    modified += item.render() != before
                if matching:
                    logger.info('Script update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
        if any(item.render() == content for item in nodes):
            return
        node._native_input = native_scope[1] != 'known-fields'
        if native_scope[1] == 'unknown':
            node._opaque_native_line = content
        nodes.insert(index, node)
        self._changed()

    def add_native_rule(self, content, insert=None):
        self._add_native('Rule', content, insert)

    def modify(self, search, replace, is_regex=False, count=0):
        from collections import defaultdict, deque
        from rule_framework.fom import _apply_text_replacement
        original, _, _ = decode_text(self.render_bytes())
        updated, _ = _apply_text_replacement(original, search, replace, is_regex, count)
        if updated == original:
            return
        unchanged = defaultdict(deque)
        for _, section, nodes in self._collections():
            for node in nodes:
                identity = section, node.render(), getattr(node, 'line_ending', self._newline)
                unchanged[identity].append(getattr(node, '_native_input', False))
        self._parse_text(updated)
        for _, section, nodes in self._collections():
            for node in nodes:
                identity = section, node.render(), node.line_ending
                if unchanged[identity]:
                    node._native_input = unchanged[identity].popleft()
                else:
                    node._loon_loaded = False
        self.validate()
        self._changed()


    def scaffold(self, base_name):
        single_line(base_name, 'Loon file name')
        now = _get_now(self)
        if self.is_module:
            self._parse_text(f'#!name={base_name}\n#!desc=最后更新时间 {now}\n#!total=0\n')
        elif self.file_role == 'script-declarations':
            self._parse_text(f'# NAME: {base_name}\n# UPDATED: {now}\n# TOTAL: 0\n')
        else:
            self._parse_text(f'# NAME: {base_name}\n# UPDATED: {now}\n# TOTAL: 1\n[Rule]\nFINAL,DIRECT\n')
            self.file_role = 'full-profile'
        self._changed()

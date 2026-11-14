"""Lossless Quantumult X profiles and sectionless rewrite fragments."""
from rule_framework.text_json import split_physical_lines
import logging
from pathlib import Path
import re

from rule_framework.ast import ASTNode, BlankNode, CommentNode, SectionNode, RuleNode, RewriteNode
from rule_framework.domain_refs import canonical_domain, url_host_references, ReferenceRecognitionError
from rule_framework.quantumult_lists import (
    QuantumultRuleNode, parse_quantumult_line, quantumult_native_type,
    validate_quantumult_value, validate_quantumult_policy,
    validate_quantumult_options, validate_quantumult_conditions,
)
from rule_framework.rule_helpers import UNSET, calculate_insert_index, rule_identity, select_rule_types, SEMANTIC_TYPES, validate_domain_selector
from rule_framework.text_json import decode_text, encode_text, serialize_physical_nodes

logger = logging.getLogger('RuleFramework')
QX_FIELDS = ('file_role', 'client', 'text_encoding', 'text_bom', '_newline',
             '_section_names', '_metadata_baseline')


class QuantumultUnknownNode(CommentNode):
    """Unrecognized declarations retain their exact source text."""


REJECT_MODES = {'reject', 'reject-200', 'reject-img', 'reject-dict', 'reject-array'}
SCRIPT_MODES = {'script-request-header', 'script-request-body', 'script-response-header',
                'script-response-body', 'script-echo-response', 'script-analyze-echo-response'}


def single_line(value, field):
    if not isinstance(value, str) or not value.strip() or any(c in value for c in '\r\n\0'):
        raise ValueError(f'{field} must be a non-empty single-line string')
    return value


def unquote(value):
    return value[1:-1] if len(value) > 1 and value[0] in ('"', "'") and value[-1] == value[0] else value


def split_comment(line):
    # Inline comments are separated from declarations by whitespace. URL fragments
    # and the script URL's #arguments remain part of their declared field.
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == '\\':
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif index and line[index - 1].isspace() and (char in '#;' or line[index:index + 2] == '//'):
            start = index
            while start and line[start - 1].isspace():
                start -= 1
            return line[:start], line[start:]
    return line, ''



PROCESSOR_MODES = {'request-header', 'request-body', 'response-body'}
JQ_MODES = {'jsonjq-request-body', 'jsonjq-response-body'}
HTTP_MODES = REJECT_MODES | SCRIPT_MODES | PROCESSOR_MODES | JQ_MODES | {'302', '307', 'echo-response'}


def quoted_value(value, old=''):
    if len(old) >= 2 and old[0] in ('"', "'") and old[-1] == old[0]:
        return old[0] + value.replace(old[0], '\\' + old[0]) + old[0]
    return value


class QuantumultHTTPNode(RewriteNode):
    def __init__(self, line):
        content, self.inline_comment = split_comment(line)
        marker = re.search(r'\s+(url(?:-and-header)?)\s+([\w-]+)(?=\s|$)', content)
        if not marker:
            raise ValueError('Unknown Quantumult X URL declaration')
        prefix = content[:marker.start()]
        token = re.match(r'\s*("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\S+)', prefix)
        if not token:
            raise ValueError('Quantumult X URL pattern is absent')
        super().__init__(content, unquote(token.group(1)))
        self.method, self.mode = marker.groups()
        self.header_pattern = prefix[token.end():].strip() or None
        if self.method == 'url' and self.header_pattern is not None:
            raise ValueError('url declarations contain one URL match field')
        if self.method == 'url-and-header' and self.header_pattern is None:
            raise ValueError('url-and-header requires the header match condition')
        if self.mode not in HTTP_MODES:
            raise ValueError(f'Unknown Quantumult X rewrite mode: {self.mode}')
        self.processor_match = None
        self.content_type = None
        self.result = None
        self._spans = {'match_pattern': token.span(1), 'method': marker.span(1), 'mode': marker.span(2)}
        if self.header_pattern is not None:
            left = token.end() + len(prefix[token.end():]) - len(prefix[token.end():].lstrip())
            self._spans['header_pattern'] = (left, len(prefix.rstrip()))
        tail_start = marker.end()
        while tail_start < len(content) and content[tail_start].isspace():
            tail_start += 1
        tail_end = len(content.rstrip())
        tail = content[tail_start:tail_end]
        if self.mode in PROCESSOR_MODES | {'echo-response'}:
            separator = re.search(r'\s+' + re.escape(self.mode) + r'\s+', tail)
            if not separator:
                raise ValueError(f'{self.mode} requires separated match/result fields')
            field = 'content_type' if self.mode == 'echo-response' else 'processor_match'
            setattr(self, field, unquote(tail[:separator.start()]))
            self._spans[field] = (tail_start, tail_start + separator.start())
            self.result = unquote(tail[separator.end():])
            self._spans['result'] = (tail_start + separator.end(), tail_end)
        elif self.mode in REJECT_MODES:
            if tail:
                raise ValueError('Quantumult X reject responses have no result arguments')
        else:
            if not tail:
                raise ValueError('Quantumult X processing result is absent')
            self.result = unquote(tail)
            self._spans['result'] = (tail_start, tail_end)
        self._baseline_fields = self.fields

    @property
    def fields(self):
        return {name: getattr(self, name) for name in ('match_pattern', 'method', 'mode',
                'header_pattern', 'processor_match', 'content_type', 'result')}

    @property
    def identity(self):
        family = 'request-url' if self.mode in REJECT_MODES | {'302', '307'} else self.mode
        return family, self.match_pattern, self.method, self.header_pattern, self.processor_match

    def render(self):
        fields = self.fields
        if fields == self._baseline_fields:
            return self.content + self.inline_comment
        result = self.content
        # A result-family transition changes the argument count, retaining URL,
        # method, their separators and the original trailing padding/comment.
        old_mode = self._baseline_fields['mode']
        if (old_mode in REJECT_MODES) != (self.mode in REJECT_MODES):
            start, _ = self._spans['mode']
            padding = self.content[len(self.content.rstrip()):]
            result = self.content[:start] + self.mode + ('' if self.result is None else ' ' + self.result) + padding
            return result + self.inline_comment
        for field, (start, end) in sorted(self._spans.items(), key=lambda item: item[1][0], reverse=True):
            if fields[field] != self._baseline_fields[field]:
                result = result[:start] + quoted_value(fields[field], self.content[start:end]) + result[end:]
        return result + self.inline_comment


def validate_regex(value, field):
    single_line(value, field)
    try:
        re.compile(value)
    except re.error as error:
        raise ValueError(f'Invalid or unsupported structured {field} regex: {error}') from error


def validate_http(node, *, validate_patterns=True):
    pattern_check = validate_regex if validate_patterns else single_line
    pattern_check(node.match_pattern, 'url_pattern')
    if node.method not in ('url', 'url-and-header') or node.mode not in HTTP_MODES:
        raise ValueError('Unsupported Quantumult X method or rewrite type')
    if node.method == 'url-and-header':
        pattern_check(node.header_pattern, 'header_pattern')
    elif node.header_pattern is not None:
        raise ValueError('header_pattern requires method=url-and-header')
    if node.mode in REJECT_MODES:
        if node.result is not None:
            raise ValueError('Quantumult X reject response has no destination')
    else:
        single_line(node.result, 'script_path' if node.mode in SCRIPT_MODES else 'result')
    if node.mode in PROCESSOR_MODES:
        pattern_check(node.processor_match, 'match_pattern')
    if node.mode == 'echo-response':
        single_line(node.content_type, 'content_type')




LOCAL_SCRIPT_TYPES = {'cron', 'event-network', 'event-interaction', 'http-backend'}
LOCAL_SCRIPT_FIELDS = {'script-path', 'tag', 'enabled', 'img-url', 'require-devices', 'path'}


class QuantumultLocalScriptNode(ASTNode):
    def __init__(self, line, section):
        self.content, self.inline_comment = split_comment(line)
        self.section = section
        assignments = list(re.finditer(r',\s*([\w-]+)\s*=\s*', self.content))
        head_end = assignments[0].start() if assignments else len(self.content.rstrip())
        head = self.content[:head_end]
        tokens = list(re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s]+', head))
        if not tokens:
            raise ValueError('Quantumult X script path is absent')
        if section == 'http_backend':
            if len(tokens) != 1:
                raise ValueError('HTTP backend requires a single script path')
            self.stage, self.schedule = 'http-backend', None
        elif tokens[0].group() in ('event-network', 'event-interaction'):
            if len(tokens) != 2:
                raise ValueError('Quantumult X event requires one script path')
            self.stage, self.schedule = tokens[0].group(), None
        else:
            if len(tokens) not in (6, 7):
                raise ValueError('Quantumult X task requires five or six cron fields and one script path')
            self.stage, self.schedule = 'cron', ' '.join(token.group() for token in tokens[:-1])
        self.fields = {'script-path': unquote(tokens[-1].group())}
        self._spans = {'script-path': tokens[-1].span()}
        for index, assignment in enumerate(assignments):
            key = assignment.group(1)
            if key in self.fields:
                raise ValueError(f'Duplicate Quantumult X script option: {key}')
            end = assignments[index + 1].start() if index + 1 < len(assignments) else len(self.content.rstrip())
            self.fields[key] = unquote(self.content[assignment.end():end].rstrip())
            self._spans[key] = assignment.end(), assignment.end() + len(self.content[assignment.end():end].rstrip())
        self._baseline = dict(self.fields)

    @property
    def identity(self):
        devices = tuple(sorted(value.strip() for value in self.fields.get('require-devices', '').split(',') if value.strip()))
        return self.stage, self.fields.get('path') if self.stage == 'http-backend' else self.schedule, devices

    def render(self):
        result = self.content
        for field, (start, end) in sorted(self._spans.items(), key=lambda item: item[1][0], reverse=True):
            if self.fields[field] != self._baseline[field]:
                result = result[:start] + quoted_value(self.fields[field], self.content[start:end]) + result[end:]
        for field, value in self.fields.items():
            if field not in self._spans:
                result += ', ' + field + '=' + value
        return result + self.inline_comment


def validate_local_script(node):
    unknown = set(node.fields) - LOCAL_SCRIPT_FIELDS
    if unknown:
        raise ValueError(f'Unsupported Quantumult X script declaration fields: {sorted(unknown)}')
    single_line(node.fields.get('script-path'), 'script_path')
    if node.stage == 'cron':
        from rule_framework.surge import validate_cron
        validate_cron(node.schedule)
    elif node.stage == 'http-backend':
        validate_regex(node.fields.get('path'), 'backend pattern')
    elif node.stage not in LOCAL_SCRIPT_TYPES:
        raise ValueError('Unknown Quantumult X script execution stage')
    if node.fields.get('enabled', 'true') not in ('true', 'false'):
        raise ValueError('Quantumult X script enabled must be a boolean')
    if 'require-devices' in node.fields:
        devices = [value.strip() for value in node.fields['require-devices'].split(',')]
        if not devices or any(not device or any(c.isspace() or c in '#;' for c in device) for device in devices):
            raise ValueError('Quantumult X require_devices must contain non-empty device IDs')
    for field in ('tag', 'img-url'):
        if field in node.fields:
            single_line(node.fields[field], field)
    if node.stage != 'http-backend' and 'path' in node.fields:
        raise ValueError('Backend path requires http-backend stage')


def validate_hostnames(hostnames):
    if not isinstance(hostnames, list) or not hostnames:
        raise ValueError('Quantumult X MITM hostnames must be a non-empty list')
    for host in hostnames:
        single_line(host, 'MITM hostname')
        if host != host.strip() or any(c.isspace() or c in ',%#;' for c in host):
            raise ValueError('Quantumult X MITM entries require one hostname each')
        name = host
        if host.startswith('['):
            import ipaddress
            match = re.fullmatch(r'\[([^\]]+)\](?::([0-9]+))?', host)
            if not match:
                raise ValueError('Invalid Quantumult X bracketed MITM address')
            ipaddress.IPv6Address(match.group(1))
            port = match.group(2)
            name = None
        elif ':' in host:
            name, port = host.rsplit(':', 1)
        else:
            port = None
        if port is not None and (not port.isdigit() or not 1 <= int(port) <= 65535):
            raise ValueError('Quantumult X MITM port must be in range 1..65535')
        if name is not None:
            validate_domain_selector(name)
            if not re.fullmatch(r'[\w.*?-]+', name):
                raise ValueError('Quantumult X MITM supports literal labels, * and ? wildcard syntax')


class QuantumultMITMNode(ASTNode):
    def __init__(self, line):
        self.content, self.inline_comment = split_comment(line)
        match = re.fullmatch(r'(\s*hostname\s*=\s*)(.*?)([ \t]*)', self.content)
        if not match:
            raise ValueError('Unrecognized Quantumult X hostname declaration')
        self.prefix, raw, self.trailing = match.groups()
        self.raw_hosts = raw.split(',')
        self.hostnames = [host.strip() for host in self.raw_hosts]
        self._baseline = tuple(self.hostnames)

    def render(self):
        if tuple(self.hostnames) == self._baseline:
            return self.content + self.inline_comment
        originals = list(zip(self._baseline, self.raw_hosts))
        raw = []
        for host in self.hostnames:
            found = next((index for index, (value, _) in enumerate(originals) if value == host), None)
            if found is None:
                raw.append((' ' if raw and ', ' in self.content else '') + host)
            else:
                raw.append(originals.pop(found)[1])
        if raw:
            raw[0] = raw[0].lstrip()
        return self.prefix + ','.join(raw) + self.trailing + self.inline_comment


class QuantumultStructuredMixin:
    def __init__(self, filepath):
        super().__init__(filepath)
        self.client = 'Quantumult X'
        self.file_role = 'rewrite-fragment'
        self.text_encoding, self.text_bom = 'utf-8', b''
        self._newline = '\n'
        self._section_names = {}
        self._metadata_baseline = b''
        self.ends_with_newline = True

    @property
    def is_snippet(self):
        return self.file_role == 'rewrite-fragment'

    def get_script_section_name(self):
        return 'rewrite_local'

    def load(self):
        raw = Path(self.filepath).read_bytes()
        text, self.text_encoding, self.text_bom = decode_text(raw)
        self._parse_text(text)
        self._metadata_baseline = raw
        self.is_dirty = False

    def _parse_text(self, text):
        self.header_nodes, self.sections, self.section_order, self._section_names = [], {}, [], {}
        records = split_physical_lines(text)
        self.ends_with_newline = text.endswith(('\r', '\n'))
        self._newline = next((row[len(row.rstrip('\r\n')):] for row in records
                              if row.endswith(('\r', '\n'))), self._newline)
        section = None
        for row in records:
            line = row.rstrip('\r\n')
            declaration = re.fullmatch(r'\s*\[([^\]]+)\][ \t]*', line)
            if declaration:
                name = declaration.group(1)
                section = name
                while section in self.sections:
                    section += '\0'
                self.sections[section] = []
                self.section_order.append(section)
                self._section_names[section] = name
                node = SectionNode(name)
                node.raw_section_line = line
            else:
                node = self._parse_line(line, self._section_names.get(section))
            node.line_ending = row[len(line):]
            node._qx_baseline_line = line
            (self.header_nodes if section is None else self.sections[section]).append(node)
        names = set(self._section_names.values())
        if not names:
            self.file_role = 'rewrite-fragment'
        else:
            self.file_role = 'full-profile' if names & {'general', 'dns', 'policy', 'server_local',
                'server_remote', 'filter_remote', 'rewrite_remote', 'task_local', 'http_backend'} or any(
                isinstance(node, QuantumultRuleNode) and node.type.upper() == 'FINAL'
                for key in self.section_order if self._section_names[key] == 'filter_local'
                for node in self.sections[key]) else 'configuration-fragment'

    def _parse_line(self, line, section):
        if not line.strip():
            return BlankNode(line)
        if line.lstrip().startswith(('#', ';', '//')):
            return CommentNode(line)
        if section in (None, 'mitm') and re.match(r'\s*hostname\s*=', line):
            return QuantumultMITMNode(line)
        if section == 'filter_local':
            try:
                parsed = parse_quantumult_line(line)
                return parsed if isinstance(parsed, QuantumultRuleNode) else QuantumultUnknownNode(line)
            except (ValueError, IndexError):
                return QuantumultUnknownNode(line)
        if section in ('task_local', 'http_backend'):
            try:
                return QuantumultLocalScriptNode(line, section)
            except ValueError:
                pass
        if section in (None, 'rewrite_local'):
            try:
                return QuantumultHTTPNode(line)
            except ValueError:
                pass
        return QuantumultUnknownNode(line)

    def _all_nodes(self):
        return self.header_nodes + [node for key in self.section_order for node in self.sections[key]]

    def render_bytes(self):
        nodes = self._all_nodes()
        return serialize_physical_nodes(nodes, newline=self._newline,
            ends_with_newline=self.ends_with_newline, encoding=self.text_encoding, bom=self.text_bom)

    def save(self):
        self.validate()
        self.validate_complete()
        Path(self.filepath).write_bytes(self.render_bytes())

    def _section(self, name):
        if self.is_snippet:
            if name not in ('rewrite_local', 'mitm'):
                raise ValueError(f'Quantumult X rewrite-fragment has no {name} section')
            return self.header_nodes
        key = next((key for key in self.section_order if self._section_names[key] == name), None)
        if key is None:
            key = name
            self.sections[key] = [SectionNode(name)]
            self.section_order.append(key)
            self._section_names[key] = name
        return self.sections[key]

    def _insert_index(self, name, insert):
        nodes = self._section(name)
        index = calculate_insert_index(nodes, insert, not self.is_snippet, name)
        if name == 'filter_local':
            final = next((i for i, node in enumerate(nodes)
                          if isinstance(node, QuantumultRuleNode) and node.type.upper() == 'FINAL'), None)
            if final is not None:
                if insert is None:
                    index = final
                elif index > final:
                    raise ValueError('Quantumult X routing insertion must precede FINAL')
        return nodes, index

    def add_rule(self, rule_type, value, policy=UNSET, insert=None, *, conditions=UNSET, options=UNSET):
        if conditions is not UNSET:
            validate_quantumult_conditions(conditions)
        if options is not UNSET:
            options = validate_quantumult_options(options)
        if policy is not UNSET:
            validate_quantumult_policy(policy)
        native_type = quantumult_native_type(rule_type, value)
        validate_quantumult_value(native_type, value)
        nodes, index = self._insert_index('filter_local', insert)
        identity = rule_identity(native_type, value)
        matching = [node for key in self.section_order if self._section_names[key] == 'filter_local'
                    for node in self.sections[key] if isinstance(node, QuantumultRuleNode)
                    and node.identity == identity]
        if matching:
            modified = 0
            for node in matching:
                validate_quantumult_value(node.type.upper(), node.value)
                validate_quantumult_options(node.options)
                changed = False
                if policy is not UNSET and node.policy != policy:
                    node.policy = policy
                    changed = True
                if options is not UNSET and node.options != options:
                    node.options = options
                    changed = True
                modified += changed
            logger.info('Quantumult X rule update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self._changed()
            return
        if policy is UNSET:
            raise ValueError('A new Quantumult X rule requires an explicit policy')
        fields = [native_type, policy] if native_type == 'FINAL' else [native_type, value, policy]
        nodes.insert(index, QuantumultRuleNode(','.join([*fields, *(options if options is not UNSET else ())])))
        self._changed()

    def add_url_rewrite(self, raw_content=None, url_pattern=None, reject_type=UNSET,
                        redirect_url=UNSET, status_code=UNSET, insert=None, *,
                        rewrite_type=UNSET, method='url', header_pattern=UNSET,
                        match_pattern=UNSET, replacement=UNSET, content_type=UNSET, data=UNSET):
        supplied = (reject_type, redirect_url, status_code, rewrite_type, header_pattern,
                    match_pattern, replacement, content_type, data)
        if raw_content is not None:
            if any(field is not UNSET for field in supplied) or url_pattern is not None or method != 'url':
                raise ValueError('Native rewrite content conflicts with structured fields')
            return self._add_native('rewrite_local', raw_content, insert)
        validate_regex(url_pattern, 'url_pattern')
        if not isinstance(method, str) or method not in ('url', 'url-and-header'):
            raise ValueError('Quantumult X method must be url or url-and-header')
        if header_pattern is not UNSET:
            validate_regex(header_pattern, 'header_pattern')
        header = None if header_pattern is UNSET else header_pattern
        if method == 'url-and-header':
            validate_regex(header, 'header_pattern')
        elif header is not None:
            raise ValueError('header_pattern requires method=url-and-header')
        if reject_type is not UNSET and (not isinstance(reject_type, str) or reject_type not in REJECT_MODES):
            raise ValueError('Unsupported Quantumult X reject_type')
        if status_code is not UNSET and (isinstance(status_code, bool) or not isinstance(status_code, int) or status_code not in (302, 307)):
            raise ValueError('Quantumult X status_code must be 302 or 307')
        if rewrite_type is not UNSET and (not isinstance(rewrite_type, str) or rewrite_type not in HTTP_MODES - SCRIPT_MODES):
            raise ValueError('Unsupported Quantumult X rewrite_type; HTTP scripts use add_script')
        if redirect_url is not UNSET:
            single_line(redirect_url, 'redirect_url')
        if reject_type is not UNSET and (redirect_url is not UNSET or status_code is not UNSET):
            raise ValueError('Reject response fields conflict with redirect fields')
        if rewrite_type in REJECT_MODES and (redirect_url is not UNSET or status_code is not UNSET):
            raise ValueError('Reject rewrite_type conflicts with redirect fields')
        if rewrite_type in ('302', '307') and (reject_type is not UNSET or status_code is not UNSET and str(status_code) != rewrite_type):
            raise ValueError('Redirect rewrite_type conflicts with response results')
        if rewrite_type in REJECT_MODES and reject_type is not UNSET and reject_type != rewrite_type:
            raise ValueError('rewrite_type and reject_type specify conflicting response results')
        processor = rewrite_type in PROCESSOR_MODES if rewrite_type is not UNSET else False
        if processor:
            validate_regex(match_pattern if match_pattern is not UNSET else None, 'match_pattern')
        elif match_pattern is not UNSET:
            raise ValueError('match_pattern requires a header/body rewrite_type')
        if rewrite_type in JQ_MODES | PROCESSOR_MODES | {'echo-response'} if rewrite_type is not UNSET else False:
            if any(field is not UNSET for field in (reject_type, redirect_url, status_code)):
                raise ValueError('Processing results conflict with reject/redirect fields')
        elif any(field is not UNSET for field in (replacement, content_type, data)):
            raise ValueError('Processing result fields require their rewrite_type')
        if rewrite_type != 'echo-response' and (content_type is not UNSET or data is not UNSET):
            raise ValueError('content_type/data require echo-response')
        if rewrite_type == 'echo-response' and replacement is not UNSET:
            raise ValueError('echo-response uses data as its response result')
        for field, value in (('replacement', replacement), ('content_type', content_type), ('data', data)):
            if value is not UNSET:
                single_line(value, field)
        nodes, index = self._insert_index('rewrite_local', insert)
        all_nodes = [node for section, bucket in self._buckets() if section == 'rewrite_local' for node in bucket]
        self._require_known_identity(all_nodes, url_pattern)
        mode = rewrite_type if rewrite_type is not UNSET else 'request-url'
        family = 'request-url' if mode in REJECT_MODES | {'302', '307'} else mode
        identity = (family, url_pattern, method, header, match_pattern if processor else None)
        matching = [node for node in all_nodes if isinstance(node, QuantumultHTTPNode) and node.identity == identity]
        modified = 0
        for node in matching:
            validate_http(node)
            before = node.fields
            if family == 'request-url':
                if reject_type is not UNSET or rewrite_type in REJECT_MODES:
                    node.mode, node.result = reject_type if reject_type is not UNSET else rewrite_type, None
                elif redirect_url is not UNSET or status_code is not UNSET or rewrite_type in ('302', '307'):
                    node.mode = str(status_code) if status_code is not UNSET else rewrite_type if rewrite_type in ('302', '307') else node.mode if node.mode in ('302', '307') else '302'
                    if redirect_url is not UNSET:
                        node.result = redirect_url
            else:
                if replacement is not UNSET:
                    node.result = replacement
                if data is not UNSET:
                    node.result = data
                if content_type is not UNSET:
                    node.content_type = content_type
            validate_http(node)
            modified += before != node.fields
        logger.info('Quantumult X rewrite update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
        if matching:
            if modified:
                self._changed()
            return
        if family == 'request-url':
            mode = reject_type if reject_type is not UNSET else str(status_code) if status_code is not UNSET else rewrite_type if rewrite_type is not UNSET else '302' if redirect_url is not UNSET else 'reject'
            tail = '' if mode in REJECT_MODES else ' ' + single_line(redirect_url if redirect_url is not UNSET else None, 'redirect_url')
        elif mode == 'echo-response':
            tail = ' ' + single_line(content_type if content_type is not UNSET else None, 'content_type') + ' echo-response ' + single_line(data if data is not UNSET else None, 'data')
        else:
            tail = (' ' + match_pattern + ' ' + mode if processor else '') + ' ' + single_line(replacement if replacement is not UNSET else None, 'replacement')
        prefix = url_pattern + (' ' + header if header is not None else '')
        node = QuantumultHTTPNode(prefix + ' ' + method + ' ' + mode + tail)
        validate_http(node)
        nodes.insert(index, node)
        self._changed()

    add_rewrite = add_url_rewrite

    def add_native_rule(self, content, insert=None):
        return self._add_native('filter_local', content, insert)

    def _add_native(self, section, content, insert=None):
        from rule_framework.native_input import validate_native_entry
        native_scope = validate_native_entry(self, content, kind='declaration', section=section)
        single_line(content, 'Native input')
        nodes, index = self._insert_index(section, insert)
        node = self._parse_line(content, section)
        if isinstance(node, QuantumultRuleNode):
            try:
                validate_quantumult_value(node.type.upper(), node.value)
                validate_quantumult_policy(node.policy)
                validate_quantumult_options(node.options)
            except ValueError:
                pass
            else:
                if any(isinstance(item, QuantumultRuleNode) and item.identity == node.identity for item in nodes):
                    return self.add_rule(node.type, node.value, policy=node.policy, options=node.options, insert=insert)
        if isinstance(node, QuantumultHTTPNode):
            try:
                validate_http(node)
            except ValueError:
                pass
            else:
                matching = [item for actual_section, bucket in self._buckets() if actual_section == section
                            for item in bucket if isinstance(item, QuantumultHTTPNode) and item.identity == node.identity]
                modified = 0
                for item in matching:
                    before = item.fields
                    item.mode, item.result, item.content_type = node.mode, node.result, node.content_type
                    modified += before != item.fields
                if matching:
                    logger.info('Quantumult X native identity update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
        if isinstance(node, QuantumultLocalScriptNode):
            try:
                validate_local_script(node)
            except ValueError:
                pass
            else:
                matching = [item for actual_section, bucket in self._buckets() if actual_section == section
                            for item in bucket if isinstance(item, QuantumultLocalScriptNode) and item.identity == node.identity]
                modified = 0
                for item in matching:
                    before = dict(item.fields)
                    item.fields.update(node.fields)
                    validate_local_script(item)
                    modified += before != item.fields
                if matching:
                    logger.info('Quantumult X native local identity update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
        if not any(item.render() == content for item in nodes):
            node._qx_baseline_line = content
            node._qx_native = native_scope[1] != 'known-fields'
            if native_scope[1] == 'unknown':
                node._opaque_native_line = content
            nodes.insert(index, node)
            self._changed()

    def add_script(self, script, insert=None):
        if isinstance(script, str):
            single_line(script, 'Native script')
            if not re.search(r'\surl(?:-and-header)?\s', script):
                for section in ('task_local', 'http_backend'):
                    try:
                        node = QuantumultLocalScriptNode(script, section)
                        validate_local_script(node)
                    except ValueError:
                        continue
                    return self._add_native(section, script, insert)
            return self._add_native('rewrite_local', script, insert)
        if not isinstance(script, dict):
            raise ValueError('Quantumult X script must be a dictionary or explicit native string')
        if script.get('type') in LOCAL_SCRIPT_TYPES:
            return self._add_local_script(script, insert)
        unknown = set(script) - {'type', 'pattern', 'script_path'}
        if unknown:
            raise ValueError(f'Unsupported Quantumult X script fields: {sorted(unknown)}')
        mode = script.get('type')
        if not isinstance(mode, str) or mode not in SCRIPT_MODES:
            raise ValueError('Quantumult X HTTP script type must declare a supported script stage')
        pattern = single_line(script.get('pattern'), 'pattern')
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(f'Invalid structured script regex: {error}') from error
        result = script.get('script_path', UNSET)
        if result is not UNSET:
            single_line(result, 'script_path')
        nodes, index = self._insert_index('rewrite_local', insert)
        all_nodes = [node for section, bucket in self._buckets() if section == 'rewrite_local' for node in bucket]
        self._require_known_identity(all_nodes, pattern, scripts=True)
        matching = [node for node in all_nodes if isinstance(node, QuantumultHTTPNode)
                    and node.identity == (mode, pattern, 'url', None, None)]
        modified = 0
        for node in matching:
            validate_http(node)
            if result is not UNSET and result != node.result:
                node.result = result
                modified += 1
        logger.info('Quantumult X script update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
        if matching:
            if modified:
                self._changed()
            return
        if result is UNSET:
            raise ValueError('A new Quantumult X script requires script_path')
        node = QuantumultHTTPNode(pattern + ' url ' + mode + ' ' + result)
        validate_http(node)
        nodes.insert(index, node)
        self._changed()

    def _add_local_script(self, script, insert=None):
        unknown = set(script) - {'type', 'pattern', 'cronexp', 'script_path', 'name', 'img_url', 'enabled', 'require_devices'}
        if unknown:
            raise ValueError(f'Unsupported Quantumult X local script fields: {sorted(unknown)}')
        stage = script['type']
        section = 'http_backend' if stage == 'http-backend' else 'task_local'
        if self.is_snippet:
            raise ValueError('Quantumult X local task/backend declarations require their profile section')
        schedule = script.get('cronexp')
        if stage == 'cron':
            from rule_framework.surge import validate_cron
            validate_cron(schedule)
        elif 'cronexp' in script:
            raise ValueError('cronexp requires type=cron')
        if stage == 'http-backend':
            validate_regex(script.get('pattern'), 'backend pattern')
        elif 'pattern' in script:
            raise ValueError('Local event/cron declarations have no URL match pattern')
        devices = script.get('require_devices', [])
        if not isinstance(devices, list) or any(not isinstance(device, str) or not device.strip()
                or any(c.isspace() or c in ',#;' for c in device) for device in devices):
            raise ValueError('Quantumult X require_devices must be a list of non-empty device IDs')
        fields = {}
        for public, native in (('script_path', 'script-path'), ('name', 'tag'), ('img_url', 'img-url')):
            if public in script:
                fields[native] = single_line(script[public], public)
        if 'enabled' in script:
            if not isinstance(script['enabled'], bool):
                raise ValueError('Quantumult X script enabled must be a boolean')
            fields['enabled'] = str(script['enabled']).lower()
        if devices:
            fields['require-devices'] = ', '.join(devices)
        if stage == 'http-backend':
            fields['path'] = script['pattern']
        identity = (stage, script['pattern'] if stage == 'http-backend' else schedule, tuple(sorted(devices)))
        nodes, index = self._insert_index(section, insert)
        matching = [node for key in self.section_order if self._section_names[key] == section
                    for node in self.sections[key] if isinstance(node, QuantumultLocalScriptNode) and node.identity == identity]
        modified = 0
        for node in matching:
            validate_local_script(node)
            before = dict(node.fields)
            for field, value in fields.items():
                node.fields[field] = value
            validate_local_script(node)
            modified += before != node.fields
        logger.info('Quantumult X local script update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
        if matching:
            if modified:
                self._changed()
            return
        path = single_line(fields.pop('script-path', None), 'script_path')
        prefix = (schedule + ' ' if stage == 'cron' else stage + ' ' if stage.startswith('event-') else '') + path
        node = QuantumultLocalScriptNode(prefix + ''.join(', ' + key + '=' + value for key, value in fields.items()), section)
        validate_local_script(node)
        nodes.insert(index, node)
        self._changed()

    def _require_known_identity(self, nodes, pattern, *, scripts=False):
        for node in nodes:
            if not isinstance(node, QuantumultUnknownNode):
                continue
            raw = split_comment(node.render())[0]
            first = re.match(r'\s*("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\S+)', raw)
            if first and ((pattern is not None and unquote(first.group(1)) == pattern)
                          or scripts and re.search(r'\surl(?:-and-header)?\s+script-', raw)):
                raise ValueError(f'Cannot recognize required Quantumult X declaration identity at {self.filepath}: {raw!r}')

    def add_mitm(self, hostnames, insert=None):
        validate_hostnames(hostnames)
        nodes, index = self._insert_index('mitm', insert)
        matching = [node for _, bucket in self._buckets() for node in bucket if isinstance(node, QuantumultMITMNode)]
        if matching:
            node = matching[0]
            validate_hostnames(node.hostnames)
            existing = {canonical_domain(host) for item in matching for host in item.hostnames}
            changed = False
            for host in hostnames:
                if canonical_domain(host) not in existing:
                    node.hostnames.append(host)
                    existing.add(canonical_domain(host))
                    changed = True
            if changed:
                self._changed()
            return
        unique = []
        seen = set()
        for host in hostnames:
            if canonical_domain(host) not in seen:
                unique.append(host)
                seen.add(canonical_domain(host))
        nodes.insert(index, QuantumultMITMNode('hostname = ' + ', '.join(unique)))
        self._changed()

    def remove_mitm(self, hostnames):
        validate_hostnames(hostnames)
        selectors = {canonical_domain(host) for host in hostnames}
        removed = 0
        for _, nodes in self._buckets():
            kept = []
            for node in nodes:
                if isinstance(node, QuantumultMITMNode):
                    validate_hostnames(node.hostnames)
                    hosts = [host for host in node.hostnames if canonical_domain(host) not in selectors]
                    removed += len(node.hostnames) - len(hosts)
                    node.hostnames = hosts
                    if not hosts:
                        continue
                kept.append(node)
            nodes[:] = kept
        if removed:
            self._changed()
        logger.info('Quantumult X MITM removal matched=%s in %s', removed, self.filepath)

    def remove_rewrite(self, pattern):
        single_line(pattern, 'url_pattern')
        removed = 0
        for section, nodes in self._buckets():
            if section != 'rewrite_local':
                continue
            self._require_known_identity(nodes, pattern)
            kept = [node for node in nodes if not (isinstance(node, QuantumultHTTPNode)
                    and node.mode not in SCRIPT_MODES and node.match_pattern == pattern)]
            removed += len(nodes) - len(kept)
            nodes[:] = kept
        if removed:
            self._changed()
        logger.info('Quantumult X rewrite removal matched=%s in %s', removed, self.filepath)

    def remove_script(self, name=None, pattern=None, script_path=None):
        if all(value is None for value in (name, pattern, script_path)):
            raise ValueError('remove_script requires an explicit name, pattern or script_path')
        for field, value in (('name', name), ('pattern', pattern), ('script_path', script_path)):
            if value is not None:
                single_line(value, field)
        removed = 0
        for section, nodes in self._buckets():
            if section not in ('rewrite_local', 'task_local', 'http_backend'):
                continue
            if section == 'rewrite_local':
                self._require_known_identity(nodes, pattern, scripts=True)
            kept = []
            for node in nodes:
                selected = False
                if isinstance(node, QuantumultHTTPNode) and node.mode in SCRIPT_MODES:
                    selected = (name is None and (pattern is not None or script_path is not None)
                                and (pattern is None or node.match_pattern == pattern)
                                and (script_path is None or node.result == script_path))
                elif isinstance(node, QuantumultLocalScriptNode):
                    selected = (name is None or node.fields.get('tag') == name) and (pattern is None or node.fields.get('path') == pattern) and (script_path is None or node.fields['script-path'] == script_path)
                elif isinstance(node, QuantumultUnknownNode) and section in ('task_local', 'http_backend'):
                    raise ValueError(f'Cannot recognize required Quantumult X script selector at {self.filepath} [{section}]: {node.render()!r}')
                if selected:
                    removed += 1
                else:
                    kept.append(node)
            nodes[:] = kept
        if removed:
            self._changed()
        logger.info('Quantumult X script removal matched=%s in %s', removed, self.filepath)

    def _buckets(self):
        yield 'rewrite_local' if self.is_snippet else None, self.header_nodes
        for key in self.section_order:
            yield self._section_names[key], self.sections[key]

    def _host_matches(self, pattern, value, section, line):
        try:
            references = url_host_references(pattern)
        except ReferenceRecognitionError as error:
            raise ValueError(f'Cannot recognize required Quantumult X URL host reference at {self.filepath} [{section}]:{line}: {error}') from error
        return value is None or references.contains(value)

    def remove_rule(self, rule_type, value=None, *, conditions=UNSET):
        if conditions is not UNSET:
            validate_quantumult_conditions(conditions)
        native_types = ({quantumult_native_type(rule_type, value)} if rule_type in ('domain_suffix', 'domain_wildcard')
                        else {quantumult_native_type(kind, value) for kind in select_rule_types(rule_type)})
        if rule_type == 'domain' and value is not None:
            validate_domain_selector(value)
        removed = 0
        for section, nodes in self._buckets():
            kept = []
            for line, node in enumerate(nodes, 1):
                selected = False
                if section == 'filter_local' and isinstance(node, QuantumultRuleNode):
                    native_type = node.type.upper()
                    if native_type in native_types:
                        selected = value is None or (canonical_domain(node.value) == canonical_domain(value)
                            if native_type in SEMANTIC_TYPES['domain'] else node.value == value)
                    elif rule_type == 'domain' and native_type not in {'HOST', 'HOST-SUFFIX', 'HOST-WILDCARD',
                            'HOST-KEYWORD', 'USER-AGENT', 'IP-CIDR', 'IP6-CIDR', 'IP-ASN', 'GEOIP', 'FINAL'}:
                        raise ValueError(f'Cannot recognize required Quantumult X rule reference at {self.filepath} [{section}]:{line}')
                elif rule_type == 'domain':
                    if section == 'rewrite_local' and isinstance(node, QuantumultHTTPNode):
                        selected = self._host_matches(node.match_pattern, value, section, line)
                    elif isinstance(node, QuantumultMITMNode):
                        try:
                            validate_hostnames(node.hostnames)
                        except ValueError as error:
                            raise ValueError(f'Cannot recognize required Quantumult X MITM reference at {self.filepath}:{line}: {error}') from error
                        hosts = [host for host in node.hostnames if value is not None and
                                 canonical_domain(host if host.startswith('[') else host.rsplit(':', 1)[0]) != canonical_domain(value)]
                        removed += len(node.hostnames) - len(hosts)
                        node.hostnames = hosts
                        selected = not hosts
                    elif isinstance(node, QuantumultUnknownNode) and section in ('filter_local', 'rewrite_local'):
                        raise ValueError(f'Cannot recognize required Quantumult X domain reference at {self.filepath} [{section}]:{line}: {node.render()!r}')
                if selected:
                    removed += 1
                else:
                    kept.append(node)
            nodes[:] = kept
        if removed:
            self._changed()
        logger.info('Quantumult X domain/rule removal matched=%s in %s', removed, self.filepath)

    def modify(self, search, replace, is_regex=False, count=0):
        from collections import Counter
        from rule_framework.fom import _apply_text_replacement
        original, _, _ = decode_text(self.render_bytes())
        updated, _ = _apply_text_replacement(original, search, replace, is_regex, count)
        if updated == original:
            return
        unchanged = Counter((section, node.render(), getattr(node, 'line_ending', self._newline))
                            for section, nodes in self._buckets() for node in nodes)
        self._parse_text(updated)
        for section, nodes in self._buckets():
            for node in nodes:
                identity = section, node.render(), node.line_ending
                if unchanged[identity]:
                    unchanged[identity] -= 1
                else:
                    node._qx_changed = True
        self.validate()
        self._changed()

    def _changed(self):
        self.is_dirty = True
        self.update_metadata(only_if_changed=True)

    def update_metadata(self, *, only_if_changed=False):
        metadata_before = self.render_bytes() if not only_if_changed else None
        from collections import Counter
        from rule_framework.fom import _get_now
        counts = Counter(node.type.upper() for node in self._all_nodes() if isinstance(node, QuantumultRuleNode))
        for node in self._all_nodes():
            if isinstance(node, QuantumultHTTPNode):
                counts['SCRIPT' if node.mode in SCRIPT_MODES else 'REJECT' if node.mode in REJECT_MODES else 'REDIRECT' if node.mode in ('302', '307') else 'HTTP-PROCESSOR'] += 1
                if node.mode in SCRIPT_MODES:
                    counts['HTTP-REQUEST-SCRIPT' if node.mode.startswith('script-request-') else 'HTTP-RESPONSE-SCRIPT'] += 1
            elif isinstance(node, QuantumultLocalScriptNode):
                counts['SCRIPT'] += 1
            elif isinstance(node, QuantumultMITMNode):
                counts['MITM'] += len(node.hostnames)
        total = sum(value for key, value in counts.items() if key not in ('HTTP-REQUEST-SCRIPT', 'HTTP-RESPONSE-SCRIPT'))
        known_counts = {'HOST', 'HOST-SUFFIX', 'HOST-WILDCARD', 'HOST-KEYWORD', 'USER-AGENT', 'IP-CIDR', 'IP6-CIDR', 'IP-ASN', 'GEOIP', 'FINAL', 'SCRIPT', 'HTTP-REQUEST-SCRIPT', 'HTTP-RESPONSE-SCRIPT', 'REJECT', 'REDIRECT', 'MITM', 'HTTP-PROCESSOR'}
        from rule_framework.metadata import restore_unchanged_ini_metadata, remember_ini_metadata
        if only_if_changed and restore_unchanged_ini_metadata(self, known_counts):
            return
        for node in self.header_nodes:
            if isinstance(node, CommentNode) and (match := re.fullmatch(r'(\s*#\s+)([\w-]+)(:\s*)(.*?)([ \t]*)', node.render())):
                key = match.group(2).upper()
                value = str(total) if key == 'TOTAL' else (_get_now(self) if key == 'UPDATED' else str(counts[key]) if key in known_counts else None)
                if value is not None:
                    node.content = match.group(1) + match.group(2) + match.group(3) + value + match.group(5)
        settings = getattr(self, 'settings', {})
        from rule_framework.metadata import resolve_signature
        author, repo = resolve_signature(settings)
        author_re = re.compile(r'^\s*#\s*AUTHOR:\s*(.*?)\s*$', re.I)
        repo_re = re.compile(r'^\s*#\s*REPO:\s*(.*?)\s*$', re.I)
        authors = [(i, author_re.fullmatch(node.render())) for i, node in enumerate(self.header_nodes)]
        own = next((i for i, match in authors if match and match.group(1).strip() == author), None)
        additions = []
        if own is None:
            additions.append(CommentNode(f'# AUTHOR: {author}'))
        if not any((m := repo_re.fullmatch(node.render())) and m.group(1).strip() == repo for node in self.header_nodes):
            additions.append(CommentNode(f'# REPO: {repo}'))
        if additions:
            index = own + 1 if own is not None else next((i for i, match in authors if match), 0)
            self.header_nodes[index:index] = additions
        remember_ini_metadata(self, known_counts, only_if_changed, before=metadata_before)


    def validate_complete(self):
        if self.render_bytes() != self._metadata_baseline:
            self._changed()
            self._metadata_baseline = self.render_bytes()

    def validate(self):
        super().validate()
        if self.client != 'Quantumult X' or self.file_role not in ('rewrite-fragment', 'full-profile', 'configuration-fragment'):
            raise ValueError('Invalid Quantumult X client or file purpose')
        if self._newline not in ('\r', '\n', '\r\n') or not isinstance(self.ends_with_newline, bool):
            raise ValueError('Invalid Quantumult X newline state')
        if not isinstance(self.is_dirty, bool) or not isinstance(self._metadata_baseline, bytes):
            raise ValueError('Invalid Quantumult X managed state')
        if set(self.section_order) != set(self.sections) or set(self.sections) != set(self._section_names):
            raise ValueError('Quantumult X sections and section order must retain their identities')
        if len(self.section_order) != len(set(self.section_order)):
            raise ValueError('Quantumult X section order must retain each section identity once')
        if self.is_snippet and self.sections:
            raise ValueError('Quantumult X rewrite fragments retain sectionless purpose')
        for section, nodes in self._buckets():
            for node in nodes:
                rendered = getattr(node, 'raw_section_line', node.render())
                if not isinstance(node, ASTNode) or any(c in rendered for c in '\r\n\0'):
                    raise ValueError('Quantumult X node must occupy one line')
                if getattr(node, 'line_ending', self._newline) not in ('', '\r', '\n', '\r\n'):
                    raise ValueError('Invalid Quantumult X node newline')
                changed = getattr(node, '_qx_changed', False) or rendered != getattr(node, '_qx_baseline_line', None)
                if isinstance(node, SectionNode):
                    if node.name != section or section is None or not isinstance(node.name, str):
                        raise ValueError('Quantumult X section node must retain its declared placement')
                    if changed and node.name not in {'general', 'dns', 'policy', 'server_local', 'server_remote',
                            'filter_local', 'filter_remote', 'rewrite_local', 'rewrite_remote', 'task_local', 'http_backend', 'mitm'}:
                        raise ValueError('Changed Quantumult X section syntax is unrecognized')
                elif isinstance(node, QuantumultHTTPNode):
                    if section != 'rewrite_local':
                        raise ValueError('Quantumult X HTTP declarations belong in rewrite_local')
                    if changed:
                        validate_http(node)
                        parsed = QuantumultHTTPNode(rendered)
                        if parsed.fields != node.fields:
                            raise ValueError('Changed Quantumult X HTTP fields have inconsistent rendered syntax')
                elif isinstance(node, QuantumultLocalScriptNode):
                    if section != node.section:
                        raise ValueError('Quantumult X local script must retain its execution section')
                    if changed:
                        validate_local_script(node)
                        parsed = QuantumultLocalScriptNode(rendered, section)
                        if parsed.identity != node.identity or parsed.fields != node.fields:
                            raise ValueError('Changed Quantumult X local script has inconsistent rendered syntax')
                elif isinstance(node, QuantumultMITMNode):
                    if section not in ('mitm', 'rewrite_local') or section == 'rewrite_local' and not self.is_snippet:
                        raise ValueError('Quantumult X MITM hostnames belong in mitm or a sectionless rewrite fragment')
                    if changed:
                        validate_hostnames(node.hostnames)
                        if QuantumultMITMNode(rendered).hostnames != node.hostnames:
                            raise ValueError('Changed Quantumult X MITM fields have inconsistent rendered syntax')
                elif isinstance(node, QuantumultRuleNode):
                    if section != 'filter_local':
                        raise ValueError('Quantumult X routing declarations belong in filter_local')
                    if changed:
                        validate_quantumult_value(node.type.upper(), node.value)
                        validate_quantumult_policy(node.policy)
                        validate_quantumult_options(node.options)
                        parsed = parse_quantumult_line(rendered)
                        if parsed.identity != node.identity or parsed.policy != node.policy or parsed.options != node.options:
                            raise ValueError('Changed Quantumult X rule has inconsistent rendered syntax')
                elif changed and not getattr(node, '_qx_native', False):
                    if isinstance(node, BlankNode):
                        valid = not rendered.strip()
                    else:
                        valid = isinstance(node, CommentNode) and not isinstance(node, QuantumultUnknownNode) and rendered.lstrip().startswith(('#', ';', '//'))
                    if not valid:
                        raise ValueError('Changed Quantumult X structured syntax is unrecognized')




def recognizes_quantumult_snippet(filepath, data=None):
    """Sectionless URL grammar is an explicit syntax clue for shared .snippet."""
    if data is not None:
        text, _, _ = decode_text(data)
    elif not Path(filepath).is_file():
        return False
    else:
        text, _, _ = decode_text(Path(filepath).read_bytes())
    active = [line for line in text.splitlines() if line.strip()
              and not line.lstrip().startswith(('#', ';', '//'))]
    return bool(active) and not any(re.match(r'\s*\[', line) for line in active) and any(
        re.search(r'\surl(?:-and-header)?\s', line) or re.match(r'\s*hostname\s*=', line)
        for line in active)

"""Role-aware, lossless Surge profiles, fragments and modules."""
from rule_framework.text_json import split_physical_lines

from rule_framework.logical_refs import is_parenthesized_payload

from pathlib import Path
import logging
import re

from rule_framework.ast import (ASTNode, BlankNode, CommentNode, RuleNode, SectionNode,
    get_comma_indices_at_depth_0, RewriteNode, ScriptNode, MITMNode)
from rule_framework.fom import INIFileFOM, _get_now
from rule_framework.rule_helpers import (UNSET, calculate_insert_index, condition_options,
    native_rule_type, rule_identity, validate_options, validate_standard_value,
    select_rule_types, validate_domain_selector, STANDARD_TYPES, SEMANTIC_TYPES)
from rule_framework.text_json import decode_text, encode_text, serialize_physical_nodes
from rule_framework.domain_refs import canonical_domain, url_host_references, ReferenceRecognitionError

logger = logging.getLogger('RuleFramework')


def split_comment(line):
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == '\\':
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
        elif char in '\"\'':
            quote = char
        elif index and line[index - 1].isspace() and (char in '#;' or line[index:index + 2] == '//'):
            start = index
            while start and line[start - 1].isspace():
                start -= 1
            return line[:start], line[start:]
    return line, ''


def padded(old, value):
    return old[:len(old) - len(old.lstrip())] + value + old[len(old.rstrip()):]


def unquote(value):
    return value[1:-1] if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0] else value


def single_line(value, field, *, empty=False):
    if not isinstance(value, str) or (not empty and not value.strip()) or any(c in value for c in '\r\n\0'):
        raise ValueError(f'{field} must be a {"possibly empty" if empty else "non-empty"} single-line string')
    return value


def token_spans(content):
    spans = list(re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s]+', content))
    # Every quote starts/ends a whole token; otherwise identity is unknown.
    for item in spans:
        token = item.group()
        if token[0] in ('"', "'") and (len(token) < 2 or token[-1] != token[0]):
            raise ValueError('Unclosed quoted field')
    return spans



def validate_new_regex(value):
    single_line(value, 'Regex match condition')
    try:
        re.compile(value)
    except re.error as error:
        raise ValueError(f'Invalid or unsupported structured regex: {error}; explicit native input retains unverified client syntax') from error


class SurgeURLRewriteNode(RewriteNode):
    def __init__(self, line):
        content, self.inline_comment = split_comment(line)
        self.spans = token_spans(content)
        values = [unquote(item.group()) for item in self.spans]
        if len(values) not in (2, 3):
            raise ValueError('URL Rewrite requires pattern, replacement and optional type')
        mode = values[2] if len(values) == 3 else ('reject' if values[1] == 'reject' else 'header')
        if mode not in ('header', '302', '307', 'reject'):
            raise ValueError(f'Unrecognized Surge URL Rewrite type: {mode}')
        super().__init__(content, values[0])
        self.replacement = '_' if len(values) == 2 and mode == 'reject' else values[1]
        self.mode = mode
        self._baseline = (self.match_pattern, self.replacement, self.mode)

    def render(self):
        fields = [self.match_pattern, self.replacement, self.mode]
        if (self.match_pattern, self.replacement, self.mode) == self._baseline:
            return self.content + self.inline_comment
        result, cursor = '', 0
        for index, item in enumerate(self.spans):
            result += self.content[cursor:item.start()]
            original = item.group()
            value = fields[index]
            result += original if unquote(original) == value else (('"' + value + '"') if any(c.isspace() for c in value) else value)
            cursor = item.end()
        if len(self.spans) == 2:
            result += ' ' + self.mode
        return result + self.content[cursor:] + self.inline_comment


class SurgeMapLocalNode(RewriteNode):
    def __init__(self, line):
        content, self.inline_comment = split_comment(line)
        pattern = re.match(r'\s*("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\S+)', content)
        if not pattern:
            raise ValueError('Map Local requires a URL pattern')
        self.pattern_span = pattern.span(1)
        super().__init__(content, unquote(pattern.group(1)))
        self.fields = {}
        self.field_spans = {}
        cursor = pattern.end()
        while cursor < len(content):
            token = re.match(r'\s+([\w-]+)=("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s]+)', content[cursor:])
            if not token:
                if not content[cursor:].strip():
                    break
                raise ValueError('Unrecognizable Map Local field')
            key = token.group(1)
            if key in self.fields:
                raise ValueError(f'Duplicate Map Local field {key}')
            self.fields[key] = unquote(token.group(2))
            self.field_spans[key] = (cursor + token.start(2), cursor + token.end(2))
            cursor += token.end()
        self._baseline = dict(self.fields)
        self._original_pattern = self.match_pattern

    def render(self):
        result = self.content
        for key, (start, end) in sorted(self.field_spans.items(), key=lambda entry: entry[1][0], reverse=True):
            value = self.fields[key]
            if value == self._baseline[key]:
                continue
            old = self.content[start:end]
            quoted = old[0] in ('"', "'") or any(char.isspace() for char in value)
            result = result[:start] + (('"' + value.replace('"', r'\"') + '"') if quoted else value) + result[end:]
        for key, value in self.fields.items():
            if key not in self.field_spans:
                result += ' ' + key + '=' + (('"' + value.replace('"', r'\"') + '"') if key in ('data', 'header') or any(c.isspace() for c in value) else value)
        if self.match_pattern != self._original_pattern:
            validate_new_regex(self.match_pattern)
            start, end = self.pattern_span
            old = self.content[start:end]
            quote = old[0] if old[0] in ('"', "'") else ('"' if any(char.isspace() for char in self.match_pattern) else '')
            result = result[:start] + quote + self.match_pattern + quote + result[end:]
            if SurgeMapLocalNode(result).match_pattern != self.match_pattern:
                raise ValueError('Changed Map Local URL pattern has inconsistent native quoting')
        return result + self.inline_comment


def validate_map_local(fields):
    unknown = set(fields) - {'data', 'data-type', 'status-code', 'header'}
    if unknown:
        raise ValueError(f'Unrecognized Map Local fields required by mutation: {sorted(unknown)}')
    kind = fields.get('data-type', 'file')
    if kind not in ('file', 'text', 'tiny-gif', 'base64'):
        raise ValueError('Map Local data_type must be file, text, tiny-gif or base64')
    if kind != 'tiny-gif' and 'data' not in fields:
        raise ValueError('Map Local data is required for this data_type')
    if 'data' in fields:
        single_line(fields['data'], 'Map Local data', empty=kind in ('text', 'base64', 'tiny-gif'))
    if kind == 'base64':
        import base64
        try:
            base64.b64decode(fields['data'], validate=True)
        except Exception as error:
            raise ValueError('Map Local base64 data is invalid') from error
    if 'header' in fields:
        single_line(fields['header'], 'Map Local headers', empty=True)
    if 'status-code' in fields and (not re.fullmatch(r'[0-9]+', fields['status-code'])
                                  or not 200 <= int(fields['status-code']) <= 999):
        raise ValueError('Map Local status_code must be an integer in range 200..999')


SCRIPT_FIELDS = {'type', 'pattern', 'cronexp', 'script-path', 'requires-body', 'max-size',
    'binary-body-mode', 'full-header-mode', 'script-update-interval', 'timeout', 'argument',
    'engine', 'debug', 'wake-system'}
SCRIPT_BOOLS = {'requires-body', 'binary-body-mode', 'full-header-mode', 'debug', 'wake-system'}


def native_value(value, *, quoted=False):
    if quoted or not value or any(c.isspace() for c in value) or ',' in value or value.startswith(('#', ';', '//')) or '"' in value:
        return '"' + value.replace('"', r'\"') + '"'
    return value


class SurgeScriptNode(ScriptNode):
    def __init__(self, line):
        content, self.inline_comment = split_comment(line)
        label = re.match(r'([^=]+)=(.*)', content)
        if not label:
            raise ValueError('Unrecognizable Surge script assignment')
        self.name_span = (0, label.end(1))
        self.fields, self.field_spans = {}, {}
        commas = get_comma_indices_at_depth_0(content)
        boundaries = [label.start(2)] + [i + 1 for i in commas if re.match(r'\s*[\w-]+\s*=', content[i + 1:])]
        for index, start in enumerate(boundaries):
            end = boundaries[index + 1] - 1 if index < len(boundaries) - 1 else len(content)
            raw = content[start:end]
            field = re.fullmatch(r'(\s*)([\w-]+)(\s*=\s*)(.*?)([ \t]*,?[ \t]*)', raw)
            if not field or not field.group(4):
                raise ValueError('Unrecognizable script parameter')
            key = field.group(2)
            if key in self.fields:
                raise ValueError(f'Duplicate script parameter: {key}')
            value = field.group(4)
            self.fields[key] = unquote(value)
            self.field_spans[key] = (start + field.start(4), start + field.end(4))
        super().__init__(content, self.fields.get('pattern'), name=label.group(1).strip())
        self._baseline = dict(self.fields)
        self._original_name = self.name

    @property
    def identity(self):
        stage = self.fields.get('type', 'generic')
        return stage, self.fields.get('pattern') if stage.startswith('http-') else self.fields.get('cronexp')

    def render(self):
        result = self.content
        for key, (start, end) in sorted(self.field_spans.items(), key=lambda entry: entry[1][0], reverse=True):
            value = self.fields[key]
            if value == self._baseline[key]:
                continue
            old = self.content[start:end]
            result = result[:start] + native_value(value, quoted=old[0] in ('"', "'")) + result[end:]
        for key, value in self.fields.items():
            if key not in self.field_spans:
                result += ('' if result.rstrip().endswith(',') else ',') + key + '=' + native_value(value)
        if self.name != self._original_name:
            result = padded(self.content[:self.name_span[1]], self.name) + result[self.name_span[1]:]
        return result + self.inline_comment


def unknown_script_requires_identity(line, identity):
    """Keep undecidable declarations guarded; exclude a known unrelated condition."""
    content, _comment = split_comment(line)
    assignment = re.match(r'([^=]+)=(.*)', content)
    if not assignment:
        return True
    boundaries = [assignment.start(2)] + [index + 1 for index in get_comma_indices_at_depth_0(content)
        if re.match(r'\s*[\w-]+\s*=', content[index + 1:])]
    identity_fields = []
    for index, start in enumerate(boundaries):
        end = boundaries[index + 1] - 1 if index < len(boundaries) - 1 else len(content)
        field = content[start:end]
        key = re.match(r'\s*([\w-]+)\s*=', field)
        if not key:
            return True
        if key[1] in {'type', 'pattern', 'cronexp'}:
            identity_fields.append(field)
    try:
        parsed = SurgeScriptNode('guard = ' + ','.join(identity_fields))
    except ValueError:
        return True
    if parsed.identity[0] not in {'http-request', 'http-response', 'cron'} or parsed.identity[1] is None:
        return True
    return parsed.identity == identity


def validate_cron(value):
    single_line(value, 'cronexp')
    fields = value.split()
    if len(fields) not in (5, 6):
        raise ValueError('cronexp requires five or six fields')
    limits = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
    if len(fields) == 6:
        limits.insert(0, (0, 59))
    months = {name: index + 1 for index, name in enumerate(('jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec'))}
    days = {name: index for index, name in enumerate(('sun','mon','tue','wed','thu','fri','sat'))}
    for index, (field, (low, high)) in enumerate(zip(fields, limits)):
        names = months if index == len(fields) - 2 else (days if index == len(fields) - 1 else {})
        for item in field.lower().split(','):
            pieces = item.split('/')
            if len(pieces) > 2 or (len(pieces) == 2 and (not pieces[1].isdigit() or not 1 <= int(pieces[1]) <= high + 1)):
                raise ValueError('Invalid cron step')
            base = pieces[0]
            if base == '*':
                continue
            values = base.split('-')
            if len(values) > 2:
                raise ValueError('Invalid cron range')
            numbers = []
            for part in values:
                number = names.get(part, int(part) if part.isdigit() else None)
                if number is None or not low <= number <= high:
                    raise ValueError(f'Cron field outside valid range {low}..{high}')
                numbers.append(number)
            if len(numbers) == 2 and numbers[0] > numbers[1]:
                raise ValueError('Invalid reversed cron range')


def validate_script(fields):
    unknown = set(fields) - SCRIPT_FIELDS
    if unknown:
        raise ValueError(f'Unrecognized script fields required by mutation: {sorted(unknown)}')
    stage = fields.get('type')
    if stage not in ('http-request', 'http-response', 'cron'):
        raise ValueError('Structured Surge scripts require HTTP request/response or cron type')
    single_line(fields.get('script-path'), 'script_path')
    if stage.startswith('http-'):
        single_line(fields.get('pattern'), 'pattern')
        if 'cronexp' in fields or 'wake-system' in fields:
            raise ValueError('HTTP scripts cannot carry cron scheduling fields')
    else:
        validate_cron(fields.get('cronexp'))
        if set(fields) & {'pattern', 'requires-body', 'max-size', 'binary-body-mode', 'full-header-mode'}:
            raise ValueError('Cron scripts cannot carry HTTP body/match fields')
    for key in SCRIPT_BOOLS & fields.keys():
        if fields[key] not in ('true', 'false', '1', '0'):
            raise ValueError(f'{key} must be a Boolean')
    if 'max-size' in fields and (not re.fullmatch(r'-?[0-9]+', fields['max-size']) or int(fields['max-size']) < -1):
        raise ValueError('max_size must be an integer >= -1')
    for key in ('timeout', 'script-update-interval'):
        if key in fields:
            try:
                value = float(fields[key])
            except (ValueError, TypeError) as error:
                raise ValueError(f'{key} must be numeric') from error
            import math
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f'{key} must be positive')
    if 'engine' in fields and fields['engine'] not in ('auto', 'jsc', 'webview'):
        raise ValueError('engine must be auto, jsc or webview')


class SurgeUnknownNode(CommentNode):
    """Untouched native content; a required structural decision must fail."""


class SurgeMITMNode(MITMNode):
    def __init__(self, line):
        content, self.inline_comment = split_comment(line)
        match = re.fullmatch(r'(\s*(hostname(?:-disabled)?)\s*=\s*)((?:(?:%APPEND%|%INSERT%)\s*)?)(.*)', content)
        if not match:
            raise ValueError('Unrecognized MITM hostname assignment')
        self.prefix = match.group(1) + match.group(3)
        self.key = match.group(2)
        self.operator = match.group(3).strip()
        self.raw_hosts = match.group(4).split(',') if match.group(4) else []
        super().__init__([item.strip() for item in self.raw_hosts], content)
        self._baseline_hosts = tuple(self.hostnames)

    def render(self):
        if tuple(self.hostnames) == self._baseline_hosts:
            return self.raw_content + self.inline_comment
        fields = []
        for host in self.hostnames:
            old = next((field for field in self.raw_hosts if field.strip() == host), host)
            fields.append(old)
        if fields:
            fields[0] = fields[0].lstrip()
        return self.prefix + ','.join(fields) + self.inline_comment


def mitm_reference(value):
    single_line(value, 'MITM hostname')
    host = value[1:] if value.startswith('-') else value
    if host.startswith('<') and host.endswith('>'):
        return host
    host = re.sub(r':[0-9]+$', '', host)
    if re.search(r'[\s,%{}=/]', host):
        raise ValueError('Unrecognizable MITM hostname reference')
    return canonical_domain(host)


class SurgeRuleNode(RuleNode):
    def __init__(self, line):
        content, self.inline_comment = split_comment(line)
        commas = get_comma_indices_at_depth_0(content)
        boundaries = [-1, *commas, len(content)]
        self.fields = [content[boundaries[i] + 1:boundaries[i + 1]] for i in range(len(boundaries) - 1)]
        fields = [field.strip() for field in self.fields]
        final = fields[0].upper() == 'FINAL'
        if len(fields) < (2 if final else 3):
            raise ValueError('Surge routing entries require a policy')
        super().__init__(fields[0], '' if final else unquote(fields[1]), unquote(fields[1 if final else 2]))
        self.options = tuple(fields[2 if final else 3:])
        self._baseline = (self.type, self.value, self.policy, self.options)

    @property
    def identity(self):
        return rule_identity(self.type, self.value, self.options)

    def render(self):
        final = self.type.upper() == 'FINAL'
        values = [self.type, self.policy] if final else [self.type, self.value, self.policy]
        baseline = [self._baseline[0], self._baseline[2]] if final else list(self._baseline[:3])
        fields = [old if value == expected else padded(old, native_value(value, quoted=old.strip().startswith(('"', "'"))))
                  for old, value, expected in zip(self.fields, values, baseline)]
        if tuple(self.options) == self._baseline[3]:
            fields.extend(self.fields[len(values):])
        else:
            fields.extend(self.options)
            if not self.inline_comment:
                fields[-1] += self.fields[-1][len(self.fields[-1].rstrip()):]
        return ','.join(fields) + self.inline_comment


class SurgeFile(INIFileFOM):
    transaction_fields = INIFileFOM.transaction_fields + (
        'file_role', 'client', 'text_encoding', 'text_bom', '_newline', '_section_names',
        '_baseline_text',
    )

    def __init__(self, filepath):
        super().__init__(filepath)
        self.client = 'Surge'
        self.file_role = 'module' if Path(filepath).suffix.lower() == '.sgmodule' else 'configuration-fragment'
        self.text_encoding, self.text_bom = 'utf-8', b''
        self._newline = '\n'
        self._section_names = {}
        self._baseline_text = ''
        self.ends_with_newline = True

    @property
    def is_module(self):
        return self.file_role == 'module'

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
            node._surge_loaded = True
            node._surge_baseline_line = line
            if section is None:
                self.header_nodes.append(node)
            else:
                self.sections[section].append(node)
        if self.file_role != 'module':
            names = set(self._section_names.values())
            self.file_role = 'full-profile' if names & {'General', 'Proxy', 'Proxy Group'} or any(
                isinstance(node, SurgeRuleNode) and node.type.upper() == 'FINAL'
                for node in self.sections.get('Rule', [])) else 'configuration-fragment'

    def _parse_line(self, line, section):
        if not line.strip():
            return BlankNode(line)
        if line.lstrip().startswith(('#', ';', '//')):
            return CommentNode(line)
        if section == 'MITM' and re.match(r'\s*hostname(?:-disabled)?\s*=', line):
            try:
                return SurgeMITMNode(line)
            except ValueError:
                return SurgeUnknownNode(line)
        if section == 'Script':
            try:
                return SurgeScriptNode(line)
            except ValueError:
                pass
        if section == 'Map Local':
            try:
                return SurgeMapLocalNode(line)
            except ValueError:
                pass
        if section == 'URL Rewrite':
            try:
                return SurgeURLRewriteNode(line)
            except ValueError:
                pass
        if section == 'Rule':
            try:
                return SurgeRuleNode(line)
            except ValueError:
                pass
        return SurgeUnknownNode(line) if section in {'Rule', 'URL Rewrite', 'Map Local', 'Script', 'Header Rewrite', 'Body Rewrite'} else CommentNode(line)

    def _iter_sections(self, section=None):
        for key in self.section_order:
            name = self._section_names[key]
            if section is None or name == section:
                yield name, self.sections[key]

    def _section_nodes(self, section):
        for _, nodes in self._iter_sections(section):
            yield from nodes

    def render_bytes(self):
        nodes = self.header_nodes + [node for key in self.section_order for node in self.sections[key]]
        return serialize_physical_nodes(nodes, newline=self._newline,
            ends_with_newline=self.ends_with_newline, encoding=self.text_encoding, bom=self.text_bom)

    def save(self):
        self.validate()
        self.validate_complete()
        Path(self.filepath).write_bytes(self.render_bytes())

    def _ensure_section(self, name):
        if name not in self.sections:
            self.sections[name] = [SectionNode(name)]
            self.section_order.append(name)
            self._section_names[name] = name

    def _insert_index(self, section, insert):
        self._ensure_section(section)
        nodes = self.sections[section]
        index = calculate_insert_index(nodes, insert, True, section)
        if section == 'Rule':
            terminal = next((i for i, node in enumerate(nodes) if isinstance(node, SurgeRuleNode)
                             and node.type.upper() == 'FINAL'), None)
            if terminal is not None:
                if insert is None:
                    index = terminal
                elif index > terminal:
                    raise ValueError('Surge routing insertion must remain before FINAL')
        return index

    def _changed(self):
        self.is_dirty = True
        self.update_metadata(only_if_changed=True)

    def add_rule(self, rule_type, value, policy=UNSET, insert=None, *, conditions=UNSET, options=UNSET):
        rule_type = native_rule_type(rule_type, value, client='Surge')
        validate_standard_value(rule_type, value, client='Surge')
        index = self._insert_index('Rule', insert)
        rule_nodes = list(self._section_nodes('Rule'))
        selected = condition_options(conditions) if conditions is not UNSET else UNSET
        if selected is not UNSET:
            validate_options(selected, rule_type, 'Surge')
        if options is not UNSET:
            options = validate_options(options, rule_type, 'Surge')
        if policy is not UNSET and (not isinstance(policy, str) or not policy.strip() or any(
                token in policy for token in ',\r\n\0')):
            raise ValueError('Surge policy must be a non-empty single-line field')
        if self.is_module and policy is not UNSET and policy not in {'DIRECT', 'REJECT', 'REJECT-TINYGIF'}:
            raise ValueError('Surge module rules require internal policies: DIRECT, REJECT, REJECT-TINYGIF')
        if selected is not UNSET or options is not UNSET:
            for existing in rule_nodes:
                if isinstance(existing, SurgeRuleNode) and rule_identity(existing.type, existing.value)[:2] == rule_identity(rule_type, value)[:2]:
                    validate_options(existing.options, rule_type, 'Surge')
        matching = [node for node in rule_nodes if isinstance(node, SurgeRuleNode)
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
        satisfied = [node for node in rule_nodes if isinstance(node, SurgeRuleNode)
                     and node.identity == rule_identity(rule_type, value, actual_options)
                     and (policy is UNSET or node.policy == policy)]
        if satisfied:
            logger.info('Rule update already satisfied; matched=%s modified=0 in %s', len(satisfied), self.filepath)
            return
        if rule_type == 'URL-REGEX':
            validate_new_regex(value)
        raw_value = native_value(value) if rule_type == 'URL-REGEX' else value
        node = SurgeRuleNode(','.join([rule_type, raw_value, native_value(actual_policy), *actual_options]))
        self.sections['Rule'].insert(index, node)
        self._changed()


    def add_url_rewrite(self, raw_content=None, url_pattern=None, reject_type=UNSET,
                        redirect_url=UNSET, status_code=UNSET, insert=None):
        if raw_content is not None and (url_pattern is not None or any(value is not UNSET for value in (reject_type, redirect_url, status_code))):
            raise ValueError('Native rewrite content and structured rewrite fields are separate inputs')
        if reject_type == 'reject' and (redirect_url is not UNSET or status_code is not UNSET):
            raise ValueError('Reject and redirect results conflict')
        if reject_type == 'header' and status_code is not UNSET:
            raise ValueError('Header rewrite and redirect status conflict')
        response_rejects = {'reject-dict': '{}', 'reject-array': '[]', 'reject-200': '', 'reject-img': UNSET}
        if reject_type in response_rejects:
            if raw_content is not None or redirect_url is not UNSET or status_code is not UNSET:
                raise ValueError('Response reject intent cannot also supply redirect/status fields')
            self.add_map_local(url_pattern, data=response_rejects[reject_type],
                               data_type='tiny-gif' if reject_type == 'reject-img' else 'text', insert=insert)
            return
        index = self._insert_index('URL Rewrite', insert)
        if raw_content is not None:
            self._add_native('URL Rewrite', raw_content, insert)
            return
        single_line(url_pattern, 'url_pattern')
        pattern = unquote(url_pattern)
        self._require_known_identity('URL Rewrite', pattern)
        if reject_type is not UNSET and reject_type not in ('reject', 'header'):
            raise ValueError(f'Unsupported Surge URL rewrite result: {reject_type!r}')
        if redirect_url is not UNSET:
            single_line(redirect_url, 'redirect_url')
        if status_code is not UNSET and (type(status_code) is not int or status_code not in (302, 307)):
            raise ValueError('Surge URL rewrite status_code must be 302 or 307')
        matching = [node for node in self._section_nodes('URL Rewrite')
                    if isinstance(node, SurgeURLRewriteNode) and node.match_pattern == pattern]
        modified = 0
        for node in matching:
            before = node.render()
            if redirect_url is not UNSET:
                node.replacement = redirect_url
                if node.mode == 'reject':
                    node.mode = '302'
            if reject_type is not UNSET:
                node.mode = reject_type
                if reject_type == 'reject':
                    node.replacement = '_'
            if status_code is not UNSET:
                node.mode = str(status_code)
            if node.mode in ('header', '302', '307') and node.replacement in ('_', '-', 'reject'):
                raise ValueError('A redirect/header rewrite requires a replacement URL')
            modified += before != node.render()
        if matching:
            logger.info('Rewrite update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self._changed()
            return
        mode = ('302' if redirect_url is not UNSET else 'reject') if reject_type is UNSET else reject_type
        if status_code is not UNSET:
            mode = str(status_code)
        replacement = '_' if mode == 'reject' else (redirect_url if redirect_url is not UNSET else UNSET)
        if replacement is UNSET:
            raise ValueError('A redirect/header rewrite requires redirect_url for a new declaration')
        validate_new_regex(pattern)
        raw_pattern = ('"' + pattern + '"') if any(char.isspace() for char in pattern) else pattern
        node = SurgeURLRewriteNode(f'{raw_pattern} {replacement} {mode}')
        self.sections['URL Rewrite'].insert(index, node)
        self._changed()

    add_rewrite = add_url_rewrite


    def add_map_local(self, url_pattern, *, data=UNSET, data_type=UNSET, headers=UNSET,
                      status_code=UNSET, insert=None):
        single_line(url_pattern, 'url_pattern')
        if status_code is not UNSET and (type(status_code) is not int or not 200 <= status_code <= 999):
            raise ValueError('Map Local status_code must be an integer in range 200..999')
        supplied = {key: value for key, value in (
            ('data', data), ('data-type', data_type), ('header', headers),
            ('status-code', str(status_code) if status_code is not UNSET else UNSET),
        ) if value is not UNSET}
        for key, value in supplied.items():
            single_line(value, key, empty=key in ('data', 'header'))
        index = self._insert_index('Map Local', insert)
        pattern = unquote(url_pattern)
        self._require_known_identity('Map Local', pattern)
        matching = [node for node in self._section_nodes('Map Local')
                    if isinstance(node, SurgeMapLocalNode) and node.match_pattern == pattern]
        modified = 0
        for node in matching:
            fields = dict(node.fields, **supplied)
            validate_map_local(fields)
            before = node.render()
            node.fields = fields
            modified += before != node.render()
        if matching:
            logger.info('Map Local update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self._changed()
            return
        validate_map_local(supplied)
        validate_new_regex(pattern)
        tokens = ['"' + pattern + '"']
        for key, value in supplied.items():
            tokens.append(key + '=' + ('"' + value.replace('"', r'\"') + '"' if key in ('data', 'header') else value))
        node = SurgeMapLocalNode(' '.join(tokens))
        self.sections['Map Local'].insert(index, node)
        self._changed()


    def add_script(self, script, insert=None):
        index = self._insert_index('Script', insert)
        if isinstance(script, str):
            self._add_native('Script', script, insert)
            return
        if not isinstance(script, dict):
            raise ValueError('scripts entries must be dictionaries or native strings')
        unknown = set(script) - {'name'} - {key.replace('-', '_') for key in SCRIPT_FIELDS}
        if unknown:
            raise ValueError(f'Unsupported structured script fields: {sorted(unknown)}')
        fields = {}
        for key, value in script.items():
            if key == 'name':
                single_line(value, 'Script name')
                if '=' in value:
                    raise ValueError('Script name contains assignment delimiter')
                continue
            native = key.replace('_', '-')
            if native in SCRIPT_BOOLS:
                if type(value) is not bool:
                    raise ValueError(f'{key} must be a Boolean')
                value = str(value).lower()
            elif native in ('timeout', 'max-size', 'script-update-interval'):
                if type(value) not in (int, float) or (native == 'max-size' and type(value) is not int):
                    raise ValueError(f'{key} has an invalid numeric type')
                value = str(value)
            else:
                single_line(value, key, empty=native == 'argument')
            fields[native] = value.replace('_', '-') if native == 'type' else value
        stage = fields.get('type')
        if stage not in ('http-request', 'http-response', 'cron'):
            raise ValueError('Structured script type must be HTTP request/response or cron')
        condition = 'pattern' if stage.startswith('http-') else 'cronexp'
        single_line(fields.get(condition), condition)
        identity = stage, unquote(fields[condition])
        fields[condition] = identity[1]
        self._require_known_script_identity(identity)
        matching = [node for node in self._section_nodes('Script')
                    if isinstance(node, SurgeScriptNode) and node.identity == identity]
        modified = 0
        for node in matching:
            updated = dict(node.fields, **fields)
            validate_script(updated)
            before = node.render()
            node.fields = updated
            if 'name' in script:
                node.name = script['name']
            modified += before != node.render()
        if matching:
            logger.info('Script update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
            if modified:
                self._changed()
            return
        validate_script(fields)
        if stage.startswith('http-'):
            validate_new_regex(fields['pattern'])
        name = script.get('name') or Path(fields['script-path'].split('?', 1)[0]).name
        single_line(name, 'Script name')
        node = SurgeScriptNode(name + ' = ' + ','.join(key + '=' + native_value(value) for key, value in fields.items()))
        self.sections['Script'].insert(index, node)
        self._changed()


    def remove_rule(self, rule_type, value=None, *, conditions=UNSET):
        from rule_framework.native_input import guard_required_rule_semantics
        guard_required_rule_semantics(self, rule_type, value)
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
                if section == 'Rule' and isinstance(node, SurgeRuleNode):
                    if node.type.upper() in types:
                        selected = value is None or (canonical_domain(node.value) == canonical_domain(value)
                            if rule_type == 'domain' else node.value == value)
                    elif rule_type == 'domain' and node.type.upper() == 'URL-REGEX':
                        selected = self._host_match(unquote(node.value), value, section, index)
                    elif rule_type == 'domain' and node.type.upper() in {'AND', 'OR', 'NOT'}:
                        from rule_framework.logical_refs import logical_reference_matches
                        selected = logical_reference_matches(node.type, node.value, value, client=self.client,
                            location=f'{self.filepath} [{section}]:{index}')
                    elif rule_type == 'domain' and node.type.upper() not in STANDARD_TYPES | {'FINAL', 'RULE-SET', 'DOMAIN-SET'}:
                        if value is None or is_parenthesized_payload(node.value) or canonical_domain(node.value) == canonical_domain(value):
                            raise ValueError(f'Cannot recognize required domain reference in {node.type!r} at {self.filepath} [{section}]:{index}')
                    if selected and selected_conditions is not UNSET:
                        selected = node.identity[2] == selected_conditions
                elif rule_type == 'domain':
                    if isinstance(node, (SurgeURLRewriteNode, SurgeMapLocalNode)):
                        selected = self._host_match(node.match_pattern, value, section, index)
                    elif isinstance(node, SurgeScriptNode):
                        stage = node.fields.get('type', 'generic')
                        if stage in ('http-request', 'http-response'):
                            from rule_framework.native_input import guard_required_script_fields
                            guard_required_script_fields(self, node.fields)
                            selected = self._host_match(node.fields.get('pattern'), value, section, index)
                        elif stage not in ('cron', 'generic', 'event', 'dns', 'rule'):
                            raise ValueError(f'Cannot recognize script stage at {self.filepath} [{section}]:{index}')
                    elif isinstance(node, SurgeMITMNode):
                        hosts = [host for host in node.hostnames if value is not None and mitm_reference(host) != canonical_domain(value)]
                        if hosts != node.hostnames:
                            removed += len(node.hostnames) - len(hosts)
                            node.hostnames = hosts
                        selected = not hosts
                    elif isinstance(node, SurgeUnknownNode) and section in ('Rule', 'URL Rewrite', 'Map Local', 'Script', 'Header Rewrite', 'Body Rewrite'):
                        raise ValueError(f'Cannot recognize required domain reference at {self.filepath} [{section}]:{index}: {node.render()!r}')
                    elif node.render().lstrip().startswith('#!include') and section in ('Rule', 'URL Rewrite', 'Map Local', 'Script', 'MITM'):
                        raise ValueError(f'External include domain references are unknown at {self.filepath} [{section}]:{index}')
                if selected:
                    removed += 1
                else:
                    retained.append(node)
            self.sections[key] = retained
        if removed:
            self._changed()
        logger.info('Domain/rule removal matched=%s in %s', removed, self.filepath)

    def _host_match(self, pattern, value, section, index):
        try:
            references = url_host_references(pattern)
        except ReferenceRecognitionError as error:
            raise ValueError(f'Cannot recognize URL host reference at {self.filepath} [{section}]:{index}: {error}') from error
        return value is None or references.contains(value)

    def remove_mitm(self, hostnames):
        if isinstance(hostnames, str):
            hostnames = [hostnames]
        if not isinstance(hostnames, list) or not hostnames:
            raise ValueError('MITM hostnames must be a non-empty list')
        for host in hostnames:
            single_line(host, 'MITM hostname')
        selectors = {canonical_domain(host) for host in hostnames}
        removed = 0
        for key in self.section_order:
            if self._section_names[key] != 'MITM':
                continue
            retained = []
            for node in self.sections[key]:
                if isinstance(node, SurgeMITMNode):
                    hosts = [host for host in node.hostnames if canonical_domain(host) not in selectors]
                    removed += len(node.hostnames) - len(hosts)
                    node.hostnames = hosts
                    if not hosts:
                        continue
                retained.append(node)
            self.sections[key] = retained
        if removed:
            self._changed()


    def add_mitm(self, hostnames, insert=None):
        if not isinstance(hostnames, list) or not hostnames:
            raise ValueError('MITM hostnames must be a non-empty list')
        for host in hostnames:
            single_line(host, 'MITM hostname')
            if ',' in host or '%' in host:
                raise ValueError('MITM entries use one hostname each; operators belong to the declaration')
            mitm_reference(host)
        index = self._insert_index('MITM', insert)
        matching = [node for node in self.sections['MITM'] if isinstance(node, SurgeMITMNode) and node.key == 'hostname']
        if matching:
            node = matching[0]
            existing = {canonical_domain(host) for host in node.hostnames}
            added = []
            for host in hostnames:
                if canonical_domain(host) not in existing:
                    node.hostnames.append(host)
                    added.append(host)
                    existing.add(canonical_domain(host))
            if added:
                separator = ', ' if ', ' in node.raw_content else ','
                # Keep the existing token separator for appended hosts.
                node.raw_hosts.extend(separator[1:] + host for host in added)
                self._changed()
            return
        unique = list(dict.fromkeys(hostnames))
        prefix = 'hostname = %APPEND% ' if self.is_module else 'hostname = '
        node = SurgeMITMNode(prefix + ', '.join(unique))
        self.sections['MITM'].insert(index, node)
        self._changed()


    def validate(self):
        super().validate()
        from rule_framework.managed_validation import validate_passive_node
        if self.file_role not in ('module', 'full-profile', 'configuration-fragment'):
            raise ValueError('Invalid managed Surge file role')
        if self.client != 'Surge':
            raise ValueError('Invalid managed Surge client')
        if self._newline not in ('\n', '\r\n', '\r') or type(self.is_dirty) is not bool:
            raise ValueError('Invalid managed Surge newline/dirty state')
        if not isinstance(self._section_names, dict) or set(self._section_names) != set(self.sections):
            raise ValueError('Surge section identity must match the managed section map')
        for node in self.header_nodes:
            changed = not getattr(node, '_surge_loaded', False) or node.render() != getattr(node, '_surge_baseline_line', None)
            if not getattr(node, '_native_input', False):
                validate_passive_node(node, changed=changed)
        for section, nodes in self._iter_sections():
            headers = [node for node in nodes if isinstance(node, SectionNode)]
            if (len(headers) != 1 or not nodes or nodes[0] is not headers[0]
                    or headers[0].name != section
                    or not re.fullmatch(r'\s*\[' + re.escape(section) + r'\][ \t]*', getattr(headers[0], 'raw_section_line', headers[0].render()))):
                raise ValueError('Surge section header must match its managed section and appear first')
            for node in nodes:
                if not isinstance(node, ASTNode):
                    raise ValueError('Managed Surge sections require AST nodes')
                if getattr(node, 'line_ending', self._newline) not in ('', '\n', '\r\n', '\r'):
                    raise ValueError('Invalid managed Surge node newline')
                changed = not getattr(node, '_surge_loaded', False) or node.render() != getattr(node, '_surge_baseline_line', None)
                if getattr(node, '_native_input', False):
                    continue
                validate_passive_node(node, changed=changed)
                if isinstance(node, SurgeMapLocalNode):
                    if not isinstance(node.fields, dict) or any(not isinstance(value, str) for value in node.fields.values()):
                        raise ValueError('Map Local fields require string values')
                    if changed:
                        single_line(node.match_pattern, 'Map Local URL pattern')
                        validate_map_local(node.fields)
                elif isinstance(node, SurgeScriptNode) and changed:
                    if not isinstance(node.fields, dict) or any(not isinstance(value, str) for value in node.fields.values()):
                        raise ValueError('Script fields require string values')
                    single_line(node.name, 'Script name')
                    validate_script(node.fields)
                elif isinstance(node, SurgeURLRewriteNode) and changed:
                    single_line(node.match_pattern, 'URL Rewrite pattern')
                    single_line(node.replacement, 'URL Rewrite replacement')
                    if node.mode not in ('header', '302', '307', 'reject'):
                        raise ValueError('Invalid Surge URL Rewrite type')
                    if node.mode != 'reject' and node.replacement in ('_', '-', 'reject'):
                        raise ValueError('URL Rewrite redirect/header result requires a replacement URL')
                elif isinstance(node, SurgeRuleNode) and changed:
                    single_line(node.policy, 'Surge policy')
                    if any(token in node.policy for token in ',\r\n\0'):
                        raise ValueError('Invalid Surge policy field')
                    if self.is_module and node.policy not in ('DIRECT', 'REJECT', 'REJECT-TINYGIF'):
                        raise ValueError('Surge module rules require internal policies')
                    if node.type.upper() != 'FINAL':
                        validate_standard_value(node.type.upper(), unquote(node.value), client='Surge')
                        # Preserved existing options remain authoritative when a policy changes.
                        if tuple(node.options) != node._baseline[3] or not getattr(node, '_surge_loaded', False):
                            validate_options(node.options, node.type.upper(), 'Surge')
                elif isinstance(node, SurgeMITMNode) and changed:
                    if not isinstance(node.hostnames, list):
                        raise ValueError('MITM hostnames require a list')
                    for host in node.hostnames:
                        mitm_reference(host)
                elif isinstance(node, SurgeUnknownNode) and changed and not getattr(node, '_native_input', False):
                    raise ValueError(f'Changed Surge content requires recognizable syntax in [{section}]')
        encode_text('', self.text_encoding, self.text_bom)


    def remove_rewrite(self, pattern):
        single_line(pattern, 'Rewrite match pattern')
        pattern = unquote(pattern)
        removed = 0
        for key in self.section_order:
            if self._section_names[key] not in ('URL Rewrite', 'Map Local'):
                continue
            retained = []
            for node in self.sections[key]:
                if isinstance(node, (SurgeURLRewriteNode, SurgeMapLocalNode)) and node.match_pattern == pattern:
                    removed += 1
                    continue
                if isinstance(node, SurgeUnknownNode):
                    first = token_spans(split_comment(node.render())[0])
                    if first and unquote(first[0].group()) == pattern:
                        raise ValueError('Cannot recognize the required rewrite identity')
                retained.append(node)
            self.sections[key] = retained
        if removed:
            self._changed()
        logger.info('Rewrite removal matched=%s in %s', removed, self.filepath)

    def remove_script(self, name=None, pattern=None, script_path=None):
        if all(value is None for value in (name, pattern, script_path)):
            raise ValueError('Script removal requires an explicit name, pattern or script_path selector')
        for field, value in (('name', name), ('pattern', pattern), ('script_path', script_path)):
            if value is not None:
                single_line(value, field)
        removed = 0
        for key in self.section_order:
            if self._section_names[key] != 'Script':
                continue
            retained = []
            for node in self.sections[key]:
                if isinstance(node, SurgeScriptNode):
                    selected = ((name is None or node.name == name)
                                and (pattern is None or node.fields.get('pattern') == unquote(pattern))
                                and (script_path is None or node.fields.get('script-path') == script_path))
                    if selected:
                        removed += 1
                        continue
                elif isinstance(node, SurgeUnknownNode):
                    label = node.render().split('=', 1)[0].strip()
                    if name is None or label == name:
                        raise ValueError('Cannot recognize the required script selector')
                retained.append(node)
            self.sections[key] = retained
        if removed:
            self._changed()
        logger.info('Script removal matched=%s in %s', removed, self.filepath)


    def update_metadata(self, *, only_if_changed=False):
        metadata_before = self.render_bytes() if not only_if_changed else None
        from collections import Counter
        counts = Counter()
        for section, nodes in self._iter_sections():
            for node in nodes:
                if isinstance(node, SurgeRuleNode):
                    counts[node.type.lower()] += 1
                elif isinstance(node, SurgeURLRewriteNode):
                    counts['reject' if node.mode == 'reject' else 'redirect'] += 1
                elif isinstance(node, SurgeMapLocalNode):
                    counts['reject'] += 1
                elif isinstance(node, SurgeScriptNode):
                    counts[node.fields.get('type', 'generic') + '-script'] += 1
                elif isinstance(node, SurgeMITMNode) and node.key == 'hostname':
                    counts['mitm'] += len(node.hostnames)
                elif section == 'General':
                    match = re.match(r'\s*force-http-engine-hosts\s*=\s*(.*)', split_comment(node.render())[0])
                    if match:
                        value = re.sub(r'^%(APPEND|INSERT)%\s*', '', match.group(1))
                        counts['force-http-engine-hosts'] += sum(bool(host.strip()) for host in value.split(','))
        total = sum(counts.values())
        from rule_framework.metadata import restore_unchanged_ini_metadata, remember_ini_metadata
        if only_if_changed and restore_unchanged_ini_metadata(self, counts):
            return
        now = _get_now(self)
        for node in self.header_nodes:
            if not isinstance(node, CommentNode):
                continue
            line = node.render()
            assignment = re.fullmatch(r'(\s*#!([\w-]+)\s*=\s*)(.*?)([ \t]*)', line)
            legacy = re.fullmatch(r'(\s*#(?:!)?\s+([\w-]+):\s*)(.*?)([ \t]*)', line)
            match = assignment or legacy
            if match:
                key = match.group(2).lower()
                value = UNSET
                if key == 'total':
                    value = str(total)
                elif key in counts or key in {'and','or','not','domain','domain-suffix','url-regex','reject','redirect','mitm',
                                            'http-request-script','http-response-script','cron-script','force-http-engine-hosts'}:
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
        authors = [(i, author_re.fullmatch(node.render())) for i, node in enumerate(self.header_nodes)]
        own = next((i for i, match in authors if match and match.group(1) == author), None)
        additions = []
        if own is None:
            additions.append(CommentNode(f'#!author= {author}' if self.is_module else f'# AUTHOR: {author}'))
        if not any((match := repo_re.fullmatch(node.render())) and match.group(1) == repo for node in self.header_nodes):
            additions.append(CommentNode(f'#!homepage= {repo}' if self.is_module else f'# REPO: {repo}'))
        if additions:
            index = own + 1 if own is not None else next((i for i, match in authors if match), 0)
            self.header_nodes[index:index] = additions
        remember_ini_metadata(self, counts, only_if_changed, before=metadata_before)


    def _require_known_identity(self, section, pattern):
        nodes = list(self._section_nodes(section))
        for node in nodes:
            if not isinstance(node, SurgeUnknownNode):
                continue
            first = token_spans(split_comment(node.render())[0])
            if first and unquote(first[0].group()) == pattern:
                raise ValueError(f'Cannot recognize required {section} identity in {self.filepath}: {node.render()!r}')


    def _require_known_script_identity(self, identity):
        for node in self._section_nodes('Script'):
            if isinstance(node, SurgeUnknownNode) and unknown_script_requires_identity(node.render(), identity):
                raise ValueError('Cannot recognize the required Surge script identity')


    def modify(self, search, replace, is_regex=False, count=0):
        from collections import Counter
        from rule_framework.fom import _apply_text_replacement
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
                    node._surge_loaded = False
        self.validate()
        self._changed()


    def scaffold(self, base_name):
        single_line(base_name, 'Surge file name')
        now = _get_now(self)
        if self.is_module:
            self._parse_text(f'#!name={base_name}\n#!desc=最后更新时间 {now}\n#!total=0\n')
        else:
            self._parse_text(f'# NAME: {base_name}\n# UPDATED: {now}\n# TOTAL: 1\n[Rule]\nFINAL,DIRECT\n')
            self.file_role = 'full-profile'
        self._changed()


    def _add_native(self, section, content, insert=None):
        from rule_framework.native_input import validate_native_entry
        native_scope = validate_native_entry(self, content, kind='declaration', section=section)
        single_line(content, 'Native input')
        if re.match(r'\s*\[', content):
            raise ValueError('Native section content requires an explicit text/Hook operation')
        index = self._insert_index(section, insert)
        node = self._parse_line(content, section)
        if native_scope == ('known-fields', 'known-fields'):
            if isinstance(node, SurgeRuleNode):
                matching = [item for item in self._section_nodes('Rule')
                            if isinstance(item, SurgeRuleNode) and item.identity == node.identity]
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
            elif isinstance(node, SurgeURLRewriteNode):
                self._require_known_identity('URL Rewrite', node.match_pattern)
                matching = [item for item in self._section_nodes('URL Rewrite')
                            if isinstance(item, SurgeURLRewriteNode) and item.match_pattern == node.match_pattern]
                modified = 0
                for item in matching:
                    before = item.render()
                    item.replacement = node.replacement
                    item.mode = node.mode
                    modified += item.render() != before
                if matching:
                    logger.info('Rewrite update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
            elif isinstance(node, SurgeMapLocalNode):
                self._require_known_identity('Map Local', node.match_pattern)
                matching = [item for item in self._section_nodes('Map Local')
                            if isinstance(item, SurgeMapLocalNode) and item.match_pattern == node.match_pattern]
                modified = 0
                for item in matching:
                    fields = dict(item.fields, **node.fields)
                    validate_map_local(fields)
                    before = item.render()
                    item.fields = fields
                    modified += item.render() != before
                if matching:
                    logger.info('Map Local update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
            elif isinstance(node, SurgeScriptNode):
                self._require_known_script_identity(node.identity)
                matching = [item for item in self._section_nodes('Script')
                            if isinstance(item, SurgeScriptNode) and item.identity == node.identity]
                modified = 0
                for item in matching:
                    updated = dict(item.fields, **node.fields)
                    validate_script(updated)
                    before = item.render()
                    item.fields = updated
                    item.name = node.name
                    modified += item.render() != before
                if matching:
                    logger.info('Script update matched=%s modified=%s in %s', len(matching), modified, self.filepath)
                    if modified:
                        self._changed()
                    return
        if any(item.render() == content for item in self._section_nodes(section)):
            return
        node._native_input = native_scope[1] != 'known-fields'
        if native_scope[1] == 'unknown':
            node._opaque_native_line = content
        self.sections[section].insert(index, node)
        self._changed()

    def add_native_rule(self, content, insert=None):
        self._add_native('Rule', content, insert)


    def validate_complete(self):
        """Validate and finalize while the complete Task can still roll back."""
        self.validate()
        super().validate_complete()

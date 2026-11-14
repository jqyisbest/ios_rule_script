"""Evidence-bounded collections of HTTP declarations and module references."""

from dataclasses import dataclass
from copy import deepcopy
import logging
import re
from urllib.parse import urlsplit

from rule_framework.ast import BlankNode, CommentNode, SectionNode, RuleNode
from rule_framework.rule_helpers import UNSET, _BatchInsert, calculate_insert_index
from rule_framework.quantumult_lists import QuantumultRuleNode
from rule_framework.surge import SurgeFile, SurgeURLRewriteNode, SurgeScriptNode, SurgeMITMNode, SurgeMapLocalNode, validate_map_local, split_comment
from rule_framework.loon import LoonFile, LoonRewriteNode, LoonScriptNode, LoonMITMNode
from rule_framework.shadowrocket import ShadowrocketFile, ShadowrocketRewriteNode, ShadowrocketScriptNode, ShadowrocketMITMNode
from rule_framework.quantumult import QuantumultStructuredMixin, QuantumultHTTPNode, QuantumultMITMNode, QuantumultLocalScriptNode, validate_http, validate_hostnames, validate_local_script
from rule_framework.stash_formats import StashMixin, _rewrite_parts, _provider_fields, validate_script_fields, SCRIPT_FIELDS, _semantic_equal, _semantic_snapshot, _header_parts, _body_jq_parts, _mock_fields, _mitm_items

logger = logging.getLogger('RuleFramework')
FORMATS = {
    'Surge': {'module', 'configuration', 'configuration-fragment'},
    'Loon': {'plugin', 'script-declarations', 'configuration', 'configuration-fragment'},
    'Shadowrocket': {'module', 'configuration', 'configuration-fragment'},
    'Quantumult X': {'rewrite-fragment', 'configuration', 'configuration-fragment'},
    'Stash': {'override'},
}


def canonical_client(client):
    return 'Quantumult X' if client == 'QuantumultX' else client


@dataclass(frozen=True)
class ModuleDeclaration:
    kind: str
    fields: dict
    location: str = ''
    native_content: str | None = None
    section: str = ''
    comments: tuple[str, ...] = ()

    def __post_init__(self):
        _validate_declaration(self)
        object.__setattr__(self, 'fields', deepcopy(self.fields))


@dataclass(frozen=True)
class ModuleCollection:
    client: str
    file_role: str
    declarations: tuple[ModuleDeclaration, ...]

    def __post_init__(self):
        _validate_collection(self)
        object.__setattr__(self, 'client', canonical_client(self.client))


def validate_merge_declaration(definition):
    unknown = set(definition) - {'action', 'type', 'name', 'task', 'file', 'targets',
                                 'sources', 'destination', 'insert'}
    if unknown:
        raise ValueError(f'Unsupported merge_modules fields: {sorted(unknown)}')
    sources = definition.get('sources')
    if not isinstance(sources, list) or any(not isinstance(path, str) or not path.strip()
                                           or '\0' in path for path in sources):
        raise ValueError('merge_modules.sources must be an explicit list of managed file paths')
    validate_destination(definition.get('destination', UNSET))


def _client(fom):
    if isinstance(fom, SurgeFile):
        return 'Surge'
    if isinstance(fom, LoonFile):
        return 'Loon'
    if isinstance(fom, ShadowrocketFile):
        return 'Shadowrocket'
    if isinstance(fom, QuantumultStructuredMixin):
        return 'Quantumult X'
    if isinstance(fom, StashMixin):
        return 'Stash'
    raise ValueError(f'{type(fom).__name__} has no verified module collection interface')


def _rewrite_fields(pattern, target, mode):
    fields = {'url_pattern': pattern}
    if mode in ('302', '307'):
        fields.update(redirect_url=target, status_code=int(mode))
    else:
        fields['reject_type'] = mode
        if mode == 'header':
            fields['redirect_url'] = target
    return fields


def export_modules(fom):
    client = _client(fom)
    _guard_file_directives(fom)
    entries = []
    if client == 'Stash':
        entries.extend(_export_stash(fom))
    else:
        buckets = [('', fom.header_nodes)] + [(key, fom.sections[key]) for key in fom.section_order]
        pending_comments = []
        for section, nodes in buckets:
            for index, node in enumerate(nodes):
                fields = None
                provenance = re.fullmatch(r'#!(author|homepage|repo)\s*=\s*(\S.*)', node.render().strip())
                if provenance is not None:
                    entries.append(ModuleDeclaration('file-metadata', {'name': provenance[1], 'value': provenance[2]},
                        f'{fom.filepath}:header:{index + 1}', node.render()))
                    continue
                platform = re.fullmatch(r'#!system\s*=\s*(ios|mac)', node.render().strip()) if client == 'Surge' else None
                if platform is not None:
                    entries.append(ModuleDeclaration('file-directive', {'name': 'system', 'value': platform[1]},
                        f'{fom.filepath}:header:{index + 1}', node.render()))
                    continue
                if isinstance(node, (SurgeURLRewriteNode, LoonRewriteNode, ShadowrocketRewriteNode)):
                    fields = _rewrite_fields(node.match_pattern, node.replacement, node.mode)
                elif isinstance(node, SurgeMapLocalNode):
                    validate_map_local(node.fields)
                    entries.append(ModuleDeclaration('map-local', dict(node.fields, url_pattern=node.match_pattern),
                        f'{fom.filepath}:{section}:{index + 1}', node.render(), section, tuple(pending_comments)))
                    pending_comments.clear()
                    continue
                elif isinstance(node, RuleNode):
                    fields = _routing_fields(node, client)
                    entries.append(ModuleDeclaration('routing', fields, f'{fom.filepath}:{section}:{index + 1}',
                        node.render(), section, tuple(pending_comments)))
                    pending_comments.clear()
                    continue
                elif isinstance(node, (SurgeScriptNode, LoonScriptNode, ShadowrocketScriptNode)):
                    _validate_script(client, node.fields)
                    entries.append(ModuleDeclaration('script', dict(node.fields),
                        f'{fom.filepath}:{section}:{index + 1}', node.render(), section, tuple(pending_comments)))
                    pending_comments.clear()
                    continue
                elif isinstance(node, (SurgeMITMNode, LoonMITMNode, ShadowrocketMITMNode)):
                    if client == 'Loon' and node.operator:
                        raise ValueError('Unverified Loon MITM inheritance operator')
                    entries.append(ModuleDeclaration('mitm', {'hostnames': list(node.hostnames),
                        'key': node.key, 'operator': node.operator}, f'{fom.filepath}:{section}:{index + 1}', node.render(), section, tuple(pending_comments)))
                    pending_comments.clear()
                    continue
                elif isinstance(node, QuantumultHTTPNode):
                    validate_http(node)
                    entries.append(ModuleDeclaration('qx-http', dict(node.fields),
                        f'{fom.filepath}:{section}:{index + 1}', node.render(), 'rewrite_local', tuple(pending_comments)))
                    pending_comments.clear()
                    continue
                elif isinstance(node, QuantumultLocalScriptNode):
                    validate_local_script(node)
                    entries.append(ModuleDeclaration('qx-local-script', dict(node.fields),
                        f'{fom.filepath}:{section}:{index + 1}', node.render(), node.section, tuple(pending_comments)))
                    pending_comments.clear()
                    continue
                elif isinstance(node, QuantumultMITMNode):
                    validate_hostnames(node.hostnames)
                    entries.append(ModuleDeclaration('mitm', {'hostnames': list(node.hostnames), 'key': 'hostname', 'operator': ''},
                        f'{fom.filepath}:{section}:{index + 1}', node.render(), 'mitm', tuple(pending_comments)))
                    pending_comments.clear()
                    continue
                elif isinstance(node, (BlankNode, SectionNode)) or (isinstance(node, CommentNode)
                        and node.render().lstrip().startswith(('#', ';', '//'))):
                    if isinstance(node, CommentNode) and not node.render().startswith('#!'):
                        pending_comments.append(node.render())
                    continue
                else:
                    raise ValueError(f'Cannot recognize required module declaration at {fom.filepath}:{section}:{index + 1}')
                entries.append(ModuleDeclaration('rewrite', fields, f'{fom.filepath}:{section}:{index + 1}',
                    node.render(), section, tuple(pending_comments)))
                pending_comments.clear()
    return ModuleCollection(client, fom.file_role, tuple(entries))


def _literal_redirect(fields):
    # Cross-engine matching is limited to anchors and literal URL characters.
    pattern = fields.get('url_pattern')
    normalized = pattern.replace(r'\/', '/') if isinstance(pattern, str) else None
    if normalized is None or not re.fullmatch(r'\^https?://(?:[A-Za-z0-9_/:=-]|\\[.])+\$?', normalized):
        raise ValueError('Cross-client URL pattern requires the verified anchored literal HTTP(S) grammar')
    target = fields.get('redirect_url')
    parsed = urlsplit(target) if isinstance(target, str) else None
    if parsed is None or parsed.scheme not in ('http', 'https') or not parsed.hostname or re.search(r'[\s${}\\]', target):
        raise ValueError('Cross-client redirect requires a literal HTTP(S) Location without capture or gateway references')
    if fields.get('status_code') not in (302, 307) or type(fields.get('status_code')) is not int:
        raise ValueError('Cross-client response result requires verified 302/307 semantics')


def merge_modules(fom, collections, *, destination=UNSET, insert=None):
    client = _client(fom)
    destination_for(fom, destination)
    before_bytes = fom.render_bytes()
    if not isinstance(collections, (list, tuple)) or any(not isinstance(item, ModuleCollection) for item in collections):
        raise ValueError('merge_modules requires ModuleCollection values')
    for collection in collections:
        _validate_collection(collection)
    cursor = _MergeInsert(insert) if isinstance(insert, dict) else None
    if cursor is not None:
        insert = cursor
    yaml_comments = []

    def finish(item, before):
        if cursor is not None:
            cursor.advance(fom)
        if before is not None:
            _stash_new_comments(fom, item, before, yaml_comments)

    if any(item.declarations for item in collections):
        _guard_file_directives(fom)
    for collection in collections:
        cross_client = collection.client != client
        for item in collection.declarations:
            before = _stash_comment_state(fom, item, insert) if client == 'Stash' and item.comments else None
            if cursor is not None:
                cursor.select(fom, item)
            if item.kind == 'file-metadata':
                _merge_file_metadata(fom, item)
                finish(item, before)
                continue
            if item.kind == 'file-directive':
                if cross_client:
                    raise ValueError(f'{collection.client} -> {client} platform activation condition equivalence is unverified at {item.location}')
                _merge_file_directive(fom, item)
                finish(item, before)
                continue
            if item.kind in ('routing', 'map-local'):
                if cross_client:
                    raise ValueError(f'{collection.client} -> {client} {item.kind} result/conditions equivalence is unverified at {item.location}')
                section = ('filter_local' if client == 'Quantumult X' else 'Rule') if item.kind == 'routing' else 'Map Local'
                inline_comment = split_comment(item.native_content)[1] if item.native_content else ''
                if client == 'Quantumult X' and item.native_content:
                    inline_comment = QuantumultRuleNode(item.native_content).inline_comment
                previous = {id(node) for nodes in _buckets(fom, section) for node in nodes} if item.comments or inline_comment else set()
                if item.kind == 'routing':
                    fom.add_rule(item.fields['type'], item.fields['value'], policy=item.fields['policy'],
                                 conditions=_routing_conditions(item.fields, client),
                                 options=item.fields['options'], insert=insert)
                else:
                    values = { {'data-type': 'data_type', 'header': 'headers', 'status-code': 'status_code'}.get(key, key):
                        int(value) if key == 'status-code' else value for key, value in item.fields.items()}
                    fom.add_map_local(**values, insert=insert)
                if item.comments or inline_comment:
                    _comment_new_ini_node(fom, section, item.comments, previous, inline_comment)
                finish(item, before)
                continue
            if item.kind.startswith('stash-'):
                if cross_client:
                    raise ValueError(f'{collection.client} -> {client} {item.kind} phase/provider/result equivalence is unverified at {item.location}')
                _merge_stash(fom, item, insert)
                finish(item, before)
                continue
            if item.kind in ('qx-http', 'qx-local-script'):
                if not cross_client:
                    _merge_qx(fom, item, insert)
                    finish(item, before)
                    continue
                if item.kind != 'qx-http' or item.fields.get('method') != 'url' or item.fields.get('mode') not in ('302', '307'):
                    raise ValueError(f'{collection.client} -> {client} processing phase/conditions equivalence is unverified at {item.location}')
                comments = item.comments
                if item.native_content is not None:
                    inline = QuantumultHTTPNode(item.native_content).inline_comment.strip()
                    if inline:
                        comments += (inline,)
                item = ModuleDeclaration('rewrite', _rewrite_fields(item.fields['match_pattern'],
                    item.fields['result'], item.fields['mode']), item.location, comments=comments)
                if client == 'Stash' and item.comments:
                    before = _stash_comment_state(fom, item, insert)
            if item.kind in ('script', 'mitm'):
                if item.kind == 'mitm' and item.fields.get('operator') and collection.file_role != fom.file_role:
                    raise ValueError('MITM inheritance operator requires matching module file purpose')
                if cross_client:
                    raise ValueError(f'{collection.client} -> {client} {item.kind} execution/reference equivalence is unverified at {item.location}')
                if item.kind == 'script':
                    _merge_script(fom, item, insert)
                else:
                    _merge_mitm(fom, item, insert)
                finish(item, before)
                continue
            if item.kind != 'rewrite':
                raise ValueError(f'Unsupported module declaration kind: {item.kind}')
            fields = dict(item.fields)
            if cross_client:
                if {client, collection.client} != {'Stash', 'Quantumult X'}:
                    raise ValueError(f'{collection.client} -> {client} module matching/processing equivalence is unverified at {item.location}')
                _literal_redirect(fields)
                fields.pop('family', None)
            if not cross_client and item.native_content is not None and client != 'Stash':
                _merge_ini_rewrite(fom, item, insert)
            else:
                add = getattr(fom, 'add_url_rewrite', fom.add_rewrite)
                previous = ({id(node) for nodes in _buckets(fom, 'rewrite_local') for node in nodes}
                            if client == 'Quantumult X' and item.comments else None)
                add(**fields, insert=insert)
                if previous is not None:
                    _comment_new_ini_node(fom, 'rewrite_local', item.comments, previous, '')
            finish(item, before)
    if yaml_comments:
        _apply_stash_comments(fom, yaml_comments)
    if fom.render_bytes() != before_bytes:
        changed = getattr(fom, '_changed', None)
        if callable(changed):
            changed()
    logger.info('Module merge client=%s declarations=%s runtime-validation=not-run', client,
                sum(len(item.declarations) for item in collections))


def execute_merge(ctx, definition):
    from rule_framework.workspace import MissingSourceInputError
    validate_merge_declaration(definition)
    if ctx.workspace is None:
        raise ValueError('merge_modules requires a managed workspace')
    collections = []
    for path in definition['sources']:
        if ctx.workspace.is_missing_source_input(path):
            raise MissingSourceInputError(ctx.workspace.resolve_path(path))
        if not ctx.workspace.exists(path):
            raise ValueError(f'Module source does not exist: {path}')
        collections.append(ctx.workspace.get_fom(path).export_modules())
    ctx.fom.merge_modules(collections, destination=definition.get('destination', UNSET),
                          insert=definition.get('insert'))


def _validate_script(client, fields):
    if client == 'Surge':
        from rule_framework.surge import validate_script
    elif client == 'Loon':
        from rule_framework.loon import validate_script
    elif client == 'Shadowrocket':
        from rule_framework.shadowrocket import validate_script
    else:
        raise ValueError(f'Unverified script representation for {client}')
    validate_script(fields)


def _buckets(fom, section):
    if isinstance(fom, LoonFile) and fom.file_role == 'script-declarations':
        return [fom.header_nodes]
    if isinstance(fom, QuantumultStructuredMixin) and fom.is_snippet:
        return [fom.header_nodes]
    names = {'rewrite', 'url rewrite'} if section.lower() == 'rewrite' else {section.lower()}
    return [fom.sections[key] for key in fom.section_order
            if fom._section_names[key].lower() in names]


def _insert_node(fom, section, node, insert, comments=()):
    positioned = fom._insert_index(section, insert)
    if isinstance(positioned, tuple):
        nodes, index = positioned
    else:
        nodes, index = fom.sections[section], positioned
    nodes[index:index] = [*(CommentNode(text) for text in comments), node]
    fom.is_dirty = True


def _comment_new_ini_node(fom, section, comments, previous, inline_comment):
    for nodes in _buckets(fom, section):
        for index, node in enumerate(nodes):
            if id(node) not in previous and not isinstance(node, SectionNode):
                if inline_comment:
                    replacement = fom._parse_line(node.render() + inline_comment, section)
                    if type(replacement) is not type(node):
                        raise ValueError('Imported inline annotation changed the declaration type')
                    replacement.line_ending = getattr(node, 'line_ending', fom._newline)
                    nodes[index] = replacement
                nodes[index:index] = [CommentNode(text) for text in comments]
                return


def _script_condition_matches(existing, supplied):
    stage = supplied.get('type')
    condition = 'cronexp' if stage == 'cron' else 'pattern'
    if existing.get('type') != stage or existing.get(condition) != supplied.get(condition):
        return False
    for key in ('requires-body', 'binary-body-mode', 'full-header-mode', 'enable'):
        if key in supplied:
            default = 'true' if key == 'enable' else 'false'
            if (existing.get(key, default) in ('true', '1')) != (supplied[key] in ('true', '1')):
                return False
    for key in ('max-size', 'engine'):
        if key in supplied and supplied[key] != existing.get(key, UNSET):
            return False
    return True


def _merge_script(fom, item, insert):
    client = _client(fom)
    _validate_script(client, item.fields)
    cls = {'Surge': SurgeScriptNode, 'Loon': LoonScriptNode,
           'Shadowrocket': ShadowrocketScriptNode}[client]
    matches = []
    for nodes in _buckets(fom, 'Script'):
        for node in nodes:
            if isinstance(node, cls):
                if _script_condition_matches(node.fields, item.fields):
                    _validate_script(client, node.fields)
                    matches.append(node)
            elif not isinstance(node, (BlankNode, SectionNode, LoonMITMNode)) and not node.render().lstrip().startswith(('#', ';', '//')):
                raise ValueError(f'Cannot recognize required {client} Script declaration identity')
    if matches:
        fom._insert_index('Script', insert)
    modified = 0
    for node in matches:
        before = node.render()
        node.fields.update(deepcopy(item.fields))
        _validate_script(client, node.fields)
        modified += before != node.render()
    if matches:
        fom.is_dirty |= bool(modified)
    else:
        if not isinstance(item.native_content, str):
            raise ValueError('A new script collection declaration requires its verified native declaration')
        node = cls(item.native_content)
        _validate_script(client, node.fields)
        _insert_node(fom, 'Script', node, insert, item.comments)
    logger.info('Module script update client=%s matched=%s modified=%s', client, len(matches), modified)


def _merge_mitm(fom, item, insert):
    client = _client(fom)
    if client == 'Quantumult X':
        candidate = QuantumultMITMNode(item.native_content)
        validate_hostnames(candidate.hostnames)
        matching = [node for nodes in _buckets(fom, 'mitm') for node in nodes if isinstance(node, QuantumultMITMNode)]
        if matching:
            fom.add_mitm(candidate.hostnames, insert=insert)
        else:
            _insert_node(fom, 'mitm', candidate, insert, item.comments)
        return
    cls = {'Surge': SurgeMITMNode, 'Loon': LoonMITMNode,
           'Shadowrocket': ShadowrocketMITMNode}[client]
    candidate = cls(item.native_content)
    if client == 'Loon' and candidate.operator:
        raise ValueError('Unverified Loon MITM inheritance operator')
    matches = [node for nodes in _buckets(fom, 'MITM') for node in nodes
               if isinstance(node, cls) and node.key == candidate.key]
    if any(node.operator != candidate.operator for node in matches):
        raise ValueError(f'{client} MITM inheritance operator conflicts with existing target: {candidate.operator!r}')
    if matches:
        # The verified client operation preserves existing layout and all omitted fields.
        if candidate.key != 'hostname':
            raise ValueError('MITM disabled-host assignment union requires an explicit operation')
        fom.add_mitm(candidate.hostnames, insert=insert)
    else:
        _insert_node(fom, 'MITM', candidate, insert, item.comments)


def _merge_qx(fom, item, insert):
    cls = QuantumultHTTPNode if item.kind == 'qx-http' else QuantumultLocalScriptNode
    candidate = cls(item.native_content) if item.kind == 'qx-http' else cls(item.native_content, item.section)
    validate = validate_http if item.kind == 'qx-http' else validate_local_script
    validate(candidate)
    matches = []
    for nodes in _buckets(fom, item.section):
        for node in nodes:
            if isinstance(node, cls):
                identity = node.identity
                if isinstance(node, QuantumultLocalScriptNode):
                    identity += (node.fields.get('enabled', 'true'),)
                wanted = candidate.identity
                if isinstance(candidate, QuantumultLocalScriptNode):
                    wanted += (candidate.fields.get('enabled', 'true'),)
                if identity == wanted:
                    validate(node)
                    matches.append(node)
            elif not isinstance(node, (QuantumultHTTPNode, QuantumultLocalScriptNode, QuantumultMITMNode, BlankNode, SectionNode)) and not node.render().lstrip().startswith(('#', ';', '//')):
                raise ValueError('Cannot recognize required Quantumult X declaration identity')
    if matches:
        fom._insert_index(item.section, insert)
    modified = 0
    for node in matches:
        before = node.render()
        if item.kind == 'qx-http':
            for key, value in candidate.fields.items():
                setattr(node, key, value)
        else:
            node.fields.update(deepcopy(candidate.fields))
        validate(node)
        modified += before != node.render()
    if matches:
        fom.is_dirty |= bool(modified)
    else:
        _insert_node(fom, item.section, candidate, insert, item.comments)
    logger.info('Module QX update kind=%s matched=%s modified=%s', item.kind, len(matches), modified)


def _export_stash(fom):
    source_comments = _stash_source_comments(fom)
    for key in fom.data:
        if key not in {'name', 'desc', 'author', 'homepage', 'openUrl', 'icon', 'category', 'date', 'version', 'http', 'script-providers'}:
            raise ValueError(f'Unverified required Stash file-level field: {key}')
    if any('#!' in str(annotation) for annotation in fom._source_annotations):
        raise ValueError('Stash YAML inheritance/parameter directives require an explicit equivalence mapping')
    providers = fom.data.get('script-providers', {})
    if not isinstance(providers, dict):
        raise ValueError('Stash source script-providers requires a mapping')
    entries = []
    for name, fields in providers.items():
        _provider_fields(fields, complete=True)
        entries.append(ModuleDeclaration('stash-provider', {'name': name, 'fields': _semantic_snapshot(fields)},
                                        f'{fom.filepath}:script-providers.{name}', comments=source_comments.get(('script-providers', name), ())))
    http = fom.data.get('http', {})
    if not isinstance(http, dict):
        raise ValueError('Cannot recognize required Stash HTTP mapping')
    for family, rows in http.items():
        if family not in ('rewrite', 'url-rewrite', 'script', 'mitm', 'header-rewrite', 'body-rewrite', 'mock') or not isinstance(rows, list):
            raise ValueError(f'Unverified required Stash module field: http.{family}')
        if family == 'mitm':
            _mitm_items(rows)
            for index, row in enumerate(rows):
                entries.append(ModuleDeclaration('stash-mitm', {'hostnames': [row]},
                    f'{fom.filepath}:http.mitm:{index + 1}',
                    comments=source_comments.get((family, index), ())))
            continue
        for index, row in enumerate(rows):
            location = f'{fom.filepath}:http.{family}:{index + 1}'
            comments = source_comments.get((family, index), ())
            if family in ('rewrite', 'url-rewrite'):
                pattern, target, mode = _rewrite_parts(row)
                fields = _rewrite_fields(pattern, target, mode)
                fields['family'] = family
                entries.append(ModuleDeclaration('rewrite', fields, location, comments=comments))
            elif family == 'script':
                if not isinstance(row, dict) or set(row) - SCRIPT_FIELDS:
                    raise ValueError(f'Unverified required Stash script fields at {location}')
                validate_script_fields(row)
                fom._require_script_provider(row)
                entries.append(ModuleDeclaration('stash-script', _semantic_snapshot(row), location, comments=comments))
            elif family == 'header-rewrite':
                entries.append(ModuleDeclaration('stash-header', _header_parts(row), location, comments=comments))
            elif family == 'body-rewrite':
                entries.append(ModuleDeclaration('stash-body', _body_jq_parts(row), location, comments=comments))
            elif family == 'mock':
                _mock_fields(row)
                entries.append(ModuleDeclaration('stash-mock', _semantic_snapshot(row), location, comments=comments))
    return entries


def _merge_stash(fom, item, insert):
    if item.kind == 'stash-provider':
        fom.add_script_provider(item.fields['name'], item.fields['fields'])
    elif item.kind == 'stash-mitm':
        if item.fields['hostnames']:
            fom.add_mitm(item.fields['hostnames'], insert=insert)
    elif item.kind == 'stash-header':
        fom.add_header_rewrite(item.fields, insert=insert)
    elif item.kind == 'stash-body':
        fom.add_body_rewrite(item.fields, insert=insert)
    elif item.kind == 'stash-mock':
        fom.add_mock(item.fields, insert=insert)
    elif item.kind == 'stash-script':
        from rule_framework.rule_helpers import calculate_insert_index
        validate_script_fields(item.fields)
        fom._require_script_provider(item.fields)
        entries = fom._sequence(fom._http(create=True), 'script', create=True)
        index = calculate_insert_index(entries, insert, is_section=True, section_name='http.script')
        matches = []
        for row in entries:
            if not isinstance(row, dict):
                raise ValueError('Cannot recognize required Stash script declaration')
            if any(row.get(key) != item.fields.get(key) for key in ('name', 'match', 'type')):
                continue
            if any(key in item.fields and not _semantic_equal(row.get(key, False if key in ('require-body', 'binary-mode') else UNSET), item.fields[key])
                   for key in ('require-body', 'binary-mode', 'max-size', 'engine')):
                continue
            if set(row) - SCRIPT_FIELDS:
                raise ValueError('Cannot recognize required existing Stash script options')
            validate_script_fields(row)
            matches.append(row)
        if matches:
            for row in matches:
                if any(key not in row or not _semantic_equal(row[key], value) for key, value in item.fields.items()):
                    row.update(deepcopy(item.fields))
                    fom.is_dirty = True
        else:
            entries.insert(index, deepcopy(item.fields))
            fom.is_dirty = True
        logger.info('Module Stash script update matched=%s', len(matches))
    else:
        raise ValueError(f'Unsupported Stash module declaration kind: {item.kind}')


def validate_destination(destination):
    if destination is UNSET:
        return
    if not isinstance(destination, dict) or set(destination) - {'client', 'format'}:
        raise ValueError('merge_modules.destination requires supported client/format fields')
    client = canonical_client(destination.get('client'))
    if 'client' in destination and (not isinstance(client, str) or client not in FORMATS):
        raise ValueError(f'Unverified HTTP/module destination client: {destination.get("client")!r}')
    if 'format' in destination:
        format_name = destination['format']
        if not isinstance(format_name, str) or format_name not in set.union(*FORMATS.values()):
            raise ValueError(f'Unverified HTTP/module destination format: {format_name!r}')
        if client is not None and format_name not in FORMATS[client]:
            raise ValueError('Module destination client and file purpose conflict')


def destination_for(fom, destination=UNSET):
    validate_destination(destination)
    actual = {'client': _client(fom), 'format': 'configuration' if fom.file_role == 'full-profile' else fom.file_role}
    if actual['format'] not in FORMATS[actual['client']]:
        raise ValueError(f'Unverified module file purpose: {actual}')
    if destination is not UNSET:
        for key, value in destination.items():
            value = canonical_client(value) if key == 'client' else value
            if actual[key] != value:
                raise ValueError(f'Module destination {key} conflicts with existing client/file purpose: {value!r} versus {actual[key]!r}')
    return actual


def prepare_declared_target(fom, actions):
    for action in actions:
        if action.type == 'merge_modules':
            destination_for(fom, action.definition.get('destination', UNSET))


def task_target_factory(actions, workspace):
    declared = [action.definition.get('destination', UNSET) for action in actions if action.type == 'merge_modules']
    explicit = [item for item in declared if item is not UNSET and 'client' in item and 'format' in item]
    purposes = {(canonical_client(item['client']), item['format']) for item in explicit}
    if len(purposes) > 1:
        raise ValueError('Task module destinations declare conflicting client/file purposes')
    return target_factory(explicit[0], workspace) if explicit else None


def target_factory(destination, workspace):
    validate_destination(destination)
    client, format_name = canonical_client(destination['client']), destination['format']
    from rule_framework.fom import QuanXConfFile, StashOverrideFile
    base = {'Surge': SurgeFile, 'Loon': LoonFile, 'Shadowrocket': ShadowrocketFile,
            'Quantumult X': QuanXConfFile, 'Stash': StashOverrideFile}[client]

    class ModuleTarget(base):
        def scaffold(self, base_name):
            if client == 'Stash':
                return super().scaffold(base_name)
            from rule_framework.surge import single_line
            single_line(base_name, 'generated file name')
            if format_name in {'module', 'plugin'}:
                self.file_role = format_name
                self._parse_text(f'#!name={base_name}\n#!total=0\n')
            else:
                text = f'# NAME: {base_name}\n# TOTAL: 0\n'
                if format_name == 'configuration':
                    text += '[general]\n[filter_local]\nfinal,direct\n' if client == 'Quantumult X' else '[Rule]\nFINAL,DIRECT\n'
                elif format_name == 'configuration-fragment':
                    text += '[rewrite_local]\n' if client == 'Quantumult X' else '[Script]\n'
                if client == 'Loon' and format_name == 'script-declarations':
                    self.file_role = format_name
                self._parse_text(text)
            self.is_dirty = True
            destination_for(self, destination)

    def create(path):
        from pathlib import Path
        suffixes = {
            'Surge': {'module': {'.sgmodule'}, 'configuration': {'.conf'}, 'configuration-fragment': {'.conf'}},
            'Loon': {'plugin': {'.plugin', '.lnplugin'}, 'script-declarations': {'.lnscript'}, 'configuration': {'.conf'}, 'configuration-fragment': {'.conf'}},
            'Shadowrocket': {'module': {'.sgmodule'}, 'configuration': {'.conf'}, 'configuration-fragment': {'.conf', '.snippet'}},
            'Quantumult X': {'rewrite-fragment': {'.conf', '.qxrewrite', '.snippet'}, 'configuration': {'.conf'}, 'configuration-fragment': {'.conf'}},
            'Stash': {'override': {'.stoverride'}},
        }
        if Path(path).suffix.lower() not in suffixes[client][format_name]:
            raise ValueError(f'Module target extension conflicts with verified file purpose {client}/{format_name}: {path}')
        from rule_framework.client_paths import client_for_path
        namespace = client_for_path(path, base_dir=workspace.base_dir)
        if namespace not in ('unknown', client):
            raise ValueError(f'Module destination client conflicts with managed namespace {namespace}: {path}')
        return ModuleTarget(path)
    return create


def _routing_conditions(fields, client):
    if client == 'Quantumult X':
        return {}
    from rule_framework.rule_helpers import OPTION_CONDITIONS
    if client == 'Shadowrocket':
        from rule_framework.shadowrocket import OPTION_CONDITIONS
    return {name: True for name, option in OPTION_CONDITIONS.items() if option in fields['options']}


def _routing_fields(node, client):
    from rule_framework.rule_helpers import validate_standard_value, validate_options
    from rule_framework.quantumult_lists import validate_quantumult_value, validate_quantumult_policy, validate_quantumult_options
    kind = node.type.upper()
    if client == 'Quantumult X':
        if kind != 'FINAL':
            validate_quantumult_value(kind, node.value)
        validate_quantumult_policy(node.policy)
        validate_quantumult_options(node.options)
    elif client == 'Shadowrocket':
        from rule_framework.shadowrocket import validate_options as native_options
        if kind != 'FINAL':
            validate_standard_value(kind, node.value, client=client)
        native_options(node.options, kind)
    else:
        if kind != 'FINAL':
            validate_standard_value(kind, node.value, client=client)
        validate_options(node.options, kind, client)
    return {'type': kind, 'value': node.value, 'policy': node.policy, 'options': list(node.options)}


def _guard_file_directives(fom):
    if isinstance(fom, StashMixin):
        if any('#!' in str(annotation) for annotation in fom._source_annotations):
            raise ValueError('Stash YAML inheritance/parameter directive has unrepresented execution context')
        return
    descriptive = ('#!name=', '#!desc=', '#!author=', '#!homepage=', '#!repo=', '#!total=')
    for nodes in [fom.header_nodes, *fom.sections.values()]:
        for node in nodes:
            rendered = node.render().lstrip()
            count = re.fullmatch(r'#!(?:mitm|script|http-request-script|http-response-script|cron|reject|redirect|rewrite|rule)\s*=\s*[0-9]+', rendered, re.IGNORECASE)
            platform = re.fullmatch(r'#!system\s*=\s*(ios|mac)', rendered) if isinstance(fom, SurgeFile) and fom.is_module else None
            if rendered.startswith('#!') and not rendered.lower().startswith(descriptive) and count is None and platform is None:
                raise ValueError(f'{_client(fom)} file directive has unrepresented execution context: {rendered!r}')


class _MergeInsert(_BatchInsert):
    """Keep source order at actual insertion boundaries, shared by snippet items."""

    def __init__(self, insert):
        super().__init__(insert)
        self.positions = {}

    def select(self, fom, item):
        self.begin_item()
        self.shared_bucket = (bool(getattr(fom, 'is_snippet', False))
                              or getattr(fom, 'file_role', None) == 'script-declarations')

    def locate(self, nodes, is_section, section_name):
        key = None if self.shared_bucket else section_name
        anchor = self.anchors.get(key)
        position = next((i for i, node in enumerate(nodes) if node is anchor), None)
        if position is None:
            # File metadata may reparse YAML while retaining sequence order.
            # Keep the accepted boundary across that identity-only rebuild.
            position = self.positions.get(key)
        if position is None:
            return super().locate(nodes, is_section, key)
        # Resolve the original marker once. New items may match that marker too.
        index = calculate_insert_index(nodes, {'at_line': position + 1}, is_section, section_name)
        self.observations.setdefault((key, id(nodes)),
                                     (nodes, {id(node) for node in nodes}, len(nodes), position))
        return index

    def advance(self, fom):
        super().advance()
        for (key, _), (nodes, *_rest) in self.observations.items():
            anchor = self.anchors.get(key)
            position = next((i for i, node in enumerate(nodes) if node is anchor), None)
            if position is not None:
                self.positions[key] = position


def _merge_ini_rewrite(fom, item, insert):
    client = _client(fom)
    cls = {'Surge': SurgeURLRewriteNode, 'Loon': LoonRewriteNode,
           'Shadowrocket': ShadowrocketRewriteNode}[client]
    section = 'Rewrite' if client == 'Loon' else 'URL Rewrite'
    candidate = cls(item.native_content)
    matching = [node for nodes in _buckets(fom, section) for node in nodes
                if isinstance(node, cls) and node.match_pattern == candidate.match_pattern]
    for nodes in _buckets(fom, section):
        for node in nodes:
            if not isinstance(node, (cls, BlankNode, SectionNode)) and not node.render().lstrip().startswith(('#', ';', '//')):
                raise ValueError(f'Cannot recognize required {client} URL rewrite identity')
    if matching:
        # Validate the explicit locator even when every result is already equal.
        fom._insert_index(section, insert)
        modified = 0
        for node in matching:
            before = node.render()
            if not (node.mode.lower().startswith('reject') and candidate.mode.lower().startswith('reject')):
                node.replacement = candidate.replacement
            node.mode = candidate.mode
            modified += before != node.render()
        fom.is_dirty |= bool(modified)
        logger.info('Module URL rewrite update client=%s matched=%s modified=%s', client, len(matching), modified)
    else:
        from rule_framework.surge import validate_new_regex
        validate_new_regex(candidate.match_pattern)
        _insert_node(fom, section, candidate, insert, item.comments)


DECLARATION_FIELDS = {
    'file-directive': {'name', 'value'},
    'file-metadata': {'name', 'value'},
    'rewrite': {'url_pattern', 'reject_type', 'redirect_url', 'status_code', 'family'},
    'script': {'type', 'pattern', 'cronexp', 'script-path', 'requires-body', 'max-size',
               'binary-body-mode', 'full-header-mode', 'script-update-interval', 'timeout', 'argument',
               'engine', 'debug', 'wake-system', 'tag', 'enable', 'img-url'},
    'mitm': {'hostnames', 'key', 'operator'},
    'routing': {'type', 'value', 'policy', 'options'},
    'map-local': {'url_pattern', 'data', 'data-type', 'status-code', 'header'},
    'qx-http': {'match_pattern', 'method', 'mode', 'header_pattern', 'processor_match', 'content_type', 'result'},
    'qx-local-script': {'script-path', 'tag', 'enabled', 'img-url', 'require-devices', 'path'},
    'stash-provider': {'name', 'fields'},
    'stash-script': SCRIPT_FIELDS,
    'stash-mitm': {'hostnames'},
    'stash-header': {'match', 'action', 'header', 'regex', 'replacement', 'value'},
    'stash-body': {'match', 'action', 'expression'},
    'stash-mock': {'match', 'text', 'base64', 'status-code', 'headers'},
}


def _validate_declaration(item):
    if not isinstance(item.kind, str) or item.kind not in DECLARATION_FIELDS:
        raise ValueError(f'Unverified module declaration kind: {item.kind!r}')
    if not isinstance(item.fields, dict) or set(item.fields) - DECLARATION_FIELDS[item.kind]:
        raise ValueError(f'Unverified module declaration fields for {item.kind}')
    if not isinstance(item.location, str) or not isinstance(item.section, str):
        raise ValueError('Module declaration location/section must be strings')
    if item.native_content is not None and (not isinstance(item.native_content, str)
            or not item.native_content.strip() or any(c in item.native_content for c in '\r\n\0')):
        raise ValueError('Module declaration native presentation must be one non-empty line')
    if item.kind in ('script', 'mitm', 'qx-http', 'qx-local-script') and item.native_content is None:
        raise ValueError(f'{item.kind} declaration requires a verified native presentation')
    if not isinstance(item.comments, tuple) or any(not isinstance(text, str) or any(c in text for c in '\r\n\0')
            or not text.lstrip().startswith(('#', ';', '//')) or text.lstrip().startswith('#!') for text in item.comments):
        raise ValueError('Module leading comments require ordinary comment lines without executable directives')


def _validate_collection(collection):
    client = canonical_client(collection.client)
    if not isinstance(client, str) or client not in FORMATS:
        raise ValueError(f'Unverified module source client: {collection.client!r}')
    role = 'configuration' if collection.file_role == 'full-profile' else collection.file_role
    if not isinstance(role, str) or role not in FORMATS[client]:
        raise ValueError(f'Unverified module source purpose for {client}: {collection.file_role!r}')
    if not isinstance(collection.declarations, tuple) or any(not isinstance(item, ModuleDeclaration) for item in collection.declarations):
        raise ValueError('ModuleCollection.declarations requires a tuple of ModuleDeclaration values')
    for item in collection.declarations:
        _validate_declaration(item)
        _validate_presentation(client, item)
        if item.kind == 'file-directive' and role != 'module':
            raise ValueError('Module platform activation directive requires module source purpose')


def _validate_presentation(client, item):
    allowed = {
        'Surge': {'rewrite', 'script', 'mitm', 'routing', 'map-local', 'file-directive', 'file-metadata'},
        'Loon': {'rewrite', 'script', 'mitm', 'routing', 'file-metadata'},
        'Shadowrocket': {'rewrite', 'script', 'mitm', 'routing', 'file-metadata'},
        'Quantumult X': {'rewrite', 'qx-http', 'qx-local-script', 'mitm', 'routing', 'file-metadata'},
        'Stash': {'rewrite', 'stash-provider', 'stash-script', 'stash-mitm', 'stash-header', 'stash-body', 'stash-mock', 'file-metadata'},
    }
    if item.kind not in allowed[client]:
        raise ValueError(f'{client} has no verified {item.kind} source declaration')
    if item.native_content is None:
        return
    fields = None
    if item.kind == 'qx-http':
        candidate = QuantumultHTTPNode(item.native_content)
        validate_http(candidate)
        fields = candidate.fields
    elif item.kind == 'qx-local-script':
        candidate = QuantumultLocalScriptNode(item.native_content, item.section)
        validate_local_script(candidate)
        fields = candidate.fields
    elif item.kind == 'file-metadata':
        match = re.fullmatch(r'#!(author|homepage|repo)\s*=\s*(\S.*)', item.native_content.strip())
        if match is None:
            raise ValueError('Unverified source provenance metadata')
        fields = {'name': match[1], 'value': match[2]}
    elif item.kind == 'file-directive':
        match = re.fullmatch(r'#!system\s*=\s*(ios|mac)', item.native_content.strip())
        if match is None:
            raise ValueError('Unverified module activation platform directive')
        fields = {'name': 'system', 'value': match[1]}
    elif item.kind == 'script':
        candidate = {'Surge': SurgeScriptNode, 'Loon': LoonScriptNode, 'Shadowrocket': ShadowrocketScriptNode}[client](item.native_content)
        _validate_script(client, candidate.fields)
        fields = candidate.fields
    elif item.kind == 'mitm':
        candidate = {'Surge': SurgeMITMNode, 'Loon': LoonMITMNode, 'Shadowrocket': ShadowrocketMITMNode,
                     'Quantumult X': QuantumultMITMNode}[client](item.native_content)
        fields = {'hostnames': list(candidate.hostnames), 'key': getattr(candidate, 'key', 'hostname'),
                  'operator': getattr(candidate, 'operator', '')}
    elif item.kind == 'map-local':
        candidate = SurgeMapLocalNode(item.native_content)
        validate_map_local(candidate.fields)
        fields = dict(candidate.fields, url_pattern=candidate.match_pattern)
    elif item.kind == 'rewrite' and client in {'Surge', 'Loon', 'Shadowrocket'}:
        candidate = {'Surge': SurgeURLRewriteNode, 'Loon': LoonRewriteNode, 'Shadowrocket': ShadowrocketRewriteNode}[client](item.native_content)
        fields = _rewrite_fields(candidate.match_pattern, candidate.replacement, candidate.mode)
    if fields is not None and not _semantic_equal(fields, item.fields):
        raise ValueError('Module declaration fields disagree with their verified native presentation')


def _merge_file_directive(fom, item):
    if not isinstance(fom, SurgeFile) or not fom.is_module or item.fields.get('name') != 'system' or item.fields.get('value') not in {'ios', 'mac'}:
        raise ValueError('Verified platform activation directive requires a Surge module target')
    directives = [node for node in fom.header_nodes if re.match(r'#!system\s*=', node.render().strip())]
    if directives:
        if any(re.fullmatch(r'#!system\s*=\s*' + item.fields['value'], node.render().strip()) is None for node in directives):
            raise ValueError('Source and target platform activation conditions conflict')
        return
    if any(not isinstance(node, (BlankNode, SectionNode)) and not node.render().lstrip().startswith(('#', ';', '//'))
           for nodes in fom.sections.values() for node in nodes):
        raise ValueError('Adding a platform activation condition would alter existing target module behavior')
    fom.header_nodes.append(CommentNode(item.native_content))
    fom.is_dirty = True


def _yaml_mapping_node(node, key):
    from ruamel.yaml.nodes import MappingNode
    if isinstance(node, MappingNode):
        return next(((left, right) for left, right in node.value if left.value == key), (None, None))
    return None, None


def _yaml_leaves(node):
    from ruamel.yaml.nodes import MappingNode, SequenceNode
    if isinstance(node, MappingNode):
        for key, value in node.value:
            yield from _yaml_leaves(key)
            yield from _yaml_leaves(value)
    elif isinstance(node, SequenceNode):
        for value in node.value:
            yield from _yaml_leaves(value)
    else:
        yield node


def _stash_source_comments(fom):
    from ruamel.yaml.nodes import MappingNode, SequenceNode
    raw = fom.render_bytes().decode(fom._encoding)
    lines = raw.splitlines()
    root = fom.yaml.compose(raw)
    result = {}
    _, http = _yaml_mapping_node(root, 'http')
    _, providers = _yaml_mapping_node(root, 'script-providers')
    families = list(http.value) if isinstance(http, MappingNode) else []
    if isinstance(providers, MappingNode):
        families.append((None, providers))
    for family_key, entries in families:
        if family_key is None:
            rows = [(key.value, value, key.end_mark.line + 1) for key, value in entries.value]
            family = 'script-providers'
        elif isinstance(entries, SequenceNode):
            family = family_key.value
            rows, start = [], family_key.end_mark.line + 1
            for index, row in enumerate(entries.value):
                rows.append((index, row, start))
                start = max((leaf.end_mark.line for leaf in _yaml_leaves(row)), default=row.end_mark.line) + 1
        else:
            continue
        for index, row, start in rows:
            comments = [line.strip() for line in lines[start:row.start_mark.line]
                        if line.lstrip().startswith('#') and not line.lstrip().startswith('#!')]
            for leaf in _yaml_leaves(row):
                if leaf.style in ('|', '>'):
                    continue
                tail = raw[leaf.end_mark.index:].splitlines()[0] if leaf.end_mark.index < len(raw) else ''
                if tail.strip().startswith('#') and not tail.strip().startswith('#!'):
                    comments.append(tail.strip())
            result[(family, index)] = tuple(dict.fromkeys(comments))
    return result


def _stash_comment_state(fom, item, insert=None):
    family = {'stash-script': 'script', 'stash-mitm': 'mitm', 'stash-header': 'header-rewrite',
              'stash-body': 'body-rewrite', 'stash-mock': 'mock', 'stash-provider': 'script-providers'}.get(item.kind, item.fields.get('family', 'url-rewrite'))
    if item.kind in ('rewrite', 'qx-http'):
        family = fom._rewrite_family(fom.data.get('http', {}), insert, item.fields.get('family', UNSET))
    entries = fom.data.get('script-providers', {}) if family == 'script-providers' else fom.data.get('http', {}).get(family, [])
    return family, len(entries), set(entries) if family == 'script-providers' else {id(value) for value in entries}


def _stash_new_comments(fom, item, before, pending):
    family, count, identities = before
    entries = fom.data.get('script-providers', {}) if family == 'script-providers' else fom.data.get('http', {}).get(family, [])
    if len(entries) <= count:
        return
    if family == 'script-providers':
        for name in entries:
            if name not in identities:
                pending.append((family, name, item.comments))
    else:
        for index, value in enumerate(entries):
            if id(value) not in identities:
                pending.append((family, index, item.comments))


def _apply_stash_comments(fom, pending):
    from ruamel.yaml.nodes import MappingNode, SequenceNode
    raw = fom.render_bytes().decode(fom._encoding)
    root = fom.yaml.compose(raw)
    _, http = _yaml_mapping_node(root, 'http')
    _, providers = _yaml_mapping_node(root, 'script-providers')
    insertions = {}
    for family, index, comments in pending:
        if family == 'script-providers':
            key, value = _yaml_mapping_node(providers, index)
            node = key
        else:
            _, entries = _yaml_mapping_node(http, family)
            node = entries.value[index] if isinstance(entries, SequenceNode) and index < len(entries.value) else None
        if node is None:
            raise ValueError('Cannot preserve the required source comment placement')
        start = raw.rfind('\n', 0, node.start_mark.index) + 1
        # Comments beside a flow declaration attach to that containing line.
        prefix = raw[start:node.start_mark.index]
        indent = re.match(r'[ \t]*', prefix).group()
        insertions.setdefault(start, []).extend(
            indent + re.sub(r'^\s*(?://|;)\s?', '# ', comment) + '\n'
            for comment in comments)
    updated = raw
    newline = '\r\n' if '\r\n' in raw else '\n'
    for start, comments in sorted(insertions.items(), reverse=True):
        updated = updated[:start] + ''.join(comments).replace('\n', newline) + updated[start:]
    if updated != raw:
        fom.modify(raw, updated, count=1)


def _merge_file_metadata(fom, item):
    name, value = item.fields.get('name'), item.fields.get('value')
    if name not in {'author', 'homepage', 'repo'} or not isinstance(value, str) or not value.strip() or any(c in value for c in '\r\n\0'):
        raise ValueError('Module provenance metadata requires a known field and non-empty value')
    if isinstance(fom, StashMixin):
        # Source module signatures remain readable ordinary YAML provenance comments.
        raw = fom.render_bytes().decode(fom._encoding)
        line = '# ' + ('AUTHOR' if name == 'author' else 'REPO') + ': ' + value
        if line not in raw.splitlines():
            fom.modify(raw, line + '\n' + raw, count=1)
        return
    line = item.native_content if getattr(fom, 'is_module', False) else '# ' + ('AUTHOR' if name == 'author' else 'REPO') + ': ' + value
    if not any(node.render().strip() == line.strip() for node in fom.header_nodes):
        fom.header_nodes.append(CommentNode(line))
        fom.is_dirty = True

"""Explicit native entry validation and a common public FOM entrance."""
import logging

from rule_framework.rule_helpers import STANDARD_TYPES, CLIENT_STRUCTURED_TYPES, validate_standard_value, validate_options

logger = logging.getLogger('RuleFramework')
KNOWN = ('known-fields', 'known-fields')
OPAQUE = ('recognition-only', 'unknown')


def validate_native_declaration(action):
    allowed = {'action', 'type', 'kind', 'content', 'insert', 'section', 'file', 'targets', 'name', 'task'}
    unsupported = set(action) - allowed
    if unsupported:
        raise ValueError(f'Unsupported add_native fields: {sorted(unsupported)}')
    if not isinstance(action.get('kind'), str) or action.get('kind') not in {'rule', 'rewrite', 'script', 'declaration'}:
        raise ValueError('add_native.kind must be rule, rewrite, script or declaration')
    content = action.get('content')
    if not isinstance(content, str) or not content.strip() or any((ord(char) < 32 and char != '\t') or char in '\x7f\x85\u2028\u2029' for char in content):
        raise ValueError('add_native.content must be one non-empty line')
    if action.get('kind') != 'declaration' and action.get('section') is not None:
        raise ValueError('add_native.section belongs to kind=declaration; typed native entries use insert.section for location')
    if action.get('kind') == 'declaration':
        section = action.get('section')
        if not isinstance(section, str) or not section.strip() or any(char in section for char in '[]\r\n\0'):
            raise ValueError('add_native.section must name one explicit native section')


def rule_scope(fom, content):
    from rule_framework.quantumult_lists import QuantumultListMixin
    client = 'Quantumult X' if isinstance(fom, QuantumultListMixin) else getattr(fom, 'client', None)
    prefix = content.split(',', 1)[0].strip().upper()
    if client == 'AdGuard':
        from rule_framework.adguard_filters import BasicDomainFilterNode, parse_filter_line, validate_filter_value
        node = parse_filter_line(content)
        if isinstance(node, BasicDomainFilterNode):
            validate_filter_value(node.core_domain)
            return KNOWN
        return OPAQUE
    if client in {'mihomo', 'Stash'}:
        from rule_framework.mihomo_formats import MIHOMO_TYPES, MihomoRuleNode, validate_mihomo_node
        behavior = getattr(fom, 'behavior', 'classical')
        known = MIHOMO_TYPES | {'MATCH'} if client == 'mihomo' else STANDARD_TYPES | {'DOMAIN-REGEX', 'MATCH'}
        if behavior == 'classical' and prefix not in known:
            return OPAQUE
        node = MihomoRuleNode(content, behavior, profile=client == 'Stash' or fom.file_role == 'full-profile')
        if client == 'Stash':
            from rule_framework.stash_formats import validate_stash_rule
            validate_stash_rule(node)
        else:
            validate_mihomo_node(node, behavior)
            fom._validate_policy_target(node)
        return KNOWN
    if client == 'Quantumult X':
        from rule_framework.quantumult_lists import (QUANTUMULT_TYPES, QuantumultRuleNode,
            validate_quantumult_value, validate_quantumult_policy, validate_quantumult_options)
        if prefix not in QUANTUMULT_TYPES:
            return OPAQUE
        try:
            node = QuantumultRuleNode(content)
        except IndexError as error:
            raise ValueError('Quantumult X native rule requires value and policy fields') from error
        validate_quantumult_value(node.type.upper(), node.value)
        validate_quantumult_policy(node.policy)
        validate_quantumult_options(node.options)
        return KNOWN
    if client in CLIENT_STRUCTURED_TYPES:
        from rule_framework.surge import SurgeRuleNode, single_line
        if getattr(fom, 'file_role', None) == 'domain-set':
            from rule_framework.standard_lists import DomainSetNode
            node = DomainSetNode(content)
            if node.type.upper() not in {'DOMAIN', 'DOMAIN-SUFFIX'}:
                return OPAQUE
            validate_standard_value(node.type.upper(), node.value)
            return KNOWN
        if prefix not in CLIENT_STRUCTURED_TYPES[client] | {'FINAL'}:
            return OPAQUE
        if hasattr(fom, 'sections'):
            if client == 'Loon':
                from rule_framework.loon import LoonRuleNode
                node = LoonRuleNode(content, allow_implicit_policy=fom.is_module)
            else:
                node = SurgeRuleNode(content)
            single_line(node.policy, client + ' native policy')
            if client == 'Surge' and fom.is_module and node.policy not in {'DIRECT', 'REJECT', 'REJECT-TINYGIF'}:
                raise ValueError('Surge module rules require internal policies: DIRECT, REJECT, REJECT-TINYGIF')
            if client == 'Loon' and fom.is_module and node.policy not in {'DIRECT', 'PROXY', 'REJECT', 'REJECT-DROP', 'REJECT-IMG', 'REJECT-DICT', 'REJECT-ARRAY'}:
                raise ValueError('Loon plugin requires a supported internal policy')
        else:
            from rule_framework.standard_lists import StandardRuleNode
            node = StandardRuleNode(content)
        if node.type.upper() != 'FINAL':
            validate_standard_value(node.type.upper(), node.value, client=client)
        option_names = {'no-resolve', 'extended-matching', 'pre-matching'} if client == 'Shadowrocket' else {'no-resolve', 'extended-matching'}
        known_options = tuple(option for option in node.options if option in option_names)
        if client == 'Shadowrocket':
            from rule_framework.shadowrocket import validate_options as shadowrocket_options
            shadowrocket_options(known_options, node.type.upper())
        else:
            validate_options(known_options, node.type.upper(), client)
        return KNOWN if known_options == node.options else ('known-fields', 'unknown')
    raise ValueError(f'{type(fom).__name__} has no verified native client format')


def rewrite_scope(fom, content):
    from rule_framework.surge import single_line, split_comment, token_spans, unquote
    client = getattr(fom, 'client', None)
    if client == 'Quantumult X':
        import re
        from rule_framework.quantumult import HTTP_MODES, QuantumultHTTPNode, validate_http
        marker = re.search(r'\s+url(?:-and-header)?\s+([\w-]+)', content)
        if not marker or marker[1] not in HTTP_MODES:
            return OPAQUE
        node = QuantumultHTTPNode(content)
        try:
            validate_http(node)
        except ValueError as error:
            if not isinstance(error.__cause__, re.error):
                raise
            validate_http(node, validate_patterns=False)
            return ('known-fields', 'unknown')
        return KNOWN
    if client == 'Stash':
        from rule_framework.stash_formats import _rewrite_parts, _rewrite_result
        from rule_framework.rule_helpers import UNSET
        _, target, mode = _rewrite_parts(content)
        _rewrite_result(target, mode, UNSET, UNSET, UNSET)
        return KNOWN
    if client in {'Surge', 'Loon', 'Shadowrocket'}:
        tokens = [unquote(item.group()) for item in token_spans(split_comment(content)[0])]
        if client == 'Surge':
            from rule_framework.surge import SurgeURLRewriteNode
            modes, parser = {'reject', 'header', '302', '307'}, SurgeURLRewriteNode
        elif client == 'Loon':
            from rule_framework.loon import REWRITE_MODES, LoonRewriteNode
            modes, parser = REWRITE_MODES, LoonRewriteNode
        else:
            from rule_framework.shadowrocket import REWRITE_MODES, ShadowrocketRewriteNode
            modes, parser = REWRITE_MODES, ShadowrocketRewriteNode
        if not any(token in modes for token in tokens[1:]):
            return OPAQUE
        node = parser(content)
        single_line(node.match_pattern, client + ' native URL pattern')
        if node.mode not in modes:
            raise ValueError(client + ' native rewrite result is invalid')
        if node.mode in {'302', '307', 'header'}:
            single_line(node.replacement, client + ' native replacement')
            if node.replacement in {'-', '_', 'reject'}:
                raise ValueError(client + ' native redirect/header requires a replacement')
        return KNOWN
    raise ValueError(f'{type(fom).__name__} does not support native rewrite input')


def script_scope(fom, content):
    import re
    client = getattr(fom, 'client', None)
    if client == 'Stash':
        from ruamel.yaml import YAML
        from rule_framework.stash_formats import SCRIPT_FIELDS, validate_script_fields
        value = YAML().load(content)
        validate_script_fields(value)
        return (KNOWN if not set(value) - SCRIPT_FIELDS - {'script', 'requires-body'} else ('known-fields', 'unknown')), value
    if client == 'Quantumult X':
        if re.search(r'\surl(?:-and-header)?\s', content):
            return rewrite_scope(fom, content), content
        from rule_framework.quantumult import QuantumultLocalScriptNode, validate_local_script
        section = 'http_backend' if len(content.split(',', 1)[0].split()) == 1 else 'task_local'
        node = QuantumultLocalScriptNode(content, section)
        validate_local_script(node)
        return KNOWN, content
    if client in {'Surge', 'Shadowrocket', 'Loon'}:
        if client == 'Surge':
            from rule_framework.surge import SurgeScriptNode as Parser, SCRIPT_FIELDS, validate_script
        elif client == 'Shadowrocket':
            from rule_framework.shadowrocket import ShadowrocketScriptNode as Parser, SCRIPT_FIELDS, validate_script
        else:
            from rule_framework.loon import LoonScriptNode as Parser, SCRIPT_FIELDS, validate_script
            if re.match(r'\s*(?:request|response)\s+if\b', content):
                return OPAQUE, content
        node = Parser(content)
        if node.fields.get('type') not in {'http-request', 'http-response', 'cron'}:
            return ('known-fields', 'unknown'), content
        validate_script({key: value for key, value in node.fields.items() if key in SCRIPT_FIELDS})
        return (KNOWN if not set(node.fields) - SCRIPT_FIELDS else ('known-fields', 'unknown')), content
    raise ValueError(f'{type(fom).__name__} does not support native script input')


def declaration_scope(fom, content, section):
    client = getattr(fom, 'client', None)
    if client == 'Stash':
        if section == 'http.mitm':
            from rule_framework.stash_formats import _mitm_item
            _mitm_item(content)
            return KNOWN
        if section == 'http.body-rewrite':
            from rule_framework.stash_formats import _body_jq_parts, _body_jq_fields
            parts = content.split(None, 2)
            if len(parts) != 3:
                raise ValueError('Stash native body declaration requires URL, action and expression')
            if parts[1] in {'request-jq', 'response-jq'}:
                _body_jq_fields(_body_jq_parts(content), complete=True)
                return KNOWN
            return OPAQUE
        raise ValueError(f'Unsupported native Stash declaration section: {section}')
    if client == 'Quantumult X':
        if section == 'mitm':
            from rule_framework.quantumult import QuantumultMITMNode, validate_hostnames
            node = QuantumultMITMNode(content)
            validate_hostnames(node.hostnames)
            return KNOWN
        if section == 'filter_local':
            return rule_scope(fom, content)
        if section == 'rewrite_local':
            return rewrite_scope(fom, content)
        if section in {'task_local', 'http_backend'}:
            from rule_framework.quantumult import QuantumultLocalScriptNode, validate_local_script
            validate_local_script(QuantumultLocalScriptNode(content, section))
            return KNOWN
        return OPAQUE
    if client in {'Surge', 'Loon', 'Shadowrocket'} and hasattr(fom, '_add_native'):
        if section == 'Rule':
            return rule_scope(fom, content)
        if section in {'Rewrite', 'URL Rewrite'}:
            return rewrite_scope(fom, content)
        if section == 'Script':
            return script_scope(fom, content)[0]
        if section == 'MITM':
            if client == 'Loon':
                from rule_framework.loon import LoonMITMNode as Parser, mitm_reference
            elif client == 'Shadowrocket':
                from rule_framework.shadowrocket import ShadowrocketMITMNode as Parser
                from rule_framework.surge import mitm_reference
            else:
                from rule_framework.surge import SurgeMITMNode as Parser, mitm_reference
            node = Parser(content)
            if not node.hostnames:
                raise ValueError(client + ' native MITM requires at least one hostname')
            for host in node.hostnames:
                mitm_reference(host)
            return ('known-fields', 'unknown') if client == 'Loon' and node.operator else KNOWN
        if section == 'Map Local' and client == 'Surge':
            from rule_framework.surge import SurgeMapLocalNode, validate_map_local
            node = SurgeMapLocalNode(content)
            validate_map_local({key: value for key, value in node.fields.items() if key in {'data', 'data-type', 'status-code', 'header'}})
            return KNOWN if not set(node.fields) - {'data', 'data-type', 'status-code', 'header'} else ('known-fields', 'unknown')
        return OPAQUE
    raise ValueError(f'{type(fom).__name__} does not support native section declarations')


def apply_native(fom, content, *, kind, insert=None, section=None):
    validate_native_declaration({'kind': kind, 'content': content, 'section': section})
    if kind == 'rule':
        operation = getattr(fom, 'add_native_rule', None)
        if operation is None:
            raise ValueError(f'{type(fom).__name__} does not support native rule input')
        syntax, semantic = rule_scope(fom, content)
        operation(content, insert=insert)
    elif kind == 'rewrite':
        syntax, semantic = rewrite_scope(fom, content)
        operation = getattr(fom, 'add_url_rewrite', fom.add_rewrite)
        operation(raw_content=content, insert=insert)
    elif kind == 'script':
        (syntax, semantic), value = script_scope(fom, content)
        fom.add_script(value, insert=insert)
    else:
        syntax, semantic = declaration_scope(fom, content, section)
        if getattr(fom, 'client', None) == 'Stash':
            from rule_framework.rule_helpers import calculate_insert_index
            family = section.split('.')[1]
            entries = fom._sequence(fom._http(create=True), family, create=True)
            index = calculate_insert_index(entries, insert, is_section=True, section_name=section)
            if content not in entries:
                entries.insert(index, content)
                if semantic == 'unknown':
                    fom._native_entries.add((section, content))
                fom.is_dirty = True
        else:
            fom._add_native(section, content, insert)
    for nodes in [getattr(fom, 'nodes', []), getattr(fom, 'header_nodes', []), *getattr(fom, 'sections', {}).values()]:
        for node in nodes:
            if node.render() == content:
                if semantic == 'known-fields':
                    node._native_input = False
                else:
                    node._opaque_native_line = content
    logger.info('Native input: preservation=verbatim; syntax-validation=%s; semantic-validation=%s; '
                'client-validation=not-run; kind=%s; format=%s in %s', syntax, semantic, kind,
                getattr(fom, 'file_role', 'unknown'), fom.filepath)


def guard_required_rule_semantics(fom, rule_type, value):
    from rule_framework.ast import RuleNode
    from rule_framework.domain_refs import canonical_domain
    from rule_framework.rule_helpers import select_rule_types
    if rule_type != 'domain':
        return
    for nodes in [getattr(fom, 'nodes', []), getattr(fom, 'header_nodes', []), *getattr(fom, 'sections', {}).values()]:
        for node in nodes:
            if isinstance(node, RuleNode) and node.type.upper() in select_rule_types(rule_type) and getattr(node, 'options', ()):
                if value is None or canonical_domain(node.value) == canonical_domain(value):
                    if rule_scope(fom, node.render())[1] == 'unknown':
                        raise ValueError(f'Cannot maintain required domain reference with unknown native matching semantics '
                                         f'in {fom.filepath}: {node.render()!r}')


def validate_native_entry(fom, content, *, kind, section=None):
    validate_native_declaration({'kind': kind, 'content': content, 'section': section})
    if kind == 'rule':
        scope = rule_scope(fom, content)
    elif kind == 'rewrite':
        scope = rewrite_scope(fom, content)
    elif kind == 'script':
        scope = script_scope(fom, content)[0]
    else:
        scope = declaration_scope(fom, content, section)
    logger.info('Native input: preservation=verbatim; syntax-validation=%s; semantic-validation=%s; '
                'client-validation=not-run; kind=%s; format=%s; section=%s in %s', *scope, kind,
                getattr(fom, 'file_role', 'unknown'), section, fom.filepath)
    return scope


def guard_required_script_fields(fom, fields):
    client = getattr(fom, 'client', None)
    if client == 'Surge':
        from rule_framework.surge import SCRIPT_FIELDS as known
    elif client == 'Loon':
        from rule_framework.loon import SCRIPT_FIELDS as known
    elif client == 'Shadowrocket':
        from rule_framework.shadowrocket import SCRIPT_FIELDS as known
    elif client == 'Stash':
        from rule_framework.stash_formats import SCRIPT_FIELDS
        known = SCRIPT_FIELDS | {'script', 'requires-body'}
    else:
        return
    unknown = set(fields) - known
    if unknown:
        raise ValueError(f'Cannot recognize required domain references with unknown native script fields '
                         f'{sorted(unknown)} in {fom.filepath}')

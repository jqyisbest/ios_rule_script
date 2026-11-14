"""Personal WeChat migration through managed FOMs and routing collections.

The numeric keyword transform intentionally changes matching behavior. General
routing conversion retains DOMAIN-KEYWORD and rejects unsupported directions.
"""

from dataclasses import replace
import re

from rule_framework.ast import CommentNode, RuleNode
from rule_framework.fom import ClashYamlFile, StandardListFile
from rule_framework.metadata import resolve_signature
from rule_framework.routing_conversion import RuleCollection


SURGE_WECHAT = 'rule/Surge/WeChat/WeChat.list'
LOON_WECHAT = 'rule/Loon/WeChat/WeChat.list'
CLASH_WECHAT = 'rule/Clash/WeChat/WeChat.yaml'
PERSONAL_WECHAT_USER_AGENTS = frozenset({'MicroMessenger*', 'WeChat*'})
OCTET = r'(?:25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9]?[0-9])'


def _transform(collection, logger, *, omit_asn=False):
    records = []
    for rule in collection.rules:
        if omit_asn and rule.type == 'IP-ASN':
            continue
        value = rule.value
        if rule.type == 'DOMAIN-KEYWORD':
            full = re.fullmatch(rf'(?:{OCTET}\.){{3}}{OCTET}', value)
            prefix = re.fullmatch(rf'(?:{OCTET}\.){{1,3}}', value)
            if full or prefix:
                octets = [int(part) for part in value.rstrip('.').split('.')]
                length = len(octets)
                address = '.'.join(str(part) for part in octets + [0] * (4 - length))
                rule = replace(rule, type='IP-CIDR', value=f'{address}/{length * 8}',
                               conditions=tuple(dict.fromkeys((*rule.conditions, 'no-resolve'))))
                logger.info('Personal matching transform: DOMAIN-KEYWORD,%s -> IP-CIDR,%s,no-resolve; '
                            'domain keyword and destination-IP matching differ; source=%s',
                            value, rule.value, rule.location)
        records.append(rule)
    return RuleCollection(tuple(records))


def _line(rule):
    return ','.join((rule.type, rule.value, *rule.conditions))


def _unique(collections, *, sort=False):
    records = {}
    for collection in collections:
        for rule in collection.rules:
            old = records.get(rule.identity)
            if old and (old.policy, old.result_options) != (rule.policy, rule.result_options):
                raise ValueError(f'Personal WeChat identity has conflicting results at {rule.location}')
            records.setdefault(rule.identity, rule)
    values = tuple(records.values())
    return RuleCollection(tuple(sorted(values, key=_line)) if sort else values)


def _signature_identity(line):
    match = re.fullmatch(r'\s*#\s+(AUTHOR|REPO):\s*(.*?)\s*', line)
    return (match[1], match[2].strip()) if match else None


def _comments(source, settings):
    author, repo = resolve_signature(settings)
    own = {('AUTHOR', author), ('REPO', repo)}
    comments = [node.render() for node in source.nodes if isinstance(node, CommentNode)]
    if not any(line.startswith('# NAME:') for line in comments):
        comments.insert(0, '# NAME: WeChat')
    comments = [line for line in comments if _signature_identity(line) not in own]
    index = next((index for index, line in enumerate(comments) if line.startswith('# AUTHOR:')),
                 next((index + 1 for index, line in enumerate(comments) if line.startswith('# NAME:')), 0))
    comments[index:index] = [f'# AUTHOR: {author}', f'# REPO: {repo}']
    return comments


def _metadata_satisfied(target, source, total):
    text = ('\n'.join(node.render() for node in target.nodes) if isinstance(target, StandardListFile)
            else target.render_bytes().decode('utf-8-sig'))
    settings = target.settings
    author, repo = resolve_signature(settings)
    own = {('AUTHOR', author), ('REPO', repo)}
    required = [f'# TOTAL: {total}']
    required.extend(node.render() for node in source.nodes if isinstance(node, CommentNode)
                    and node.render().startswith(('# AUTHOR:', '# REPO:'))
                    and _signature_identity(node.render()) not in own)
    lines = text.splitlines()
    authors = [index for index, line in enumerate(lines) if _signature_identity(line) == ('AUTHOR', author)]
    repos = [index for index, line in enumerate(lines) if _signature_identity(line) == ('REPO', repo)]
    if len(authors) != 1 or len(repos) != 1:
        return False
    upstream = [index for index, line in enumerate(lines)
                if line.startswith('# AUTHOR:') and _signature_identity(line) != ('AUTHOR', author)]
    if upstream and max(authors[0], repos[0]) >= min(upstream):
        return False
    return all(line in lines for line in required)


def _classical_yaml(path):
    target = ClashYamlFile(path)
    target.behavior = 'classical'
    return target


def _provider_header(target, source):
    """Change generated metadata while retaining unrelated current YAML bytes."""
    from rule_framework.rule_helpers import STANDARD_TYPES
    previous = target.render_bytes().decode('utf-8-sig')
    records = previous.splitlines(keepends=True)
    old_header, offset = [], 0
    for record in records:
        if record.strip() and not record.lstrip().startswith('#'):
            break
        old_header.append(record)
        offset += len(record)
    newline = next((match.group() for match in re.finditer(r'\r\n|\n|\r', previous)), '\n')
    comments = _comments(source, target.settings)
    extra, signatures = [], []
    author, repo = resolve_signature(target.settings)
    own = {'AUTHOR': author, 'REPO': repo}
    generated = STANDARD_TYPES | {'NAME', 'TOTAL', 'UPDATED', 'AND', 'OR', 'NOT', 'Total count'}
    for record in old_header:
        line = record.rstrip('\r\n')
        match = re.fullmatch(r'\s*#\s+([^:]+):\s*(.*?)\s*', line)
        key = match.group(1) if match else None
        if key in own:
            if match.group(2) != own[key] and line not in comments:
                signatures.append(record)
        elif key not in generated and line not in comments:
            extra.append(record)
    header = ''.join(extra) + newline.join(comments) + newline + ''.join(signatures)
    # Existing YAML body, including unknown fields and their annotations, is
    # retained exactly at this explicit text boundary.
    target.modify(previous, header + previous[offset:])


def build_clash_wechat(fom, workspace, logger):
    """Replace the personal classical provider using current staged Surge rules."""
    if workspace.resolve_path(fom.filepath) != workspace.resolve_path(SURGE_WECHAT):
        raise ValueError(f'WeChat source must be {SURGE_WECHAT}')
    collection = _unique([_transform(fom.export_rules(), logger, omit_asn=True)])
    retained = []
    for rule in collection.rules:
        if rule.type == 'USER-AGENT' and rule.value in PERSONAL_WECHAT_USER_AGENTS:
            logger.warning('Personal WeChat mihomo explicitly omits USER-AGENT,%s; '
                           'matching scope reduced by maintainer decision; source=%s',
                           rule.value, rule.location)
        else:
            retained.append(rule)
    collection = RuleCollection(tuple(retained))
    user_agent = next((rule for rule in collection.rules if rule.type == 'USER-AGENT'), None)
    if user_agent is not None:
        raise ValueError('mihomo required USER-AGENT is unsupported in inspected parser '
                         '88dcbf7f1614a67c3b36b848ee3592dfa92ada36; '
                         f'source={user_agent.location}; client-runtime=unknown')
    target = workspace.get_fom(CLASH_WECHAT, factory=_classical_yaml)
    if not isinstance(target, ClashYamlFile) or target.file_role != 'rule-provider' or target.behavior != 'classical':
        raise ValueError('Personal WeChat destination requires a mihomo classical YAML rule-provider')
    target.merge_rules(collection, destination={'client': 'mihomo', 'format': 'classical-yaml'})
    values = [_line(rule) for rule in collection.rules]
    if list(target.data['payload']) == values and _metadata_satisfied(target, fom, len(values)):
        logger.info('Personal WeChat mihomo output already satisfied; modified=0')
        return
    _provider_header(target, fom)
    target.data['payload'] = target.yaml.load('[]\n')
    target.behavior = 'classical'
    target.merge_rules(collection, destination={'client': 'mihomo', 'format': 'classical-yaml'})
    target.is_dirty = True
    target.update_metadata()


def build_loon_wechat(fom, workspace, logger):
    """Merge current staged Surge/Loon sources, deduplicate and sort the output."""
    if workspace.resolve_path(fom.filepath) != workspace.resolve_path(LOON_WECHAT):
        raise ValueError(f'WeChat destination must be {LOON_WECHAT}')
    if not isinstance(fom, StandardListFile) or fom.client != 'Loon' or fom.file_role != 'rule-set':
        raise ValueError('Personal WeChat destination requires a Loon external rule-set')
    source = workspace.get_fom(SURGE_WECHAT)
    collection = _unique([_transform(source.export_rules(), logger),
                          _transform(fom.export_rules(), logger)], sort=True)
    # The maintainer explicitly selected these Loon-native declarations.
    # Keep their source locations while leaving generic conversion bounded by
    # its existing audited mappings; cross-client runtime parity is unknown.
    native = tuple(rule for rule in collection.rules
                   if rule.type == 'USER-AGENT' and rule.value in PERSONAL_WECHAT_USER_AGENTS
                   and not rule.conditions)
    converted = RuleCollection(tuple(rule for rule in collection.rules if rule not in native))
    for rule in native:
        logger.warning('Personal WeChat Loon retains explicit native USER-AGENT,%s; '
                       'source=%s; cross-client-runtime-parity=unknown', rule.value, rule.location)
    # Required conversion checks apply even when old output looks satisfied.
    fom.merge_rules(converted, destination={'client': 'Loon', 'format': 'rule-set'})
    values = [_line(rule) for rule in collection.rules]
    active = [node.render().strip() for node in fom.nodes
              if node.render().strip() and not isinstance(node, CommentNode)]
    if active == values and _metadata_satisfied(fom, source, len(values)):
        logger.info('Personal WeChat Loon output already satisfied; modified=0')
        return
    comments = _comments(fom, fom.settings)
    author, repo = resolve_signature(fom.settings)
    own = {('AUTHOR', author), ('REPO', repo)}
    for node in source.nodes:
        line = node.render()
        if (isinstance(node, CommentNode) and line.startswith(('# AUTHOR:', '# REPO:'))
                and _signature_identity(line) not in own and line not in comments):
            comments.append(line)
    fom.nodes = [CommentNode(line) for line in comments]
    fom.merge_rules(converted, destination={'client': 'Loon', 'format': 'rule-set'})
    for rule in native:
        fom.add_native_rule(_line(rule))
    positions = [index for index, node in enumerate(fom.nodes) if isinstance(node, RuleNode)]
    ordered = sorted((fom.nodes[index] for index in positions), key=lambda node: node.render().strip())
    for index, node in zip(positions, ordered):
        fom.nodes[index] = node
    fom.is_dirty = True
    fom.update_metadata()


def normalize_advertising_lite(fom, workspace, logger):
    """Apply the original personal URL-pattern changes to structured rewrites."""
    from rule_framework.loon import LoonFile, LoonRewriteNode, LoonUnknownNode, REJECTS
    if not isinstance(fom, LoonFile) or not fom.is_module:
        raise ValueError('AdvertisingLite normalization requires a Loon plugin')
    old_ml = r'^https?:\/\/mlol\.qt\.qq\.com\/go\/recommend'
    new_ml = r'^https?:\/\/mlol\.qt\.qq\.com\/go\/recommend\/(?!v2\/platactivity.*)'
    protocol = r'^\^?\^?https?\??:?(//|\\/\\/)'
    changed = 0
    for section, nodes in fom.sections.items():
        if section.split('\0')[0].lower() not in ('rewrite', 'url rewrite'):
            continue
        for node in nodes:
            if isinstance(node, LoonUnknownNode) and re.match(protocol, node.render()):
                raise ValueError('Cannot recognize required AdvertisingLite Loon rewrite fields')
            if not isinstance(node, LoonRewriteNode):
                continue
            pattern = re.sub(protocol, lambda match: r'^https?:\/\/', node.match_pattern)
            if pattern == old_ml and node.mode in REJECTS:
                pattern = new_ml
            if pattern != node.match_pattern:
                node.match_pattern = pattern
                changed += 1
    if changed:
        fom.is_dirty = True
        fom.update_metadata()
    logger.info('Personal AdvertisingLite URL-pattern normalization: modified=%d; '
                'rewrite results/comments retained; client-runtime=unknown', changed)

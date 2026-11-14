"""Client clues scoped to managed paths, with explicit named-list aliases."""

import os

MANAGED_ROOTS={'rule','rewrite','script'}
CLIENT_NAMESPACES={
    'adguard':'AdGuard', 'surge':'Surge', 'loon':'Loon', 'shadowrocket':'Shadowrocket', 'stash':'Stash',
    'clash':'mihomo', 'mihomo':'mihomo', 'quantumultx':'Quantumult X', 'quantumult-x':'Quantumult X',
    'quantumult x':'Quantumult X', 'quanx':'Quantumult X',
}


def recognizes_mihomo_yaml(filepath, data=None):
    try:
        if data is not None:
            raw = data if isinstance(data, bytes) else str(data).encode('utf-8')
        elif not os.path.isfile(filepath):
            return False
        else:
            with open(filepath, 'rb') as f:
                raw = f.read()
        from rule_framework.text_json import decode_text
        text, _, _ = decode_text(raw)
        from ruamel.yaml import YAML
        from ruamel.yaml.error import YAMLError
        from ruamel.yaml.nodes import MappingNode, ScalarNode, SequenceNode
        keys = {'payload', 'rules', 'proxies', 'proxy-groups', 'rule-providers', 'mixed-port'}
        try:
            document = YAML(typ='safe').compose(text)
        except YAMLError:
            # A malformed native-looking document must retain its load failure.
            import re
            lines = [line for line in text.splitlines() if line.strip()
                     and not line.lstrip().startswith(('#', '%', '---', '...'))]
            if not lines:
                return False
            indentation = min(len(line) - len(line.lstrip()) for line in lines)
            names = '(?:' + '|'.join(sorted(keys)) + ')'
            pattern = r'^(?:\{[ \t]*)?(?:' + names + '|"' + names + '"|' + "'" + names + "')[ \t]*:"
            return any(re.match(pattern, line.lstrip()) for line in lines
                       if len(line) - len(line.lstrip()) == indentation)
        active = set()
        resolved = {}

        def mapping_fields(node):
            if not isinstance(node, MappingNode) or id(node) in active:
                return {}
            if id(node) in resolved:
                return resolved[id(node)]
            active.add(id(node))
            fields = {}
            for key, value in node.value:
                if key.tag == 'tag:yaml.org,2002:merge':
                    merged = value.value if isinstance(value, SequenceNode) else (value,)
                    for item in reversed(merged):
                        fields.update(mapping_fields(item))
            for key, value in node.value:
                if key.tag != 'tag:yaml.org,2002:merge' and isinstance(key.value, str):
                    fields[key.value] = value
            active.remove(id(node))
            resolved[id(node)] = fields
            return fields

        fields = mapping_fields(document)
        for name in ('payload', 'rules'):
            value = fields.get(name)
            if isinstance(value, SequenceNode) and all(
                    isinstance(item, ScalarNode) and item.tag == 'tag:yaml.org,2002:str'
                    for item in value.value):
                return True
        for name in ('proxies', 'proxy-groups'):
            value = fields.get(name)
            if isinstance(value, SequenceNode) and all(
                    isinstance(item, MappingNode) and {'name', 'type'} <= mapping_fields(item).keys()
                    for item in value.value):
                return True
        if isinstance(fields.get('rule-providers'), MappingNode):
            return all(isinstance(item, MappingNode) for item in mapping_fields(fields['rule-providers']).values())
        port = fields.get('mixed-port')
        return isinstance(port, ScalarNode) and port.tag == 'tag:yaml.org,2002:int'
    except Exception:
        return False


def client_for_path(filepath, *, base_dir=None, data=None):
    """Use the declared workspace first; standalone paths use their managed suffix."""
    path=os.fspath(filepath)
    if base_dir is not None:
        try:
            absolute=os.path.abspath(path) if os.path.isabs(path) else os.path.abspath(os.path.join(base_dir,path))
            path=os.path.relpath(absolute,os.path.abspath(base_dir))
        except ValueError:
            return 'unknown'
        if path == os.pardir or path.startswith(os.pardir+os.sep):
            return 'unknown'
    parts=os.path.normpath(path).replace('\\','/').split('/')
    if base_dir is None and os.path.isabs(path):
        roots=[index for index,part in enumerate(parts[:-1]) if part.lower() in MANAGED_ROOTS]
        parts=parts[roots[-1]:] if roots else parts[-1:]
    if len(parts)>=3 and parts[0].lower() in MANAGED_ROOTS:
        client=CLIENT_NAMESPACES.get(parts[1].lower())
        if client:
            return client
    # Stash's documented unique override suffix also identifies script assets.
    suffix = os.path.splitext(parts[-1])[1].lower()
    suffix_clients = {'.stoverride': 'Stash', '.lnscript': 'Loon', '.lnplugin': 'Loon', '.plugin': 'Loon', '.qxrewrite': 'Quantumult X'}
    if suffix in suffix_clients:
        return suffix_clients[suffix]
    if suffix == '.snippet':
        from rule_framework.quantumult import recognizes_quantumult_snippet
        if recognizes_quantumult_snippet(absolute if base_dir is not None else filepath, data=data):
            return 'Quantumult X'
    if suffix in ('.yaml', '.yml'):
        if recognizes_mihomo_yaml(absolute if base_dir is not None else filepath, data=data):
            return 'mihomo'
    # These already supported exact filename aliases are explicit client clues.
    # Passing only the basename excludes checkout and arbitrary category folders.
    from rule_framework.quantumult_lists import is_quantumult_path
    from rule_framework.mihomo_formats import is_mihomo_path
    if is_quantumult_path(parts[-1]):
        return 'Quantumult X'
    if is_mihomo_path(parts[-1]):
        return 'mihomo'
    return 'unknown'

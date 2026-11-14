from dataclasses import dataclass


DEFAULT_ASN_TARGETS = (
    'rule/Clash/**/*.yaml', 'rule/Clash/**/*.list', 'rule/Surge/**/*.list',
    'rule/Loon/**/*.list', 'rule/QuantumultX/**/*.list',
)


@dataclass(frozen=True)
class SOPExpansion:
    declaration: dict
    action_sources: tuple
    template: str | None = None


def _scope(definition):
    if 'file' in definition and 'targets' in definition:
        raise ValueError('SOP scope must specify either file or targets')
    if 'file' in definition:
        value = definition['file']
        if not isinstance(value, str) or not value.strip() or '\0' in value:
            raise ValueError('SOP file must be a non-empty text path without NUL characters')
        return (value,)
    if 'targets' in definition:
        values = definition['targets']
        if (not isinstance(values, list) or not values
                or any(not isinstance(value, str) or not value.strip() or '\0' in value
                       for value in values)):
            raise ValueError('SOP targets must be a non-empty list of non-empty text paths')
        return tuple(values)
    return None


def _template_actions(definition, *, inline=False):
    legacy = 'sop' in definition
    allowed = {'sop', 'asn', 'file', 'targets', 'name', 'task', 'actions'} if legacy else {
        'action', 'type', 'template', 'asn', 'file', 'targets',
    }
    if inline:
        allowed |= {'name', 'task', 'actions'}
    extra = set(definition) - allowed
    if extra:
        raise ValueError(f'Unsupported SOP fields: {sorted(extra)}')
    template = definition.get('sop') if legacy else definition.get('template')
    if not isinstance(template, str) or not template.strip():
        raise ValueError('SOP template must be a non-empty string')
    if legacy and definition.get('actions'):
        raise ValueError('Task-level SOP actions must be empty; use action: sop to order ordinary actions')
    if template != 'remove_asn_globally':
        raise ValueError(f'Unknown SOP template: {template}')
    match = {'type': 'asn'}
    if 'asn' in definition:
        value = definition['asn']
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ValueError('SOP asn must be a decimal string or integer in range 0..4294967295')
        from rule_framework.rule_helpers import validate_standard_value
        try:
            validate_standard_value('IP-ASN', str(value))
        except ValueError as error:
            raise ValueError(f'SOP asn: {error}') from error
        match['value'] = str(value)
    return [{'action': 'remove_rule', 'match': match}], template


def expand_sop_with_sources(mission):
    """Expand in place, carrying each original Action location and SOP name."""
    if 'sop' in mission:
        actions, template = _template_actions(mission)
        scope = _scope(mission)
        expanded = dict(mission, actions=actions)
        if scope is None:
            expanded['targets'] = list(DEFAULT_ASN_TARGETS)
        expanded.setdefault('name', f'SOP: {template}')
        return [SOPExpansion(expanded, tuple(('.sop', template) for _ in actions), template)]
    definitions = mission.get('actions', [])
    inline = not definitions and ('action' in mission or 'type' in mission)
    if inline:
        definitions = [mission]
    actions, sources, templates = [], [], []
    inherited_scope = _scope(mission) if any(
        (definition.get('action') or definition.get('type')) == 'sop' for definition in definitions
    ) else None
    for index, definition in enumerate(definitions):
        suffix = '' if inline else f'.actions[{index}]'
        if (definition.get('action') or definition.get('type')) == 'sop':
            generated, template = _template_actions(definition, inline=inline)
            actions.extend(generated)
            sources.extend((suffix, template) for _ in generated)
            templates.append(template)
            declared_scope = _scope(definition)
            if declared_scope is not None:
                if inherited_scope is not None and set(declared_scope) != set(inherited_scope):
                    raise ValueError('SOP action scope conflicts with its Task target scope')
                inherited_scope = declared_scope
        else:
            actions.append(definition)
            sources.append((suffix, None))
    expanded = dict(mission, actions=actions)
    if templates and not mission.get('targets') and not mission.get('file'):
        expanded['targets'] = list(inherited_scope or DEFAULT_ASN_TARGETS)
    template = templates[0] if len(set(templates)) == 1 else None
    return [SOPExpansion(expanded, tuple(sources), template)]


def expand_sop(mission: dict) -> list:
    """Return ordinary Task declarations for legacy callers."""
    return [expansion.declaration for expansion in expand_sop_with_sources(mission)]

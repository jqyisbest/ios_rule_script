"""Maintenance declarations and their observable execution results."""

from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from rule_framework.storage import SaveResult
    from rule_framework.publication import PublicationResult

from rule_framework.sops import SOPExpansion, expand_sop_with_sources


@dataclass(frozen=True)
class Source:
    config_path: Optional[str]
    path: str
    sop_template: Optional[str] = None


@dataclass(frozen=True)
class ActionSpec:
    id: str
    source: Source
    definition: dict

    @property
    def type(self):
        return self.definition.get('action') or self.definition.get('type')


@dataclass(frozen=True)
class Target:
    path: str
    patterns: tuple[str, ...]

    base_dir: Optional[str] = None

    @property
    def client(self):
        from rule_framework.client_paths import client_for_path
        return client_for_path(self.path, base_dir=self.base_dir)


@dataclass(frozen=True)
class Task:
    id: str
    name: str
    source: Source
    patterns: tuple[str, ...]
    actions: tuple[ActionSpec, ...]
    targets: tuple[Target, ...] = ()
    validation_error: Optional[str] = None
    source_ids: Optional[tuple[str, ...]] = None


@dataclass(frozen=True)
class ActionResult:
    action: ActionSpec
    target: Target
    status: str
    reason: Optional[str] = None
    fom_type: Optional[str] = None


@dataclass
class TaskResult:
    task: Task
    status: str = 'pending'
    action_results: list[ActionResult] = field(default_factory=list)
    reason: Optional[str] = None


@dataclass(frozen=True)
class MaintenanceResult:
    status: str
    task_results: tuple[TaskResult, ...]
    processed_files: tuple[str, ...] = ()
    dry_run: bool = False
    reason: Optional[str] = None
    save_result: Optional['SaveResult'] = None
    publication_result: Optional['PublicationResult'] = None
    source_results: tuple = ()



VALID_ACTIONS = {
    'add_native', 'merge_modules', 'merge_rules', 'json_remove', 'json_set', 'remove_rule', 'add_rule', 'modify', 'add_rewrite', 'remove_rewrite',
    'add_script', 'remove_script', 'add_mitm', 'remove_mitm', 'custom_hook', 'sop',
    'create_resource', 'replace_resource', 'copy_resource',
}


def _without_source_filter(declaration):
    """Keep Task source selection out of Action and SOP input."""
    return {key: value for key, value in declaration.items() if key != 'source_ids'}


def validate_task_declaration(declaration, *, require_targets=True):
    """Raise a declaration-local error; callers retain the Task and its source."""
    if not isinstance(declaration, dict):
        raise ValueError('Each task must be a dictionary')
    for key in ('name', 'task'):
        if key in declaration and (not isinstance(declaration[key], str) or not declaration[key].strip()):
            raise ValueError(f'{key} must be a non-empty string')
    if 'file' in declaration and (not isinstance(declaration['file'], str) or not declaration['file'].strip()):
        raise ValueError('file must be a non-empty string')
    if isinstance(declaration.get('file'), str) and '\0' in declaration['file']:
        raise ValueError('file must be a text path without NUL characters')
    if 'targets' in declaration:
        if not isinstance(declaration['targets'], list):
            raise ValueError('targets must be a list')
        if any(not isinstance(target, str) or not target.strip() for target in declaration['targets']):
            raise ValueError('Each target must be a non-empty string')
        if any('\0' in target for target in declaration['targets']):
            raise ValueError('Each target must be a text path without NUL characters')
    if 'source_ids' in declaration:
        from rule_framework.sources import validate_source_ids
        validate_source_ids(declaration['source_ids'])
    actions = declaration.get('actions', [])
    if not isinstance(actions, list):
        raise ValueError('actions must be a list')
    if not actions and ('action' in declaration or 'type' in declaration):
        actions = [_without_source_filter(declaration)]
    if not actions and 'sop' not in declaration:
        raise ValueError('Task must declare at least one action')
    for action in actions:
        if not isinstance(action, dict):
            raise ValueError('Each action must be a dictionary')
        kind = action.get('action') or action.get('type')
        if not isinstance(kind, str) or kind not in VALID_ACTIONS:
            raise ValueError(f'Unrecognized action type: {kind}')
        if kind == 'merge_modules':
            from rule_framework.module_conversion import validate_merge_declaration
            validate_merge_declaration(action)
        if kind == 'add_native':
            from rule_framework.native_input import validate_native_declaration
            validate_native_declaration(action)
        if kind == 'merge_rules':
            from rule_framework.routing_conversion import validate_merge_declaration
            validate_merge_declaration(action)
        if kind == 'json_remove':
            from rule_framework.text_json import validate_json_path
            if 'path' not in action:
                raise ValueError('json_remove requires an explicit path')
            validate_json_path(action['path'])
        if kind == 'json_set':
            from rule_framework.text_json import validate_json_path
            if 'path' not in action or 'value' not in action:
                raise ValueError('json_set requires path and an explicit value (null is allowed)')
            validate_json_path(action['path'])

        if kind in {'create_resource', 'copy_resource', 'replace_resource'}:
            from rule_framework.resources import validate_resource_declaration
            validate_resource_declaration(action)
        if kind == 'add_rule':
            rules = action.get('rules', [])
            if not isinstance(rules, list):
                raise ValueError('add_rule.rules must be a list')
            if not rules:
                raise ValueError('add_rule.rules must be a non-empty list')
            for rule in rules:
                if isinstance(rule, str) and rule.strip():
                    continue
                if not isinstance(rule, dict) or not isinstance(rule.get('type'), str) or not rule['type'].strip():
                    raise ValueError('Each rule must be a string or a dictionary with type and value')
                no_match_value = rule['type'].upper() == 'FINAL' and rule.get('value') is None
                if not no_match_value and (not isinstance(rule.get('value'), str) or not rule['value'].strip()):
                    raise ValueError('Each rule must be a string or a dictionary with type and value')
        if kind == 'modify':
            for key in ('search', 'replace'):
                if not isinstance(action.get(key, ''), str):
                    raise ValueError(f'modify.{key} must be a string')
            count = action.get('count', 0)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError('modify.count must be a non-negative integer')
            if not isinstance(action.get('is_regex', False), bool):
                raise ValueError('modify.is_regex must be a boolean')
            if 'search' not in action and (declaration.get('file') or declaration.get('targets')):
                raise ValueError('modify requires an explicit search string (an empty string is allowed)')
        if kind == 'remove_rule':
            match = action.get('match', {})
            if not isinstance(match, dict):
                raise ValueError('remove_rule.match must be a dictionary')
            unsupported = set(match) - {'type', 'value', 'conditions'}
            if unsupported:
                raise ValueError(f'Unsupported remove_rule.match fields: {sorted(unsupported)}')
            if not isinstance(match.get('type'), str) or not match['type'].strip():
                raise ValueError('remove_rule.match.type must be a non-empty string')
            if 'value' in match and (not isinstance(match['value'], str) or not match['value'].strip()):
                raise ValueError('remove_rule.match.value must be a non-empty string')
    if require_targets and not declaration.get('targets') and not declaration.get('file'):
        raise ValueError("Missing 'file' or 'targets' field")


def selected_task_declarations(config):
    """Select the preserved missions-first section and its declarations."""
    config_key = 'missions' if config.get('missions') else 'tasks'
    return config_key, config.get(config_key, [])


def build_tasks(config, *, config_path=None):
    """Expand declarations while retaining attributable errors as failed Tasks."""
    config_key, declarations = selected_task_declarations(config)
    tasks = []
    for index, declaration in enumerate(declarations):
        source_path = f'{config_key}[{index}]'
        task_id = f'task-{index + 1}'
        validation_error = None
        sop_template = None
        try:
            validate_task_declaration(declaration, require_targets=False)
            expanded = expand_sop_with_sources(_without_source_filter(declaration))
        except Exception as error:
            validation_error = str(error)
            original = declaration if isinstance(declaration, dict) else {}
            template = original.get('sop')
            if not isinstance(template, str):
                definitions = original.get('actions', [])
                if not definitions and (original.get('action') or original.get('type')) == 'sop':
                    definitions = [original]
                templates = ([definition.get('template') for definition in definitions
                              if isinstance(definition, dict)
                              and (definition.get('action') or definition.get('type')) == 'sop']
                             if isinstance(definitions, list) else [])
                template = templates[0] if len(templates) == 1 and isinstance(templates[0], str) else None
            expanded = [SOPExpansion(original, (), template)]
        for expansion_index, expansion in enumerate(expanded):
            mission = expansion.declaration
            sop_template = expansion.template
            expanded_id = task_id + (f'.{expansion_index + 1}' if len(expanded) > 1 else '')
            if validation_error is None:
                try:
                    validate_task_declaration(mission)
                except Exception as error:
                    validation_error = str(error)
            definitions = mission.get('actions', [])
            definitions = definitions if isinstance(definitions, list) else []
            inline = not definitions and ('action' in mission or 'type' in mission)
            if inline:
                definitions = [mission]
            actions = tuple(
                ActionSpec(
                    f'{expanded_id}.action-{action_index + 1}',
                    Source(config_path,
                           source_path + expansion.action_sources[action_index][0]
                           if action_index < len(expansion.action_sources)
                           else (source_path if inline else f'{source_path}.actions[{action_index}]'),
                           expansion.action_sources[action_index][1]
                           if action_index < len(expansion.action_sources) else None),
                    definition if isinstance(definition, dict) else {},
                )
                for action_index, definition in enumerate(definitions)
            )
            patterns = []
            if isinstance(mission.get('targets'), list):
                patterns.extend(pattern for pattern in mission['targets'] if isinstance(pattern, str) and pattern.strip())
            elif isinstance(mission.get('file'), str) and mission['file'].strip():
                patterns.append(mission['file'])
            original = declaration if isinstance(declaration, dict) else {}
            name = (original.get('name') or original.get('task') or mission.get('name')
                    or mission.get('task') or (actions[0].type if actions else expanded_id))
            source_ids = None
            raw_sids = mission.get('source_ids') if 'source_ids' in mission else original.get('source_ids')
            if isinstance(raw_sids, list):
                source_ids = tuple(s for s in raw_sids if isinstance(s, str) and s.strip())
            tasks.append(Task(expanded_id, name, Source(config_path, source_path, sop_template),
                              tuple(patterns), actions, validation_error=validation_error,
                              source_ids=source_ids))
    return tuple(tasks)

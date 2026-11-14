from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union, TYPE_CHECKING
from rule_framework.fom import FOMBase, INIFileFOM
from rule_framework.ast import parse_line, RuleNode, TypelessRuleNode
from rule_framework.rule_helpers import UNSET, validate_domain_selector
import inspect

if TYPE_CHECKING:
    from rule_framework.workspace import ManagedWorkspace


def _batch_insertions(entries, insert):
    from rule_framework.rule_helpers import _BatchInsert
    cursor = _BatchInsert(insert) if isinstance(insert, dict) else insert
    for entry in entries:
        if isinstance(cursor, _BatchInsert):
            cursor.begin_item()
        yield entry, cursor
        if isinstance(cursor, _BatchInsert):
            cursor.advance()


@dataclass
class ExecutionContext:
    fom: FOMBase
    fom_cache: dict = field(default_factory=dict)
    settings: dict = field(default_factory=dict)
    workspace: Optional["ManagedWorkspace"] = None

class Action:
    requires_completion_receipt = False

    def execute_managed(self, ctx):
        receipts = getattr(ctx.workspace, 'action_receipts', None)
        if receipts is None:
            return self.execute(ctx)
        return receipts.execute(self, ctx)

    def execute(self, ctx: ExecutionContext):
        raise NotImplementedError

@dataclass
class RemoveRuleAction(Action):
    match_type: Optional[str] = None
    match_value: Optional[str] = None
    conditions: Any = UNSET

    def execute(self, ctx: ExecutionContext):
        if self.match_type or self.match_value:
            if self.match_type == 'domain' and self.match_value is not None:
                validate_domain_selector(self.match_value)
            fields = {} if self.conditions is UNSET else {"conditions": self.conditions}
            ctx.fom.remove_rule(self.match_type, self.match_value, **fields)

@dataclass
class RemoveScriptAction(Action):
    script_name: Optional[str] = None
    pattern: Optional[str] = None
    script_path: Optional[str] = None

    def execute(self, ctx: ExecutionContext):
        ctx.fom.remove_script(name=self.script_name, pattern=self.pattern, script_path=self.script_path)

@dataclass
class AddRuleAction(Action):
    rules: List[Union[Dict, str]] = field(default_factory=list)
    insert: Optional[Dict] = None

    def execute(self, ctx: ExecutionContext):
        for r, insert in _batch_insertions(self.rules, self.insert):
            if isinstance(r, dict):
                unknown = set(r) - {'type', 'value', 'policy', 'conditions', 'options'}
                if unknown:
                    raise ValueError(f'Unsupported rule fields: {sorted(unknown)}')
                fields = {key: r[key] for key in ('policy', 'conditions', 'options') if key in r}
                ctx.fom.add_rule(r.get('type'), r.get('value'), insert=insert, **fields)
            elif isinstance(r, str):
                ctx.fom.add_native(r, kind='rule', insert=insert)

@dataclass
class AddNativeAction(Action):
    content: Any = None
    kind: Any = None
    insert: Any = None
    section: Any = None

    def execute(self, ctx: ExecutionContext):
        ctx.fom.add_native(self.content, kind=self.kind, insert=self.insert, section=self.section)

@dataclass
class ModifyAction(Action):
    requires_completion_receipt = True
    search: str = ""
    replace: str = ""
    is_regex: bool = False
    count: int = 0

    def execute(self, ctx: ExecutionContext):
        from rule_framework.text_json import validate_text_operation
        validate_text_operation(self.search, self.replace, self.is_regex, self.count)
        ctx.fom.modify(self.search, self.replace, is_regex=self.is_regex, count=self.count)

@dataclass
class JsonSetAction(Action):
    path: list = field(default_factory=list)
    value: Any = None

    def execute(self, ctx: ExecutionContext):
        operation = getattr(ctx.fom, 'json_set', None)
        if operation is None:
            raise ValueError(f"{type(ctx.fom).__name__} does not support json_set")
        operation(self.path, self.value)

@dataclass
class JsonRemoveAction(Action):
    requires_completion_receipt = True
    path: list = field(default_factory=list)

    def execute(self, ctx: ExecutionContext):
        operation = getattr(ctx.fom, 'json_remove', None)
        if operation is None:
            raise ValueError(f"{type(ctx.fom).__name__} does not support json_remove")
        operation(self.path)

@dataclass
class AddRewriteAction(Action):
    rewrites: List[Union[Dict, str]] = field(default_factory=list)
    mitm_hostnames: List[str] = field(default_factory=list)
    insert: Optional[Dict] = None

    def execute(self, ctx: ExecutionContext):
        if not isinstance(self.rewrites, list) or not isinstance(self.mitm_hostnames, list):
            raise ValueError('rewrites and mitm_hostnames must be lists')
        add_rewrite = getattr(ctx.fom, 'add_url_rewrite', ctx.fom.add_rewrite)
        if self.rewrites:
            for rw, insert in _batch_insertions(self.rewrites, self.insert):
                if isinstance(rw, dict):
                    if 'raw_content' in rw:
                        if set(rw) != {'raw_content'}:
                            raise ValueError('Native rewrite content and structured rewrite fields are separate inputs')
                        ctx.fom.add_native(rw['raw_content'], kind='rewrite', insert=insert)
                        continue
                    sig = inspect.signature(add_rewrite)
                    if 'url_pattern' in sig.parameters:
                        fields = dict(rw)
                        accepts_extra = any(parameter.kind == inspect.Parameter.VAR_KEYWORD
                                            for parameter in sig.parameters.values())
                        unsupported = set(fields) - set(sig.parameters)
                        if unsupported and not accepts_extra:
                            raise ValueError(f"Unsupported structured rewrite fields: {sorted(unsupported)}")
                        if 'insert' in fields:
                            raise ValueError('Rewrite insertion belongs in the Action insert field')
                        add_rewrite(**fields, insert=insert)
                    else:
                        raise ValueError(f'{type(ctx.fom).__name__} has no structured rewrite input')
                elif isinstance(rw, str):
                    ctx.fom.add_native(rw, kind='rewrite', insert=insert)
                else:
                    raise ValueError('Rewrite entries must be structured dictionaries or native strings')
        if self.mitm_hostnames:
            ctx.fom.add_mitm(self.mitm_hostnames)

@dataclass
class AddMitmAction(Action):
    hostnames: List[str] = field(default_factory=list)
    insert: Optional[Dict] = None

    def execute(self, ctx: ExecutionContext):
        ctx.fom.add_mitm(self.hostnames, insert=self.insert)

@dataclass
class RemoveRewriteAction(Action):
    url_pattern: str = ""

    def execute(self, ctx: ExecutionContext):
        if hasattr(ctx.fom, 'remove_rewrite'):
            ctx.fom.remove_rewrite(self.url_pattern)

@dataclass
class RemoveMitmAction(Action):
    hostnames: List[str] = field(default_factory=list)

    def execute(self, ctx: ExecutionContext):
        if hasattr(ctx.fom, 'remove_mitm'):
            ctx.fom.remove_mitm(self.hostnames)

@dataclass
class AddScriptAction(Action):
    scripts: List[Any] = field(default_factory=list)
    insert: Optional[Dict] = None

    def execute(self, ctx: ExecutionContext):
        if not isinstance(self.scripts, list):
            raise ValueError('scripts must be a list')
        for s, insert in _batch_insertions(self.scripts, self.insert):
            if isinstance(s, str):
                ctx.fom.add_native(s, kind='script', insert=insert)
            else:
                ctx.fom.add_script(s, insert=insert)

@dataclass
class CustomHookAction(Action):
    script: Optional[str] = None
    function: Optional[str] = None

    def execute(self, ctx: ExecutionContext):
        from rule_framework.hook_runtime import execute_hook
        execute_hook(ctx, self.script, self.function)

@dataclass
class ResourceAction(Action):
    definition: Dict = field(default_factory=dict)

    def execute(self, ctx: ExecutionContext):
        from rule_framework.resources import execute_resource_action
        execute_resource_action(ctx, self.definition)


@dataclass
class MergeRulesAction(Action):
    definition: Dict = field(default_factory=dict)

    def execute(self, ctx: ExecutionContext):
        from rule_framework.routing_conversion import execute_merge
        execute_merge(ctx, self.definition)


@dataclass
class MergeModulesAction(Action):
    definition: Dict = field(default_factory=dict)

    def execute(self, ctx: ExecutionContext):
        from rule_framework.module_conversion import execute_merge
        execute_merge(ctx, self.definition)


ACTION_REGISTRY = {
    'merge_modules': lambda d: MergeModulesAction(definition=d),
    'add_native': lambda d: AddNativeAction(content=d.get('content'), kind=d.get('kind'), insert=d.get('insert'), section=d.get('section')),
    'merge_rules': lambda d: MergeRulesAction(definition=d),
    'json_remove': lambda d: JsonRemoveAction(path=d['path']),
    'json_set': lambda d: JsonSetAction(path=d['path'], value=d['value']),

    'create_resource': lambda d: ResourceAction(definition=d),
    'replace_resource': lambda d: ResourceAction(definition=d),
    'copy_resource': lambda d: ResourceAction(definition=d),
    'remove_rule': lambda d: RemoveRuleAction(match_type=d.get('match', {}).get('type') if isinstance(d.get('match'), dict) else None, match_value=d.get('match', {}).get('value') if isinstance(d.get('match'), dict) else None, conditions=d.get('match', {}).get('conditions', UNSET) if isinstance(d.get('match'), dict) else UNSET),
    'remove_script': lambda d: RemoveScriptAction(script_name=d.get('name') or d.get('match', {}).get('name'), pattern=d.get('pattern') or d.get('match', {}).get('pattern'), script_path=d.get('script_path') or d.get('match', {}).get('script_path')),
    'add_rule': lambda d: AddRuleAction(rules=d.get('rules', []), insert=d.get('insert')),
    'modify': lambda d: ModifyAction(search=d.get('search', ''), replace=d.get('replace', ''), is_regex=d.get('is_regex', False), count=d.get('count', 0)),
    'add_rewrite': lambda d: AddRewriteAction(rewrites=d.get('rewrites', []), mitm_hostnames=d.get('mitm_hostnames', []), insert=d.get('insert')),
    'add_mitm': lambda d: AddMitmAction(hostnames=d.get('hostnames', []), insert=d.get('insert')),
    'remove_rewrite': lambda d: RemoveRewriteAction(url_pattern=d.get('url_pattern') or d.get('match', {}).get('url_pattern')),
    'remove_mitm': lambda d: RemoveMitmAction(hostnames=d.get('hostnames', [])),
    'add_script': lambda d: AddScriptAction(scripts=d.get('scripts', []), insert=d.get('insert')),
    'custom_hook': lambda d: CustomHookAction(script=d.get('script'), function=d.get('function'))
}

def parse_action(action_def: dict) -> Action:
    action_type = action_def.get('action') or action_def.get('type')
    if not action_type or action_type not in ACTION_REGISTRY:
        return None
    action = ACTION_REGISTRY[action_type](action_def)
    action._declaration = action_def
    return action

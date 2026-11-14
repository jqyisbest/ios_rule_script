"""Ordered Task transactions with observable provenance and rollback results."""

import glob
import logging
import os
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from typing import Any

from rule_framework.executor import ActionExecutor
from rule_framework.tasks import ActionResult, Target, TaskResult
from rule_framework.workspace import ManagedWorkspace

logger = logging.getLogger('RuleFramework')
_context = ContextVar('rule_framework_task_provenance', default={})


class ProvenanceFilter(logging.Filter):
    def filter(self, record):
        context = _context.get()
        record.provenance = ('[' + ' '.join(f'{key}={value!r}' if ' ' in str(value) else f'{key}={value}'
                                         for key, value in context.items()) + '] ') if context else ''
        return True


@contextmanager
def task_logging(*, task=None, action=None, target=None, tasks=()):
    context = {}
    if task is not None:
        context.update(task=task.id, name=task.name)
        source = action.source if action is not None else task.source
        context['source'] = f'{source.config_path}:{source.path}' if source.config_path else source.path
        if source.sop_template:
            context['sop'] = source.sop_template
    elif tasks:
        context['tasks'] = ','.join(task.id for task in tasks)
    if action is not None:
        context.update(action=action.id, kind=action.type)
    if target is not None:
        context.update(target=target.path, client=target.client)
    token = _context.set(context)
    try:
        yield
    finally:
        _context.reset(token)


@dataclass
class TaskExecution:
    task_results: tuple[TaskResult, ...]
    fom_cache: dict = field(default_factory=dict)
    file_tasks: dict = field(default_factory=dict)
    error_count: int = 0
    skip_count: int = 0
    workspace: ManagedWorkspace = None


def _lookup_owner(path, workspace, ownership_map):
    if not ownership_map:
        return None
    owner = ownership_map.get(path)
    if owner is not None:
        return owner
    if workspace and workspace.base_dir:
        abs_p = os.path.normpath(workspace.resolve_path(path)).replace('\\', '/')
        owner = ownership_map.get(abs_p)
        if owner is not None:
            return owner
        try:
            rel = os.path.relpath(abs_p, workspace.base_dir).replace('\\', '/')
            owner = ownership_map.get(rel)
            if owner is not None:
                return owner
        except ValueError:
            pass
    norm_path = os.path.normcase(path).replace('\\', '/')
    norm_rel = None
    if workspace and workspace.base_dir:
        try:
            abs_p = os.path.normpath(workspace.resolve_path(path)).replace('\\', '/')
            norm_rel = os.path.normcase(os.path.relpath(abs_p, workspace.base_dir).replace('\\', '/'))
        except ValueError:
            pass
    for key, val in ownership_map.items():
        norm_key = os.path.normcase(key).replace('\\', '/')
        if norm_key == norm_path or (norm_rel is not None and norm_key == norm_rel):
            return val
    if workspace and workspace.base_dir:
        physical_path = os.path.normcase(os.path.realpath(workspace.resolve_path(path)))
        for key, val in ownership_map.items():
            if os.path.normcase(os.path.realpath(workspace.resolve_path(key))) == physical_path:
                return val
    return None



def _resolve_targets(task, workspace, ownership_map=None):
    if not task.patterns:
        logger.warning("Mission is missing 'file' or 'targets' field, skipping.")
        return (), "Missing 'file' or 'targets' field"
    matches = {}
    physical_targets = {}
    removal_actions = {'remove_rule', 'remove_rewrite', 'remove_script', 'remove_mitm', 'json_remove'}
    removal_only = bool(task.actions) and all(
        isinstance(action.type, str) and action.type in removal_actions
        for action in task.actions
    )
    for pattern in task.patterns:
        absolute_pattern = workspace.resolve_path(pattern)
        matched = workspace.glob(pattern)
        if not matched and not glob.has_magic(absolute_pattern):
            if removal_only:
                continue
            matched = [absolute_pattern]
        for path in matched:
            normalized = os.path.normpath(path).replace('\\', '/')
            identity = os.path.normcase(os.path.realpath(path))
            normalized = physical_targets.setdefault(identity, normalized)
            origins = matches.setdefault(normalized, [])
            if pattern not in origins:
                origins.append(pattern)
    if task.source_ids is not None:
        filtered_matches = {}
        for path, origins in matches.items():
            owner = _lookup_owner(path, workspace, ownership_map)
            if owner in task.source_ids:
                filtered_matches[path] = origins
        matches = filtered_matches

    if not matches:
        return (), 'No files matched patterns'
    targets = tuple(Target(path, tuple(patterns), base_dir=workspace.base_dir) for path, patterns in matches.items())
    logger.info('\n'.join([
        f"Task '{task.name}' Target Resolution Summary:",
        f'- Total Matched: {len(targets)} files',
        f'- Resolved Targets: {len(targets)} files',
    ]))
    return targets, None


def _is_canonical_stock_remove_asn(action):
    if action is None or getattr(action, 'type', None) != 'remove_rule':
        return False
    definition = getattr(action, 'definition', None)
    if not isinstance(definition, dict):
        return False
    action_type = definition.get('action') or definition.get('type')
    if action_type != 'remove_rule':
        return False
    match = definition.get('match')
    if not isinstance(match, dict) or match.get('type') != 'asn':
        return False
    if not set(match.keys()) <= {'type', 'value'}:
        return False
    if 'value' in match:
        val = match['value']
        if val is not None and not (isinstance(val, (str, int)) and not isinstance(val, bool)):
            return False
    if not set(definition.keys()) <= {'action', 'type', 'match', 'name', 'source'}:
        return False
    return True


def _is_stock_local_removal(action):
    if action is None or getattr(action, 'type', None) != 'remove_rule':
        return False
    definition = getattr(action, 'definition', None)
    if type(definition) is not dict or type(definition.get('match')) is not dict:
        return False
    if _is_canonical_stock_remove_asn(action):
        return True
    match = definition['match']
    return (match.get('type') == 'domain' and set(match) <= {'type', 'value'}
            and (match.get('value') is None or type(match['value']) is str)
            and set(definition) <= {'action', 'type', 'match', 'name', 'source'})


def _is_immutable_settings(settings):
    from rule_framework.state_spool import _immutable
    if type(settings) is not dict:
        return False
    return all(type(k) is str and _immutable(v) for k, v in settings.items())


from rule_framework.mihomo_formats import _PristineBaseline, _capture_pristine_baseline



def _is_proven_pristine_noop(fom, baseline, workspace, action):
    if baseline is None:
        return False
    from rule_framework.state_spool import _is_stock_yaml_parser
    if not _is_stock_yaml_parser(fom):
        return False
    if getattr(fom, 'is_dirty', True):
        return False
    path = workspace.fom_cache._path(fom.filepath)
    if path in workspace._escaped_paths:
        return False
    if not _stream_formats._matches_pristine_yaml_state(
            fom, baseline, getattr(action, 'definition', None), _is_immutable_settings):
        return False
    from rule_framework.state_spool import _has_stock_methods
    if not _has_stock_methods(type(fom)):
        return False
    if not getattr(fom, '_source_exists', False):
        return False
    return True

# Local ASN/domain removals stream only through a stock, initially empty workspace.
from rule_framework.fom import ClashYamlFile as _StreamYaml, ClashClassicalListFile as _StreamList
from rule_framework.state_spool import StateSpool as _StreamSpool, _has_stock_methods
from rule_framework import mihomo_formats as _stream_formats

_STREAM_METHOD_NAMES = ('__init__', 'scaffold', 'load', '_load_bytes', 'remove_rule', 'validate',
                        'validate_complete', 'render_bytes', 'update_metadata', '_sync_managed_state')
_STREAM_METHODS = tuple((cls, name, getattr(cls, name, None))
                        for cls in (_StreamYaml, _StreamList) for name in _STREAM_METHOD_NAMES)
_STREAM_HELPERS = tuple((name, getattr(_stream_formats, name)) for name in
                       ('provider_behavior', 'parse_mihomo_entry', 'validate_mihomo_node',
                        '_capture_pristine_baseline', '_matches_pristine_yaml_state'))
_STREAM_STORE = _StreamSpool.store
_STREAM_LOG_EMIT = logging.FileHandler.emit
_STREAM_NODE_INIT = _stream_formats.MihomoRuleNode.__init__
_STREAM_NAMESPACES = tuple((cls, tuple(vars(cls).items())) for cls in dict.fromkeys(
    base for model in (_StreamYaml, _StreamList, _stream_formats.MihomoRuleNode) for base in model.__mro__))
from rule_framework import ast as _stream_ast, actions as _stream_actions, executor as _stream_executor
from rule_framework import rule_helpers as _stream_rule_helpers, value_semantics as _stream_values
from rule_framework import fom as _stream_fom, client_paths as _stream_clients
_STREAM_FUNCTIONS = tuple((module, name, value) for module in (
    _stream_formats, _stream_ast, _stream_actions, _stream_executor, _stream_rule_helpers, _stream_values,
    _stream_fom, _stream_clients)
    for name, value in vars(module).items()
    if hasattr(value, '__code__') and str(getattr(value, '__module__', '')).startswith('rule_framework'))


def _can_stream_native_task(result, workspace, settings):
    import threading
    from pathlib import Path
    from rule_framework.main import _owns_native_load
    if (len(result.task.actions) != 1 or not _is_stock_local_removal(result.task.actions[0])
            or workspace.fom_cache._files or workspace._escaped_paths
            or workspace._owned_loader is not _owns_native_load
            or not _is_immutable_settings(settings) or not _has_stock_methods(_StreamYaml)
            or threading.active_count() != 1 or type(logger) is not logging.Logger
            or logger.filters or logger.propagate or logging.getLogRecordFactory() is not logging.LogRecord
            or logging.FileHandler.emit is not _STREAM_LOG_EMIT or _StreamSpool.store is not _STREAM_STORE):
        return False
    framework = Path(__file__).resolve().parent
    for cls, namespace in _STREAM_NAMESPACES:
        current = vars(cls)
        if set(current) != {name for name, _ in namespace}:
            return False
        for name, member in namespace:
            if current[name] is not member:
                return False
            functions = ((member.fget, member.fset, member.fdel) if isinstance(member, property)
                         else (member.__func__,) if isinstance(member, (staticmethod, classmethod)) else (member,))
            for function in functions:
                code = getattr(function, '__code__', None)
                if code is not None and code.co_filename != '<string>' and Path(code.co_filename).resolve().parent != framework:
                    return False
    for cls, name, implementation in _STREAM_METHODS:
        if getattr(cls, name, None) is not implementation:
            return False
        code = getattr(implementation, '__code__', None)
        if code is not None and Path(code.co_filename).resolve().parent != framework:
            return False
    if any(getattr(_stream_formats, name) is not implementation for name, implementation in _STREAM_HELPERS):
        return False
    for module, name, implementation in _STREAM_FUNCTIONS:
        if (getattr(module, name, None) is not implementation
                or Path(implementation.__code__.co_filename).resolve().parent != framework):
            return False
    if (_stream_formats.MihomoRuleNode.__init__ is not _STREAM_NODE_INIT
            or Path(_STREAM_NODE_INIT.__code__.co_filename).resolve().parent != framework
            or Path(_STREAM_LOG_EMIT.__code__.co_filename).resolve() != Path(logging.__file__).resolve()):
        return False
    if any(type(handler) is not logging.FileHandler
           or any(type(f) is not ProvenanceFilter for f in handler.filters)
           or type(handler.formatter) is not logging.Formatter for handler in logger.handlers):
        return False
    return all(target.client.lower() == 'mihomo' and os.path.splitext(target.path)[1].lower()
               in ('.yaml', '.yml', '.list') and _owns_native_load(target.path)
               for target in result.task.targets)


class _DeferredNativeLogs(logging.Handler):
    """Two file-backed log phases keep preloading ahead of all action messages."""

    def __init__(self):
        super().__init__()
        import tempfile
        self.streams = {name: tempfile.TemporaryFile() for name in ('preload', 'action')}
        self.phase = 'preload'
        self.handlers = None

    def __enter__(self):
        self.handlers = logger.handlers
        logger.handlers = [self]
        return self

    def emit(self, record):
        import pickle
        fields = dict(record.__dict__)
        fields.update(msg=record.getMessage(), args=None, exc_info=None, exc_text=None)
        pickle.dump((fields, dict(_context.get())), self.streams[self.phase], protocol=pickle.HIGHEST_PROTOCOL)

    def replay(self, phase):
        import pickle
        stream = self.streams[phase]
        stream.flush()
        stream.seek(0)
        while True:
            try:
                fields, context = pickle.load(stream)
            except EOFError:
                break
            record = logging.makeLogRecord(fields)
            token = _context.set(context)
            try:
                for handler in self.handlers:
                    if record.levelno >= handler.level:
                        handler.handle(record)
            finally:
                _context.reset(token)

    def __exit__(self, *_):
        logger.handlers = self.handlers
        for stream in self.streams.values():
            stream.close()
        super().close()


def _execute_scoped_action(workspace, fom, action, executor):
    from contextlib import nullcontext
    receipts = workspace.action_receipts
    scope = (receipts.action_scope(workspace.current_task, action, fom.filepath)
             if receipts is not None else nullcontext())
    with scope, workspace._action_scope(action.type, fom):
        executor.execute_action(action.definition)
    workspace._validate_task()


def _stream_single_native_task(result, execution, workspace, snapshot, settings):
    if not _can_stream_native_task(result, workspace, settings):
        return False
    from rule_framework.state_spool import SpilledFOM, StateSpool
    from rule_framework.workspace import MissingSourceInputError
    action = result.task.actions[0]
    pending, available = [], []
    action_failure = None
    with _DeferredNativeLogs() as logs:
        for target in result.task.targets:
            fom = executor = baseline = None
            with task_logging(task=result.task, action=action, target=target):
                logs.phase = 'preload'
                try:
                    fom = workspace._get_owned_fom(target.path)
                    available.append((target, type(fom).__name__))
                    logger.info(f'Processing {target.path} with {type(fom).__name__}...')
                except MissingSourceInputError as error:
                    result.status, result.reason = 'skipped', f'Required source input is missing: {error.path}'
                    execution.skip_count += 1
                    with task_logging(task=result.task):
                        logger.warning(f"Task '{result.task.name}' skipped: required source input is missing: {error.path}")
                    workspace.restore(snapshot)
                    logs.replay('preload')
                    return True
                except Exception as error:
                    result.status, result.reason = 'failed', str(error)
                    result.action_results.append(ActionResult(action, target, 'failed', str(error)))
                    execution.error_count += 1
                    logger.error(f'Error processing {target.path}: {error}')
                    workspace.restore(snapshot)
                    logs.replay('preload')
                    return True
                if action_failure is not None:
                    # Original preloading examines every target before the first action failure.
                    try:
                        workspace._spill_owned_fom(target.path)
                    except Exception as error:
                        result.status, result.reason = 'failed', str(error)
                        result.action_results.append(ActionResult(action, target, 'failed', str(error)))
                        execution.error_count += 1
                        logger.error(f'Error processing {target.path}: {error}')
                        workspace.restore(snapshot)
                        logs.replay('preload')
                        return True
                    fom = None
                    continue
                logs.phase = 'action'
                try:
                    baseline = _capture_pristine_baseline(fom) if type(fom) is _StreamYaml else None
                    logger.info(f'Executing {action.type}')
                    executor = ActionExecutor(fom, fom_cache=workspace.fom_cache, settings=settings, workspace=workspace)
                    _execute_scoped_action(workspace, fom, action, executor)
                    pristine = baseline is not None and _is_proven_pristine_noop(fom, baseline, workspace, action)
                    workspace._spill_owned_fom(target.path)
                    backing = workspace._backing_fom(workspace.fom_cache._path(target.path))
                    if pristine and isinstance(backing, SpilledFOM):
                        byte_path = workspace._state_spool.write_render_cache(fom._raw_bytes)
                        backing.mark_closed_pristine(byte_path, fom.settings)
                    pending.append(ActionResult(action, target, 'success', fom_type=type(fom).__name__))
                    logger.info('Action completed')
                except Exception as error:
                    reason = str(error)
                    pending.append(ActionResult(action, target, 'failed', reason, type(fom).__name__ if fom is not None else None))
                    action_failure = reason
                    logger.error(f'Error processing {target.path}: {error}')
                    logger.info('Restored managed working state to Task start')
                finally:
                    executor = fom = baseline = None
                    logs.phase = 'preload'
        logs.replay('preload')
        logs.replay('action')
    result.action_results.extend(pending)
    if action_failure is not None:
        result.status, result.reason = 'failed', action_failure
        execution.error_count += 1
        for target, model_type in available[len(pending):]:
            result.action_results.append(ActionResult(action, target, 'skipped', 'Task stopped after an action failed', model_type))
        workspace.restore(snapshot)
        return True
    final_target = available[-1][0] if available else None
    _complete_task(result, execution, workspace, snapshot, action, final_target)
    return True


def _complete_task(result, execution, workspace, snapshot, action, target):
    """Validate and record one Task's final state across execution modes."""
    with task_logging(task=result.task, action=action, target=target):
        try:
            workspace._validate_task(complete=True)
        except Exception as error:
            result.status, result.reason = 'failed', str(error)
            workspace.restore(snapshot)
            execution.error_count += 1
            if result.action_results:
                last = result.action_results[-1]
                result.action_results[-1] = ActionResult(last.action, last.target, 'failed', str(error), last.fom_type)
            logger.error(f'Task completion validation failed: {error}')
            logger.info('Restored managed working state to Task start')
            return
    result.status = 'success'
    for path in workspace.paths():
        if path in workspace.touched_paths():
            execution.file_tasks.setdefault(path, []).append(result.task)


def execute_tasks(tasks, *, settings, load_fom, _owned_loader=None, staged_foms=None,
                  missing_source_targets=None, missing_source_directories=None, ownership_map=None,
                  source_context=None, _state_spool=None, action_receipts=None):
    """Apply ordered Task transactions to a shared, staged working state."""
    from rule_framework.workspace import (MissingSourceInputError, _matches_glob,
                                          _directory_intersects_pattern, _physical_glob_patterns)
    from rule_framework.state_spool import SpilledFOM, StateSpool, _StagedFOMMap, _has_stock_methods
    if source_context is not None:
        if staged_foms is None:
            staged_foms = source_context.staged_foms
        if missing_source_targets is None:
            missing_source_targets = source_context.missing_source_targets
        if missing_source_directories is None:
            missing_source_directories = source_context.missing_source_directories
        if ownership_map is None:
            ownership_map = source_context.ownership_map

    internal_staged = isinstance(staged_foms, _StagedFOMMap)
    if _state_spool is None and internal_staged:
        _state_spool = staged_foms._spool

    missing_source_targets = set(missing_source_targets) if missing_source_targets is not None else ()
    missing_source_directories = set(missing_source_directories) if missing_source_directories is not None else ()

    workspace = ManagedWorkspace(base_dir=settings.get('base_dir', os.getcwd()), load_fom=load_fom,
                                 settings=settings, _owned_loader=_owned_loader,
                                 missing_source_targets=missing_source_targets,
                                 missing_source_directories=missing_source_directories,
                                 _state_spool=_state_spool)
    if staged_foms:
        raw_items = (staged_foms._raw_entries().items()
                     if internal_staged
                     else staged_foms.items())
        for path, fom in raw_items:
            if internal_staged and isinstance(fom, SpilledFOM):
                is_owned = _owned_loader is not None and _owned_loader(path)
                exposed = not is_owned
                if path in staged_foms._exposed:
                    exposed = True
                workspace._register_fom(path, fom, expose=exposed)
                continue
            if '_metadata_origin' not in fom.__dict__ and (
                callable(getattr(fom, 'update_metadata', None)) or callable(getattr(fom, '_apply_metadata', None))
            ):
                fom._metadata_origin = getattr(fom, '_raw_bytes', getattr(fom, '_metadata_baseline', None))
            workspace.register_fom(path, fom)
        if internal_staged:
            staged_foms._bind_workspace(workspace)
    execution = TaskExecution(tuple(TaskResult(task) for task in tasks),
                              fom_cache=workspace.fom_cache, workspace=workspace)
    from rule_framework.source_admission import SourceAdmission
    admissions = SourceAdmission(source_context, workspace)
    workspace.source_admission = admissions
    workspace.action_receipts = action_receipts
    for result in execution.task_results:
        workspace.current_task = result.task
        with admissions.task(result, lambda task: _resolve_targets(task, workspace, ownership_map=ownership_map)):
            # Release the previous rollback state before building a new snapshot.
            snapshot = None
            if result.task.validation_error:
                result.status, result.reason = 'failed', result.task.validation_error
                execution.error_count += 1
                with task_logging(task=result.task):
                    clients = ','.join(dict.fromkeys(Target(pattern, (pattern,), base_dir=workspace.base_dir).client
                                                     for pattern in result.task.patterns)) or 'unknown'
                    logger.error(f'Task declaration failed: client={clients}; {result.reason}')
                continue
            with workspace._task_transaction() as snapshot:
                workspace.reset_touched_paths()
                with task_logging(task=result.task):
                    targets, skip_reason = _resolve_targets(result.task, workspace, ownership_map=ownership_map)
                result.task = replace(result.task, targets=targets)
                if skip_reason and not result.task.patterns:
                    result.status, result.reason = 'skipped', skip_reason
                    execution.skip_count += 1
                    continue
                if missing_source_targets or workspace.missing_source_directories:
                    missing_input = next(
                        (t.path for t in targets
                         if workspace.is_missing_source_input(t.path)),
                        None
                    )
                    if not missing_input:
                        physical_patterns = {
                            pattern: _physical_glob_patterns(workspace.resolve_path(pattern))
                            for pattern in result.task.patterns
                        }
                        for mst in sorted(missing_source_targets):
                            mst_owner = _lookup_owner(mst, workspace, ownership_map)
                            if result.task.source_ids is not None and mst_owner not in result.task.source_ids:
                                continue
                            mst_abs = workspace.resolve_path(mst)
                            mst_rel = os.path.relpath(mst_abs, workspace.base_dir).replace('\\', '/')
                            mst_physical = os.path.realpath(mst_abs)
                            for pattern in result.task.patterns:
                                abs_pattern = workspace.resolve_path(pattern)
                                if (_matches_glob(mst_abs, abs_pattern) or _matches_glob(mst_rel, pattern)
                                        or any(_matches_glob(mst_physical, physical_pattern)
                                               for physical_pattern in physical_patterns[pattern])
                                        or os.path.normcase(mst_abs) == os.path.normcase(abs_pattern)
                                        or os.path.normcase(mst_rel) == os.path.normcase(pattern)):
                                    if workspace.is_missing_source_input(mst):
                                        missing_input = mst
                                        break
                            if missing_input:
                                break

                    if not missing_input and workspace.missing_source_directories:
                        for pattern in result.task.patterns:
                            for m_dir in sorted(workspace.missing_source_directories):
                                dir_owner = _lookup_owner(m_dir, workspace, ownership_map)
                                if result.task.source_ids is not None and dir_owner not in result.task.source_ids:
                                    continue
                                if any(_directory_intersects_pattern(m_dir, physical_pattern,
                                                                     base_dir=workspace.base_dir)
                                       for physical_pattern in physical_patterns[pattern]):
                                    norm_dir_abs = os.path.realpath(workspace.resolve_path(m_dir)).replace('\\', '/')
                                    norm_dir_key = os.path.normcase(norm_dir_abs).replace('\\', '/')
                                    has_matching_target_under_dir = any(
                                        os.path.normcase(os.path.realpath(t.path)).replace('\\', '/').startswith(norm_dir_key.rstrip('/') + '/')
                                        and (pattern in t.patterns or _matches_glob(t.path, workspace.resolve_path(pattern)))
                                        for t in targets
                                        if not workspace.is_missing_source_input(t.path)
                                    )
                                    if not has_matching_target_under_dir:
                                        missing_input = pattern
                                        break
                            if missing_input:
                                break

                    if missing_input:
                        first_action = result.task.actions[0] if result.task.actions else None
                        is_initial_creation = first_action is not None and first_action.type == 'create_resource'
                        if not is_initial_creation:
                            result.status, result.reason = 'skipped', f'Required source input is missing: {missing_input}'
                            execution.skip_count += 1
                            with task_logging(task=result.task):
                                logger.warning(f"Task '{result.task.name}' skipped: required source input is missing: {missing_input}")
                            continue
                if skip_reason:
                    with task_logging(task=result.task):
                        logger.warning(f'No files matched patterns, skipping: {list(result.task.patterns)}')
                    result.status, result.reason = 'skipped', skip_reason
                    execution.skip_count += 1
                    continue
                if _stream_single_native_task(result, execution, workspace, snapshot, settings):
                    continue
                available = []


                for target in targets:
                    first_action = result.task.actions[0] if result.task.actions else None
                    with task_logging(task=result.task, action=first_action, target=target):
                        try:
                            factory = None
                            if first_action and first_action.type in {'create_resource', 'copy_resource', 'replace_resource'}:
                                from rule_framework.resources import BinaryResourceFOM
                                factory = BinaryResourceFOM
                            if any(action.type == 'merge_rules' for action in result.task.actions):
                                from rule_framework.routing_conversion import task_target_factory
                                declared_factory = task_target_factory(result.task.actions, workspace)
                                if factory is not None and declared_factory is not None:
                                    raise ValueError('Task declares conflicting resource and routing file purposes')
                                factory = declared_factory or factory
                            if any(action.type == 'merge_modules' for action in result.task.actions):
                                from rule_framework.module_conversion import task_target_factory as module_target_factory
                                declared_module_factory = module_target_factory(result.task.actions, workspace)
                                if factory is not None and declared_module_factory is not None:
                                    raise ValueError('Task declares conflicting managed file purposes')
                                factory = declared_module_factory or factory
                            fom = workspace._get_owned_fom(target.path, factory=factory)
                            if any(action.type == 'merge_rules' for action in result.task.actions):
                                from rule_framework.routing_conversion import prepare_declared_target
                                prepare_declared_target(fom, result.task.actions)
                            if any(action.type == 'merge_modules' for action in result.task.actions):
                                from rule_framework.module_conversion import prepare_declared_target as prepare_module_target
                                prepare_module_target(fom, result.task.actions)
                            available.append((target, type(fom).__name__))
                            logger.info(f'Processing {target.path} with {type(fom).__name__}...')
                            workspace._spill_owned_fom(target.path)
                            fom = None
                        except MissingSourceInputError as error:
                            result.status, result.reason = 'skipped', f'Required source input is missing: {error.path}'
                            execution.skip_count += 1
                            with task_logging(task=result.task):
                                logger.warning(f"Task '{result.task.name}' skipped: required source input is missing: {error.path}")
                            workspace.restore(snapshot)
                            break
                        except Exception as error:
                            result.status, result.reason = 'failed', str(error)
                            if first_action is not None:
                                result.action_results.append(ActionResult(first_action, target, 'failed', str(error)))
                            logger.error(f'Error processing {target.path}: {error}')
                            workspace.restore(snapshot)
                            execution.error_count += 1
                            break
                if result.status in ('failed', 'skipped'):
                    continue
                pairs = [(action, target) for action in result.task.actions for target, _ in available]
                for index, (action, target) in enumerate(pairs):
                    fom = None
                    executor = None
                    baseline = None
                    initial_entry = None
                    with task_logging(task=result.task, action=action, target=target):
                        try:
                            target_key = workspace.fom_cache._path(target.path)
                            initial_entry = workspace._backing_fom(target_key)
                            is_candidate = (
                                isinstance(initial_entry, SpilledFOM)
                                and target_key not in workspace._escaped_paths
                                and workspace._owned_loader is not None
                                and workspace._owned_loader(target_key)
                                and _is_stock_local_removal(action)
                                and _is_immutable_settings(settings)
                                and _has_stock_methods(initial_entry.model_type)
                            )
                            fom = workspace._get_owned_fom(target.path)
                            baseline = _capture_pristine_baseline(fom) if is_candidate else None
                            logger.info(f'Executing {action.type}')
                            executor = ActionExecutor(fom, fom_cache=workspace.fom_cache, settings=settings, workspace=workspace)
                            _execute_scoped_action(workspace, fom, action, executor)
                            if (is_candidate and baseline is not None
                                    and _is_proven_pristine_noop(fom, baseline, workspace, action)):
                                if workspace._state_spool is None:
                                    workspace._state_spool = StateSpool()
                                byte_path = workspace._state_spool.write_render_cache(fom._raw_bytes)
                                initial_entry.mark_closed_pristine(byte_path, fom.settings)
                                workspace._reuse_backing(target_key, initial_entry, fom)
                            else:
                                workspace._spill_owned_fom(target.path)
                            result.action_results.append(ActionResult(action, target, 'success', fom_type=type(fom).__name__))
                            logger.info('Action completed')
                        except MissingSourceInputError as error:
                            result.status, result.reason = 'skipped', f'Required source input is missing: {error.path}'
                            execution.skip_count += 1
                            with task_logging(task=result.task):
                                logger.warning(f"Task '{result.task.name}' skipped: required source input is missing: {error.path}")
                            workspace.restore(snapshot)
                            logger.info('Restored managed working state to Task start')
                            break
                        except Exception as error:
                            reason = str(error)
                            result.action_results.append(ActionResult(action, target, 'failed', reason,
                                                                      type(fom).__name__ if fom is not None else None))
                            result.status, result.reason = 'failed', reason
                            logger.error(f'Error processing {target.path}: {error}')
                            workspace.restore(snapshot)
                            logger.info('Restored managed working state to Task start')
                            execution.error_count += 1
                            for pending_action, pending_target in pairs[index + 1:]:
                                pending_fom_type = workspace._cached_fom_type(pending_target.path)
                                result.action_results.append(ActionResult(
                                    pending_action, pending_target, 'skipped',
                                    'Task stopped after an action failed',
                                    pending_fom_type,
                                ))
                            break
                        finally:
                            # Native models and proof state can now leave memory between Targets.
                            executor = None
                            fom = None
                            baseline = None
                            initial_entry = None
                pairs = None
                if result.status == 'pending':
                    final_action = result.task.actions[-1] if result.task.actions else None
                    final_target = available[-1][0] if available else None
                    _complete_task(result, execution, workspace, snapshot, final_action, final_target)
    return execution


def log_task_results(execution):
    for result in execution.task_results:
        with task_logging(task=result.task):
            clients = sorted({target.client for target in result.task.targets} or
                             {Target(pattern, (), base_dir=execution.workspace.base_dir).client for pattern in result.task.patterns} or {'unknown'})
            logger.info(f'Task Result: {result.status}; clients={",".join(clients)}'
                        + (f'; reason={result.reason}' if result.reason else ''))
    counts = {status: sum(result.status == status for result in execution.task_results)
              for status in ('success', 'failed', 'skipped')}
    logger.info(f"Task Results: success={counts['success']}, failed={counts['failed']}, skipped={counts['skipped']}")

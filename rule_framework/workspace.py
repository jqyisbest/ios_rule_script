"""Staged managed files shared by ordered Task transactions and Hooks."""

import os
import glob
from fnmatch import fnmatchcase
from functools import lru_cache
from dataclasses import dataclass, field
from contextlib import contextmanager
from collections.abc import MutableMapping
from copy import deepcopy
import pickle
from typing import Optional

from rule_framework.fom import FOMBase
from rule_framework.state_spool import SpilledFOM, StateSpool


def _native_model(fom):
    from rule_framework import fom as models
    from rule_framework.surge import SurgeFile
    from rule_framework.loon import LoonFile
    from rule_framework.shadowrocket import ShadowrocketFile
    native_types = {value for value in vars(models).values()
                    if isinstance(value, type) and issubclass(value, FOMBase)
                    and value.__module__ == models.__name__}
    native_types.update((SurgeFile, LoonFile, ShadowrocketFile))
    return type(fom) in native_types


def _matches_glob(path, pattern):
    parts = os.path.normcase(path).replace('\\', '/').split('/')
    patterns = os.path.normcase(pattern).replace('\\', '/').split('/')

    @lru_cache(None)
    def match(part_index, pattern_index):
        if pattern_index == len(patterns):
            return part_index == len(parts)
        segment = patterns[pattern_index]
        if segment == '**':
            return match(part_index, pattern_index + 1) or (
                part_index < len(parts) and not parts[part_index].startswith('.')
                and match(part_index + 1, pattern_index)
            )
        return (part_index < len(parts)
                and (not parts[part_index].startswith('.') or segment.startswith('.'))
                and fnmatchcase(parts[part_index], segment)
                and match(part_index + 1, pattern_index + 1))

    return match(0, 0)


def _physical_glob_patterns(pattern):
    """Resolve existing directory aliases while retaining unmatched suffixes."""
    physical_pattern = os.path.realpath(pattern)
    patterns = {physical_pattern}
    directory, filename = os.path.split(physical_pattern)
    suffix = [filename]
    while directory:
        parent, segment = os.path.split(directory)
        if glob.has_magic(segment):
            for matched in glob.iglob(directory, recursive=True):
                if os.path.isdir(matched):
                    expanded = os.path.normpath(os.path.join(matched, *suffix))
                    physical = os.path.realpath(expanded)
                    if os.path.normcase(physical) != os.path.normcase(expanded):
                        patterns.add(physical)
        if parent == directory:
            break
        suffix.insert(0, segment)
        directory = parent
    return tuple(sorted(patterns))


def _directory_intersects_pattern(dir_path: str, pattern: str, *, base_dir: Optional[str] = None) -> bool:
    """Return True if pattern may match file entries located beneath dir_path."""
    if base_dir:
        abs_base = os.path.realpath(base_dir)
        d_abs = os.path.realpath(os.path.join(abs_base, dir_path) if not os.path.isabs(dir_path) else dir_path).replace('\\', '/')
        p_abs = os.path.realpath(os.path.join(abs_base, pattern) if not os.path.isabs(pattern) else pattern).replace('\\', '/')
        try:
            d_rel = os.path.relpath(d_abs, abs_base).replace('\\', '/')
        except ValueError:
            d_rel = d_abs
        try:
            p_rel = os.path.relpath(p_abs, abs_base).replace('\\', '/')
        except ValueError:
            p_rel = p_abs
    else:
        d_rel = os.path.normpath(dir_path).replace('\\', '/')
        p_rel = os.path.normpath(pattern).replace('\\', '/')

    d_parts = [p for p in os.path.normcase(d_rel).replace('\\', '/').split('/') if p and p != '.']
    p_parts = [p for p in os.path.normcase(p_rel).replace('\\', '/').split('/') if p and p != '.']

    @lru_cache(None)
    def match(d_idx: int, p_idx: int) -> bool:
        if d_idx == len(d_parts):
            return p_idx < len(p_parts)
        if p_idx == len(p_parts):
            return False

        seg = p_parts[p_idx]
        if seg == '**':
            return match(d_idx, p_idx + 1) or (
                not d_parts[d_idx].startswith('.') and match(d_idx + 1, p_idx)
            )

        if not d_parts[d_idx].startswith('.') or seg.startswith('.'):
            if fnmatchcase(d_parts[d_idx], seg):
                return match(d_idx + 1, p_idx + 1)

        return False

    return match(0, 0)


class ManagedFOMCache(MutableMapping):
    """Dictionary-compatible registrations with one identity per normalized path."""

    def __init__(self, workspace):
        self.workspace = workspace
        self._files = {}
        self._identities = {}
        self._physical_identities = {}
        self._physical_keys = {}
        self._registered_paths = set()

    def _path(self, path):
        resolved = self.workspace.resolve_path(path)
        lexical = self._identities.get(os.path.normcase(resolved))
        if lexical is not None:
            return lexical
        physical = self._physical_identities.get(os.path.normcase(os.path.realpath(resolved)))
        return physical if physical in self._files else resolved

    def __getitem__(self, path):
        path = self._path(path)
        fom = self.workspace._materialize_fom(path)
        self.workspace._record_access(path)
        return fom

    def __setitem__(self, path, fom):
        self.workspace.register_fom(path, fom)

    def __delitem__(self, path):
        path = self._path(path)
        del self._files[path]
        self._identities.pop(os.path.normcase(path), None)
        physical_key = self._physical_keys.pop(path, None)
        if self._physical_identities.get(physical_key) == path:
            self._physical_identities.pop(physical_key, None)

    def __iter__(self):
        self.workspace._touched_paths.update(self._files)
        return iter(self._files)

    def __len__(self):
        return len(self._files)

    def copy(self):
        return {path: self[path] for path in tuple(self._files)}

    def _save_view(self):
        """Give the framework writer immutable references without exposing models."""
        result = dict(self._files)
        if self.workspace._pending_deletions:
            from rule_framework.storage import ManagedDeletion
            for path, digest in self.workspace._pending_deletions.items():
                result.setdefault(path, ManagedDeletion(digest))
        return result

    def _register(self, path, fom):
        path = self._path(path)
        self._files[path] = fom
        self._registered_paths.add(path)
        self._identities[os.path.normcase(path)] = path
        physical_key = os.path.normcase(os.path.realpath(path))
        prior_key = self._physical_keys.get(path)
        if prior_key != physical_key and self._physical_identities.get(prior_key) == path:
            self._physical_identities.pop(prior_key, None)
        self._physical_keys[path] = physical_key
        self._physical_identities[physical_key] = path
        return path

    def _restore(self, foms):
        self._files.clear()
        self._identities.clear()
        self._physical_identities.clear()
        self._physical_keys.clear()
        self._registered_paths.clear()
        for path, fom in foms.items():
            self._register(path, fom)


@dataclass
class _TaskCheckpoint:
    foms: dict
    states: dict = field(default_factory=dict)
    accessed: set = field(default_factory=set)
    capturing: set = field(default_factory=set)
    eager_memo: Optional[dict] = field(default=None, repr=False)
    replacements: set = field(default_factory=set)
    receipts: object = None


@dataclass(frozen=True)
class WorkspaceSnapshot:
    foms: dict
    states: dict


def _seed_native_memo(foms, memo, *, states=None):
    """Seed native aliases within this resident capture or restore group."""
    from rule_framework.state_copy import copy_managed_state

    method_name = 'snapshot_state' if states is None else 'restore_state'
    default_method = getattr(FOMBase, method_name)
    roots = []
    for path, fom in foms.items():
        if isinstance(fom, SpilledFOM):
            continue
        namespace = object.__getattribute__(fom, '__dict__')
        if (method_name in namespace
                or getattr(type(fom), method_name) is not default_method):
            continue
        state = namespace if states is None else states.get(path)
        if not isinstance(state, dict):
            continue
        roots.extend(state[name] for name in type(fom).native_transaction_fields
                     if name in type(fom).transaction_fields and name in state)
    # Existing entries retain the caller's memo policy. Unmaterialized states
    # and opaque adapter protocols stay on their existing per-file path.
    copy_managed_state(None, memo=memo, native_values=roots)


class MissingSourceInputError(FileNotFoundError):
    def __init__(self, path: str):
        super().__init__(f'Required source input is missing: {path}')
        self.path = path


class ManagedWorkspace:
    """Keep ordered working state staged until the successful aggregate is saved.

    get_fom reads the latest working state. A snapshot covers every cached file,
    including files reached by a Hook, and restore reinstates its membership and
    object state. Internal Task checkpoints copy owned models on first access
    and eagerly protect every model previously exposed to Hooks or cross-file
    operations. The dictionary identity and previously loaded FOM identities
    remain stable for callers retaining references through a transaction.
    Native models without external references can reside in private temporary
    state files between operations. Public access pins their materialized FOMs.
    """

    def __init__(self, *, base_dir, load_fom, settings=None, _owned_loader=None,
                 missing_source_targets=None, missing_source_directories=None, _state_spool=None):
        self.base_dir = os.path.abspath(base_dir)
        self.load_fom = load_fom
        if _owned_loader is not None and not callable(_owned_loader):
            raise ValueError("Owned-loader predicate must be callable")
        self._owned_loader = _owned_loader
        self.settings = deepcopy(settings or {})
        self.action_receipts = None
        self.source_admission = None
        self._pending_deletions = {}
        self.missing_source_targets = set(missing_source_targets or ())
        self.missing_source_directories = set(missing_source_directories or ())
        self._fom_cache = ManagedFOMCache(self)
        self._touched_paths = set()
        self._task_checkpoint = None
        self._escaped_paths = set()
        self._action_paths = None
        self._last_action_paths = set()
        self._state_spool = _state_spool
        from rule_framework.working_set import WorkingSetManager
        self._working_set = WorkingSetManager(self)
        self._git_checkpoint = None

    def is_missing_source_input(self, path: str) -> bool:
        key = self.fom_cache._path(path)
        if key in self._pending_deletions and key not in self.fom_cache._files:
            return True
        if not self.missing_source_targets and not self.missing_source_directories:
            return False
        from rule_framework.resources import BinaryResourceFOM
        norm = os.path.normcase(os.path.normpath(path)).replace('\\', '/')
        abs_resolved = os.path.normpath(self.resolve_path(path)).replace('\\', '/')
        abs_path = os.path.normcase(abs_resolved).replace('\\', '/')
        physical_path = os.path.normcase(os.path.realpath(abs_resolved)).replace('\\', '/')
        rel_path = os.path.normcase(os.path.relpath(abs_resolved, self.base_dir)).replace('\\', '/')
        cache_path = self.fom_cache._path(abs_resolved)

        for missing in self.missing_source_targets:
            m_norm = os.path.normcase(os.path.normpath(missing)).replace('\\', '/')
            if (norm == m_norm or abs_path == m_norm or rel_path == m_norm
                    or physical_path ==
                    os.path.normcase(os.path.realpath(self.resolve_path(missing))).replace('\\', '/')):
                fom = self.fom_cache._files.get(cache_path)
                if fom is not None and not (isinstance(fom, BinaryResourceFOM) and not fom.resource_exists):
                    return False
                if os.path.isfile(abs_resolved):
                    return False
                return True

        for missing_dir in self.missing_source_directories:
            md_norm = os.path.normcase(os.path.normpath(missing_dir)).replace('\\', '/').rstrip('/')
            md_abs = os.path.normcase(os.path.normpath(self.resolve_path(missing_dir))).replace('\\', '/').rstrip('/')
            md_physical = os.path.normcase(os.path.realpath(self.resolve_path(missing_dir))).replace('\\', '/').rstrip('/')
            if (abs_path.startswith(md_abs + '/') or norm.startswith(md_norm + '/') or rel_path.startswith(md_norm + '/')
                    or physical_path.startswith(md_physical + '/')):
                fom = self.fom_cache._files.get(cache_path)
                if fom is not None and not (isinstance(fom, BinaryResourceFOM) and not fom.resource_exists):
                    return False
                if os.path.isfile(abs_resolved):
                    return False
                return True

        return False

    @property
    def fom_cache(self):
        return self._fom_cache

    @fom_cache.setter
    def fom_cache(self, value):
        raise ValueError('Managed fom_cache identity is fixed; '
                         'use workspace.register_fom(path, fom) to stage files')

    def _record_access(self, path, *, expose=True):
        if self.source_admission is not None:
            self.source_admission.claim(path)
        self._capture_fom(path)
        self._touched_paths.add(path)
        if expose:
            self._expose_fom(path)

    def _expose_fom(self, path):
        self._escaped_paths.add(path)
        self._working_set.expose(path)
        checkpoint = self._task_checkpoint
        if (checkpoint is not None and isinstance(checkpoint.foms.get(path), SpilledFOM)
                and path not in checkpoint.replacements):
            current = self.fom_cache._files.get(path)
            if current is not None and not isinstance(current, SpilledFOM):
                checkpoint.states.setdefault(path, checkpoint.foms[path])
                checkpoint.foms[path] = current

    def _materialize_fom(self, path):
        fom = self.fom_cache._files[path]
        if isinstance(fom, SpilledFOM):
            self._working_set.before_load(path)
            fom = fom.materialize()
            self.fom_cache._files[path] = fom
        return fom

    def _spill_owned_fom(self, path, *, force=False):
        """Release native state after use while preserving exposed identities."""
        path = self.fom_cache._path(path)
        fom = self.fom_cache._files.get(path)
        if (fom is None or isinstance(fom, SpilledFOM) or path in self._escaped_paths
                or self._owned_loader is None or not self._owned_loader(path)
                or not _native_model(fom)):
            return
        from rule_framework.fom import ClashYamlFile
        from rule_framework.state_spool import _is_stock_yaml_parser, _has_stock_methods
        from rule_framework.task_runner import _is_immutable_settings
        if not _is_immutable_settings(getattr(fom, 'settings', {})):
            self._expose_fom(path)
            return
        unknown = set(fom.__dict__).difference(fom.transaction_fields).difference({'yaml'})
        if unknown:
            self._expose_fom(path)
            return
        if hasattr(fom, 'yaml') and not _is_stock_yaml_parser(fom):
            self._expose_fom(path)
            return
        if type(fom) is ClashYamlFile and not _has_stock_methods(type(fom)):
            self._expose_fom(path)
            return
        if self._state_spool is None:
            self._state_spool = StateSpool()
        try:
            spilled = self._working_set.backing_for(path) or self._state_spool.store(fom)
        except (pickle.PickleError, TypeError, AttributeError):
            # API callers may supply non-serializable settings. Retain their
            # existing in-memory behavior and rollback protocol in that case.
            self._expose_fom(path)
            return
        self._working_set.install(path, spilled, fom, force=force)

    def _backing_fom(self, path):
        entry = self.fom_cache._files.get(path)
        return entry if isinstance(entry, SpilledFOM) else self._working_set.backing_for(path)

    def _reuse_backing(self, path, backing, fom):
        self._working_set.install(path, backing, fom)

    def _record_git_version(self, message):
        """Keep private Git trees of immutable state versions; public objects stay pinned."""
        spool = self._state_spool
        store = getattr(spool, 'git_store', None)
        if store is None:
            return
        import hashlib
        import json
        entries, manifest = {}, {}
        for path, fom in self.fom_cache._files.items():
            backing = self._backing_fom(path)
            oid = getattr(backing, 'hex_sha', None)
            if oid is not None:
                name = hashlib.sha256(path.encode('utf-8')).hexdigest() + '.state'
                entries[name] = oid
                manifest[path] = {'state': name, 'model': backing.model_type.__name__}
            else:
                manifest[path] = {'resident': True, 'model': type(fom).__name__}
        try:
            entries['manifest.json'] = store.store_blob(json.dumps(manifest, sort_keys=True).encode('utf-8'))
            tree = store.store_tree(entries)
            commit = store.store_commit(tree, parent_sha=self._git_checkpoint, message=message)
            target = os.path.join(store.root, 'refs', 'heads', 'main')
            pending = target + '.tmp'
            with open(pending, 'w', encoding='ascii') as output:
                output.write(commit + '\n')
            os.replace(pending, target)
            self._git_checkpoint = commit
        except (OSError, ValueError) as error:
            # A diagnostic Git history failure does not replace Task rollback evidence.
            import logging
            logging.getLogger('RuleFramework').warning('Private Git checkpoint unavailable: %s', error)

    def _capture_fom(self, path, *, memo=None):
        checkpoint = self._task_checkpoint
        if checkpoint is None:
            return
        checkpoint.accessed.add(path)
        if self._action_paths is not None:
            self._action_paths.add(path)
        if path not in checkpoint.foms or path in checkpoint.states or path in checkpoint.capturing:
            return
        # Reads during eager native seeding or copy callbacks join the pending
        # group. Explicit captures share its prepared memo; ordinary lazy
        # captures resume once the eager phase has finished.
        if memo is None and checkpoint.eager_memo is not None:
            return
        checkpoint.capturing.add(path)
        try:
            fom = checkpoint.foms[path]
            if (not isinstance(fom, SpilledFOM) and path not in self._escaped_paths
                    and self._owned_loader is not None and self._owned_loader(path)
                    and _native_model(fom)):
                self._spill_owned_fom(path)
                spilled = self.fom_cache._files.get(path)
                if isinstance(spilled, SpilledFOM):
                    checkpoint.foms[path] = spilled
                    checkpoint.states[path] = spilled
                else:
                    checkpoint.states[path] = checkpoint.foms[path].snapshot_state(memo=memo)
            else:
                checkpoint.states[path] = checkpoint.foms[path].snapshot_state(memo=memo)
        finally:
            checkpoint.capturing.remove(path)

    @contextmanager
    def _task_transaction(self):
        if self._task_checkpoint is not None:
            raise ValueError('Task checkpoints cannot be nested')
        checkpoint = _TaskCheckpoint(self._working_set.snapshot_entries())
        if self.action_receipts is not None:
            checkpoint.receipts = self.action_receipts.snapshot()
        self._record_git_version("Task start")
        self._task_checkpoint = checkpoint
        memo = {}
        native_seeded = set()
        checkpoint.eager_memo = memo
        try:
            # Previously exposed models may share arbitrary mutable references.
            # Include additional references inspected by their copy callbacks.
            while True:
                pending = self._escaped_paths.intersection(checkpoint.foms).difference(checkpoint.states)
                if not pending:
                    break
                unseeded = pending.difference(native_seeded)
                if unseeded:
                    _seed_native_memo({path: checkpoint.foms[path] for path in sorted(unseeded)}, memo)
                    native_seeded.update(unseeded)
                    # Seeding callbacks may expose peers. Include their native
                    # roots before any extension state enters this memo.
                    continue
                for path in sorted(pending):
                    self._capture_fom(path, memo=memo)
            checkpoint.eager_memo = None
            memo.clear()
            yield checkpoint
        finally:
            checkpoint.eager_memo = None
            memo.clear()
            self._task_checkpoint = None
            self._record_git_version("Task finish")

    @contextmanager
    def _action_scope(self, action_type, fom):
        local_actions = {'add_rule', 'remove_rule', 'modify', 'json_set', 'json_remove',
                         'add_rewrite', 'remove_rewrite', 'add_script', 'remove_script',
                         'add_mitm', 'remove_mitm'}
        # Local stock actions own their models. Hooks, cross-file actions and
        # extension adapters may retain or create cross-file mutable aliases.
        owned_action = action_type in local_actions and _native_model(fom)
        previous_paths = self._action_paths
        paths = {self.resolve_path(fom.filepath)}
        self._working_set.mark_action(self.fom_cache._path(fom.filepath))
        self._action_paths = paths
        if not owned_action:
            for path in paths:
                self._expose_fom(path)
        try:
            yield
        finally:
            self._last_action_paths = paths
            self._action_paths = previous_paths
            if previous_paths is not None:
                previous_paths.update(paths)

    def _validate_task(self, *, complete=False):
        checkpoint = self._task_checkpoint
        if checkpoint is None:
            return self.validate(complete=complete)
        validated = set()
        while True:
            paths = set(checkpoint.accessed if complete else self._last_action_paths)
            paths.update(self._escaped_paths)
            pending = paths.intersection(self.fom_cache._files).difference(validated)
            if not pending:
                # Keep the registration-deletion check even for an empty scope.
                self.validate(complete=complete, paths=())
                return
            self.validate(complete=complete, paths=tuple(sorted(pending)))
            validated.update(pending)

    def resolve_path(self, path):
        message = 'Managed path must be a non-empty text path without NUL characters'
        try:
            path = os.fspath(path)
        except TypeError as error:
            raise ValueError(message) from error
        if not isinstance(path, str) or not path.strip() or '\0' in path:
            raise ValueError(message)
        if not os.path.isabs(path):
            path = os.path.join(self.base_dir, path)
        return os.path.normpath(os.path.abspath(path)).replace('\\', '/')

    def _validate_managed_path(self, path):
        root = os.path.normcase(os.path.realpath(self.base_dir))
        resolved = os.path.normcase(os.path.realpath(path))
        try:
            inside = os.path.commonpath((root, resolved)) == root
        except ValueError:
            inside = False
        if not inside:
            raise ValueError('Managed path must stay inside base_dir')
        relative = os.path.relpath(resolved, root)
        if ':' in relative:
            raise ValueError('Managed relative path must not contain colon characters')
        if os.name == 'nt' and any(char in '<>"|?*' or ord(char) < 32 for char in relative):
            raise ValueError('Managed path contains invalid Windows filename characters')
        from rule_framework.action_receipts import RECEIPTS_FILENAME
        from rule_framework.sources import SOURCES_STATE_FILENAME
        from rule_framework.storage import RECOVERY_DIRECTORY
        for name in (RECEIPTS_FILENAME, SOURCES_STATE_FILENAME, RECOVERY_DIRECTORY):
            reserved = os.path.normcase(os.path.realpath(os.path.join(self.base_dir, name)))
            if resolved == reserved or (name == RECOVERY_DIRECTORY
                                       and os.path.commonpath((reserved, resolved)) == reserved):
                raise ValueError('Managed path overlaps reserved framework state')

    def register_fom(self, path, fom):
        """Stage an adapter without disk writes; additions and replacements roll back."""
        return self._register_fom(path, fom, expose=True)

    def _register_fom(self, path, fom, *, expose):
        path = self.fom_cache._path(path)
        self._validate_managed_path(path)
        if not isinstance(fom, FOMBase):
            raise ValueError(f'Working file must be a managed FOM: {path}')
        if os.path.normcase(self.resolve_path(fom.filepath)) != os.path.normcase(path):
            raise ValueError(f'Working FOM path differs from its managed path: {path}')
        self._capture_fom(path)
        checkpoint = self._task_checkpoint
        if (checkpoint is not None and path in checkpoint.foms
                and self.fom_cache._files.get(path) is not fom):
            checkpoint.replacements.add(path)
        fom.filepath = path
        fom.settings = deepcopy(getattr(fom, 'settings', self.settings))
        if '_metadata_origin' not in fom.__dict__ and (callable(getattr(fom, 'update_metadata', None)) or callable(getattr(fom, '_apply_metadata', None))):
            from pathlib import Path
            if os.path.isfile(path):
                original = Path(path).read_bytes()
                cached = getattr(fom, '_raw_bytes', getattr(fom, '_metadata_baseline', None))
                fom._metadata_origin = cached if cached == original else original
            else:
                fom._metadata_origin = None
        self.fom_cache._register(path, fom)
        self._touched_paths.add(path)
        if expose:
            self._expose_fom(path)
        return fom

    def get_fom(self, path, *, factory=None):
        fom = self._get_owned_fom(path, factory=factory)
        self._expose_fom(self.fom_cache._path(fom.filepath))
        return fom

    def _cached_fom_type(self, path):
        fom = self.fom_cache._files.get(self.fom_cache._path(path))
        if isinstance(fom, SpilledFOM):
            return fom.model_type.__name__
        return type(fom).__name__ if fom is not None else None

    def _get_owned_fom(self, path, *, factory=None):
        path = self.fom_cache._path(path)
        self._validate_managed_path(path)
        if path not in self.fom_cache._files:
            import time
            self._working_set.before_load(path)
            load_started = time.process_time()
            if factory is None and self.is_missing_source_input(path):
                raise MissingSourceInputError(path)
            owned = factory is None and self._owned_loader is not None and self._owned_loader(path)
            if factory is None:
                fom = self.load_fom(path)
            else:
                if not callable(factory):
                    raise ValueError('Managed FOM factory must be callable')
                fom = factory(path)
                if not isinstance(fom, FOMBase):
                    raise ValueError(f'Working file must be a managed FOM: {path}')
                fom.settings = deepcopy(self.settings)
                if os.path.isfile(path):
                    fom.load()
                else:
                    fom.scaffold(os.path.splitext(os.path.basename(path))[0])
            if fom is None:
                raise ValueError(f'No supported FOM for target: {path}')
            owned = owned and self._owned_loader(path)
            self._register_fom(path, fom, expose=not owned)
            self._working_set.record_load_cost(path, time.process_time() - load_started)
        self._record_access(path, expose=False)
        return self._materialize_fom(path)

    def create_resource(self, path, data):
        """Stage resource bytes; final publication owns disk writes."""
        from rule_framework.resources import create_resource
        return create_resource(self, path, data)

    def replace_resource(self, path, data):
        """Stage a byte replacement of an existing resource."""
        from rule_framework.resources import replace_resource
        return replace_resource(self, path, data)

    def read_bytes(self, path):
        """Read current serializable file bytes, including staged Task changes."""
        path = self.resolve_path(path)
        if self.is_missing_source_input(path):
            raise MissingSourceInputError(path)
        if not self.exists(path):
            raise FileNotFoundError(f'Resource source does not exist: {path}')
        fom = self.get_fom(path)
        render = getattr(fom, 'render_bytes', None)
        if not callable(render):
            raise ValueError(f'Current staged bytes are unsupported for {type(fom).__name__}: {path}')
        data = render()
        if not isinstance(data, bytes):
            raise ValueError(f'Managed byte renderer must return bytes: {path}')
        return data

    def copy_resource(self, source, target):
        """Copy current source bytes into a staged resource target."""
        fom = self.create_resource(target, self.read_bytes(source))
        import logging
        logging.getLogger('RuleFramework').info('Resource copied: source=%s target=%s',
                                               self.resolve_path(source), fom.filepath)
        return fom

    def exists(self, path):
        path = self.resolve_path(path)
        path = self.fom_cache._path(path)
        if path in self.fom_cache._files:
            self._touched_paths.add(path)
            return True
        if path in self._pending_deletions:
            return False
        return os.path.isfile(path)

    def paths(self):
        return tuple(self.fom_cache._files)

    def touched_paths(self):
        """Paths reached since the Task began, including compatibility-cache reads."""
        return tuple(sorted(self._touched_paths))

    def reset_touched_paths(self):
        self._touched_paths.clear()

    def glob(self, pattern):
        """Resolve disk files and staged new files with the same glob semantics."""
        pattern = self.resolve_path(pattern)
        matches = {self.fom_cache._path(path) for path in glob.glob(pattern, recursive=True)
                   if os.path.isfile(path)}
        if self.fom_cache._files:
            physical_patterns = _physical_glob_patterns(pattern)
            for path in self.fom_cache._files:
                if _matches_glob(path, pattern):
                    matches.add(path)
                    continue
                physical_path = os.path.realpath(path)
                if any(_matches_glob(physical_path, physical_pattern)
                       for physical_pattern in physical_patterns):
                    matches.add(path)
        return tuple(sorted(path for path in matches
                            if path not in self._pending_deletions or path in self.fom_cache._files))

    def validate(self, *, complete=False, paths=None):
        """Validate working files while their Task can roll back.

        The default includes all files. A selected scope is for callers that can
        rule out cross-file mutation; the runner uses it only before any Hook or
        workspace-aware Action has executed.
        """
        missing = self.fom_cache._registered_paths.difference(self.fom_cache._files)
        if missing:
            raise ValueError('Managed files cannot be unregistered from fom_cache: '
                             + ', '.join(sorted(missing)) + '; keep their registered working FOMs')
        normalized = {}
        selected = None if paths is None else tuple(dict.fromkeys(self.fom_cache._path(path) for path in paths))
        files = (self.fom_cache._files.items() if selected is None else
                 ((path, self.fom_cache._files[path]) for path in selected))
        for path, fom in files:
            spilled = isinstance(fom, SpilledFOM)
            backing = fom if spilled else self._working_set.backing_for(path)
            if backing is not None and path not in self._escaped_paths and backing.has_valid_closed_pristine(self.settings):
                resolved_path = self.resolve_path(path)
                if self.resolve_path(fom.filepath) != resolved_path:
                    raise ValueError(f'Working FOM path differs from its managed path: {resolved_path}')
                if resolved_path in normalized and normalized[resolved_path] is not fom:
                    raise ValueError(f'Multiple working FOMs refer to the same path: {resolved_path}')
                normalized[resolved_path] = fom
                continue
            if spilled:
                fom = self._materialize_fom(path)
            if not isinstance(fom, FOMBase):
                raise ValueError(f'Working file must be a managed FOM: {path}')
            path = self.resolve_path(path)
            if self.resolve_path(fom.filepath) != path:
                raise ValueError(f'Working FOM path differs from its managed path: {path}')
            if path in normalized and normalized[path] is not fom:
                raise ValueError(f'Multiple working FOMs refer to the same path: {path}')
            if backing is not None:
                self._working_set.mark_action(path)
            fom.validate()
            if complete:
                validate_complete = getattr(fom, 'validate_complete', None)
                if callable(validate_complete):
                    validate_complete()
            if spilled or backing is not None:
                # Validation may synchronize nodes, bytes and metadata. Persist
                # that state before releasing the materialized adapter again.
                self._spill_owned_fom(path)
                normalized[path] = self.fom_cache._files[path]
            else:
                normalized[path] = fom
        if selected is None:
            self.fom_cache._restore(normalized)

    def snapshot(self):
        foms = self.fom_cache.copy()
        memo = {}
        _seed_native_memo(foms, memo)
        states = {path: fom.snapshot_state(memo=memo) for path, fom in foms.items()}
        return WorkspaceSnapshot(foms, states)

    def restore(self, snapshot):
        if self.action_receipts is not None and getattr(snapshot, "receipts", None) is not None:
            self.action_receipts.restore(snapshot.receipts)
        memo = {}
        active = self._task_checkpoint
        self._task_checkpoint = None
        try:
            _seed_native_memo(snapshot.foms, memo, states=snapshot.states)
            for path, state in snapshot.states.items():
                if isinstance(state, SpilledFOM) and not isinstance(snapshot.foms[path], SpilledFOM):
                    state = state.read_state()
                snapshot.foms[path].restore_state(state, memo=memo)
            self.fom_cache._restore(snapshot.foms)
            self._working_set.reset()
            self._touched_paths.clear()
        finally:
            self._task_checkpoint = active

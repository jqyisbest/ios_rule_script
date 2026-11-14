"""Private disk-backed states for native models with no escaped references."""
import logging
import os
import pickle
import tempfile
import weakref
from bisect import bisect_left
from collections.abc import MutableMapping
from copy import deepcopy
import shutil
from pathlib import Path

from rule_framework.fom import FOMBase


def _immutable(value):
    return (type(value) in (str, bytes, int, float, bool, type(None))
            or type(value) is tuple and all(_immutable(part) for part in value))


from ruamel.yaml.scalarstring import ScalarString


def _presentation_state(value):
    values = dict(getattr(value, '__dict__', {}))
    for cls in type(value).__mro__:
        slots = vars(cls).get('__slots__', ())
        slots = (slots,) if isinstance(slots, str) else slots
        for name in slots:
            if name.startswith('__') and not name.endswith('__'):
                name = '_' + cls.__name__.lstrip('_') + name
            if name not in {'__dict__', '__weakref__'} and hasattr(value, name):
                values[name] = getattr(value, name)
    return values.values()


def _codec_stamp(classes):
    result = []
    native = {Path(__file__).resolve().parent, Path(__import__('ruamel.yaml.constructor', fromlist=['x']).__file__).resolve().parent}
    for cls in classes:
        for name in ('__new__', '__getnewargs__', '__getnewargs_ex__', '__getstate__', '__setstate__', '__reduce__', '__reduce_ex__'):
            method = getattr(cls, name, None)
            code = getattr(method, '__code__', None)
            if code is not None and Path(code.co_filename).resolve().parent not in native:
                raise pickle.PicklingError('Custom state codecs require a resident model')
            result.append((cls, name, method, code))
    return tuple(result)


class _SourceLinkedPickler(pickle.Pickler):
    def __init__(self, stream, references):
        super().__init__(stream, protocol=pickle.HIGHEST_PROTOCOL)
        self.references = references

    def persistent_id(self, value):
        if isinstance(value, ScalarString):
            return self.references.get(id(value))
        return None


class _SourceLinkedUnpickler(pickle.Unpickler):
    def __init__(self, stream, values):
        super().__init__(stream)
        self.values = values

    def persistent_load(self, reference):
        if type(reference) is not int or not 0 <= reference < len(self.values):
            raise pickle.UnpicklingError('Invalid private source scalar reference')
        value = self.values[reference]
        if not isinstance(value, ScalarString):
            raise pickle.UnpicklingError('Private source reference does not identify a styled scalar')
        return value


def _independent_nodes(nodes, header, source_refs=None):
    """Recognize flat native routing nodes whose mutable fields are independent."""
    identities = [id(nodes)]
    for node in nodes:
        if type(node).__module__ not in {'rule_framework.ast', 'rule_framework.mihomo_formats'}:
            return False
        attributes = getattr(node, '__dict__', None)
        if attributes is None:
            return False
        identities.extend((id(node), id(attributes)))
        for value in attributes.values():
            if _immutable(value):
                continue
            if source_refs is not None and isinstance(value, ScalarString) and id(value) in source_refs:
                continue
            if type(value) is not list or not all(_immutable(part) for part in value):
                return False
            identities.append(id(value))
    # A sorted index bounds this safety check's own transient allocation; a set
    # holding every node, attribute dict and token list is considerably larger.
    identities.sort()
    if any(identities[index - 1] == identities[index] for index in range(1, len(identities))):
        return False
    visited = set()
    pending = [header]
    while pending:
        value = pending.pop()
        if type(value) in (str, bytes, int, float, bool, type(None)):
            continue
        if source_refs is None and isinstance(value, (str, bytes, int, float, bool)):
            continue
        position = bisect_left(identities, id(value))
        if position < len(identities) and identities[position] == id(value):
            if isinstance(value, dict):
                # Pickle reconstructs instance namespaces separately. Keep this
                # graph resident so a caller's namespace alias stays intact.
                raise pickle.PicklingError('Aliased node namespaces require a resident model')
            return False
        if id(value) in visited:
            continue
        visited.add(id(value))
        if isinstance(value, dict):
            pending.extend(value)
            pending.extend(value.values())
        elif isinstance(value, (list, tuple, set, frozenset)):
            pending.extend(value)
        elif source_refs is not None and type(value).__module__.startswith('ruamel.yaml.'):
            pending.extend(_presentation_state(value))
        else:
            # Keep opaque API values on the graph-preserving serializer.
            return False
        if source_refs is not None and isinstance(value, (dict, list, tuple)) and type(value).__module__.startswith('ruamel.yaml.'):
            pending.extend(_presentation_state(value))
    return True


def _remove_state(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as error:
        logging.getLogger('RuleFramework').warning('Temporary managed state cleanup deferred: %s', error)


from rule_framework.fom import ClashYamlFile, FOMBase
from rule_framework.mihomo_formats import MihomoRoutingMixin, MihomoYamlMixin

_STOCK_CLASH_YAML_METHODS = {
    '__init__': ClashYamlFile.__init__,
    'load': ClashYamlFile.load,
    '_load_bytes': ClashYamlFile._load_bytes,
    'remove_rule': ClashYamlFile.remove_rule,
    'validate': ClashYamlFile.validate,
    'validate_complete': ClashYamlFile.validate_complete,
    'render_bytes': ClashYamlFile.render_bytes,
    'save_to': ClashYamlFile.save_to,
    'save': ClashYamlFile.save,
    'update_metadata': ClashYamlFile.update_metadata,
    '_sync_managed_state': ClashYamlFile._sync_managed_state,
    '_commit_nodes': ClashYamlFile._commit_nodes,
}
_STOCK_IMPLEMENTATIONS_NATIVE = all(
    getattr(method, '__code__', None) is not None
    and Path(method.__code__.co_filename).resolve().parent == Path(__file__).resolve().parent
    for method in (*_STOCK_CLASH_YAML_METHODS.values(), FOMBase.validate)
)
_STOCK_FOM_BASE_VALIDATE = FOMBase.validate
_STOCK_MIHOMO_VALIDATE = MihomoRoutingMixin.validate
_STOCK_MIHOMO_VALIDATE_COMPLETE = MihomoRoutingMixin.validate_complete
_STOCK_MIHOMO_REMOVE_RULE = MihomoRoutingMixin.remove_rule
_STOCK_MIHOMO_UPDATE_METADATA = MihomoRoutingMixin.update_metadata
_STOCK_MIHOMO_YAML_RENDER_BYTES = MihomoYamlMixin.render_bytes
_STOCK_MIHOMO_YAML_SYNC = MihomoYamlMixin._sync_managed_state
_STOCK_MIHOMO_COMMIT_NODES = MihomoYamlMixin._commit_nodes


from ruamel.yaml import YAML
from ruamel.yaml.constructor import RoundTripConstructor
import ruamel.yaml.constructor as _yaml_constructor
from rule_framework.actions import RemoveRuleAction
import rule_framework.executor as _executor
import rule_framework.managed_validation as _managed_validation
import rule_framework.mihomo_formats as _mihomo_formats

_STOCK_CONSTRUCTORS = dict(RoundTripConstructor.yaml_constructors)
_STOCK_MULTI_CONSTRUCTORS = dict(RoundTripConstructor.yaml_multi_constructors)
_STOCK_CONSTRUCTORS_NATIVE = all(
    getattr(method, '__code__', None) is not None
    and Path(method.__code__.co_filename).resolve().parent == Path(_yaml_constructor.__file__).resolve().parent
    for method in (*_STOCK_CONSTRUCTORS.values(), *_STOCK_MULTI_CONSTRUCTORS.values())
)
_STOCK_DEPENDENCIES = (
    (_executor.ActionExecutor, '__init__', _executor.ActionExecutor.__init__),
    (_executor.ActionExecutor, 'execute_action', _executor.ActionExecutor.execute_action),
    (_executor, 'parse_action', _executor.parse_action),
    (RemoveRuleAction, 'execute', RemoveRuleAction.execute),
    (_mihomo_formats.MihomoRuleNode, 'render', _mihomo_formats.MihomoRuleNode.render),
    (_mihomo_formats, '_semantic_snapshot', _mihomo_formats._semantic_snapshot),
    (_mihomo_formats, '_yaml_annotations', _mihomo_formats._yaml_annotations),
    (_mihomo_formats, 'yaml_values_equal', _mihomo_formats.yaml_values_equal),
    (_mihomo_formats, '_capture_pristine_baseline', _mihomo_formats._capture_pristine_baseline),
    (_mihomo_formats, '_matches_pristine_yaml_state', _mihomo_formats._matches_pristine_yaml_state),
    (_managed_validation, 'validate_fom_collections', _managed_validation.validate_fom_collections),
    (YAML, '__init__', YAML.__init__),
    (YAML, 'load', YAML.load),
    (RoundTripConstructor, '__init__', RoundTripConstructor.__init__),
)


_STOCK_DEPENDENCY_DIRECTORIES = {Path(__file__).resolve().parent,
                                 Path(_yaml_constructor.__file__).resolve().parent}
_STOCK_DEPENDENCIES_NATIVE = all(
    getattr(method, '__code__', None) is not None
    and Path(method.__code__.co_filename).resolve().parent in _STOCK_DEPENDENCY_DIRECTORIES
    for _, _, method in _STOCK_DEPENDENCIES)


def _is_stock_yaml_parser(fom):
    if not _STOCK_CONSTRUCTORS_NATIVE or not _STOCK_DEPENDENCIES_NATIVE:
        return False
    if any(getattr(owner, name, None) is not method for owner, name, method in _STOCK_DEPENDENCIES
           if owner in (YAML, RoundTripConstructor)):
        return False
    parser = getattr(fom, 'yaml', None)
    if type(parser) is not YAML or parser.Constructor is not RoundTripConstructor:
        return False
    constructor = parser.constructor
    if type(constructor) is not RoundTripConstructor:
        return False
    for current, expected in ((constructor.yaml_constructors, _STOCK_CONSTRUCTORS),
                              (constructor.yaml_multi_constructors, _STOCK_MULTI_CONSTRUCTORS)):
        if type(current) is not dict or current.keys() != expected.keys():
            return False
        if any(getattr(method, '__module__', None) != 'ruamel.yaml.constructor' for method in current.values()):
            return False
        if any(current[key] is not method for key, method in expected.items()):
            return False
    return True


def _has_stock_methods(model_type):
    if model_type is not ClashYamlFile:
        return False
    if not _STOCK_IMPLEMENTATIONS_NATIVE or not _STOCK_DEPENDENCIES_NATIVE:
        return False
    if any(getattr(owner, name, None) is not method for owner, name, method in _STOCK_DEPENDENCIES):
        return False
    if FOMBase.validate is not _STOCK_FOM_BASE_VALIDATE:
        return False
    if MihomoRoutingMixin.validate is not _STOCK_MIHOMO_VALIDATE:
        return False
    if MihomoRoutingMixin.validate_complete is not _STOCK_MIHOMO_VALIDATE_COMPLETE:
        return False
    if MihomoRoutingMixin.remove_rule is not _STOCK_MIHOMO_REMOVE_RULE:
        return False
    if MihomoRoutingMixin.update_metadata is not _STOCK_MIHOMO_UPDATE_METADATA:
        return False
    if MihomoYamlMixin.render_bytes is not _STOCK_MIHOMO_YAML_RENDER_BYTES:
        return False
    if MihomoYamlMixin._sync_managed_state is not _STOCK_MIHOMO_YAML_SYNC:
        return False
    if MihomoYamlMixin._commit_nodes is not _STOCK_MIHOMO_COMMIT_NODES:
        return False
    for name, method in _STOCK_CLASH_YAML_METHODS.items():
        if getattr(ClashYamlFile, name, None) is not method:
            return False
    return True


class _ClosedPristineState:
    def __init__(self, byte_path, settings, model_type):
        self.byte_path = byte_path
        self.settings = deepcopy(settings) if settings else {}
        self.model_type = model_type

    def is_valid(self, current_settings=None, current_model_type=None):
        if not os.path.isfile(self.byte_path):
            return False
        if current_model_type is not None and current_model_type != self.model_type:
            return False
        if current_settings is not None and current_settings != self.settings:
            return False
        if not _has_stock_methods(self.model_type):
            return False
        return True


from io import BytesIO
from rule_framework.git_state_store import GitStateStore


def _plain_extra_state(value, seen=None):
    """Unknown object codecs stay resident; plain extra graphs preserve aliases."""
    if _immutable(value):
        return True
    if type(value) not in (dict, list, tuple, set, frozenset):
        return False
    seen = set() if seen is None else seen
    if id(value) in seen:
        return True
    seen.add(id(value))
    values = tuple(value) + tuple(value.values()) if type(value) is dict else value
    return all(_plain_extra_state(item, seen) for item in values)


def _check_state_protocol(fom):
    settings = getattr(fom, 'settings', {})
    if type(settings) is not dict or any(type(key) is not str or not _immutable(value)
                                         for key, value in settings.items()):
        raise pickle.PicklingError('Opaque model settings require resident state')
    if hasattr(fom, 'yaml') and not _is_stock_yaml_parser(fom):
        raise pickle.PicklingError('Custom YAML constructors require resident state')
    managed = set(fom.transaction_fields)
    for name, value in vars(fom).items():
        if name not in managed and name != 'yaml' and not _plain_extra_state(value):
            raise pickle.PicklingError('Unknown extra state codec requires a resident model')
    # Native AST nodes have a supported serializer; extension codecs are opaque.
    checked = set()
    for node in getattr(fom, 'nodes', ()):
        cls = type(node)
        if cls in checked:
            continue
        checked.add(cls)
        if not cls.__module__.startswith('rule_framework.'):
            raise pickle.PicklingError('Extension AST nodes require resident state')
        for name in ('__getstate__', '__setstate__', '__reduce__', '__reduce_ex__'):
            code = getattr(getattr(cls, name, None), '__code__', None)
            if code is not None and Path(code.co_filename).resolve().parent != Path(__file__).resolve().parent:
                raise pickle.PicklingError('Custom AST codecs require resident state')


class StateSpool:
    """Own private bare Git backing store and temporary files for unexposed states."""

    def __init__(self, directory=None, git_store=None):
        if git_store is not None:
            self.git_store = git_store
            self._owns_git_store = False
        else:
            self.git_store = GitStateStore(directory=directory)
            self._owns_git_store = True
        self.directory = tempfile.TemporaryDirectory(prefix='rule-framework-state-')

    def close(self):
        try:
            if hasattr(self, 'directory') and self.directory is not None:
                self.directory.cleanup()
                self.directory = None
        finally:
            if getattr(self, '_owns_git_store', False) and hasattr(self, 'git_store') and self.git_store is not None:
                self.git_store.close()

    def write_render_cache(self, raw_bytes: bytes) -> str:
        descriptor, path = tempfile.mkstemp(suffix='.bytes', dir=self.directory.name)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw_bytes)
        except BaseException:
            _remove_state(path)
            raise
        return path

    def store(self, fom):
        _check_state_protocol(fom)
        # Parser handles stay outside managed snapshots. The same boundary is
        # used by Task rollback, and preserves aliases within each native file.
        managed_fields = set(getattr(fom, 'transaction_fields', ()))
        state = {name: fom.__dict__[name] for name in managed_fields if name in fom.__dict__}
        for key, value in fom.__dict__.items():
            if key not in managed_fields and key != 'yaml':
                state[key] = value

        from rule_framework.mihomo_formats import MihomoRoutingMixin
        nodes = state.get('nodes')
        header = {name: value for name, value in state.items() if name != 'nodes'}
        source_key = header.get('_sequence_key')
        source_values = header.get('data', {}).get(source_key, ()) if isinstance(header.get('data'), dict) else ()
        references = {id(value): index for index, value in enumerate(source_values) if isinstance(value, ScalarString)}
        classes = {type(node) for node in nodes} if isinstance(nodes, list) else set()
        classes.update(type(value) for value in source_values if isinstance(value, ScalarString))
        classes.update(type(value) for value in (header.get('data'), source_values) if value is not None)
        stamp = _codec_stamp(classes)
        linked = bool(references) and isinstance(fom, MihomoRoutingMixin) and isinstance(nodes, list) and _independent_nodes(nodes, header, references)
        descriptor, tmp_path = tempfile.mkstemp(suffix='.state.tmp', dir=self.directory.name)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                if linked:
                    pickle.dump(('routing-source-nodes-v1', header, len(nodes), source_key), stream, protocol=pickle.HIGHEST_PROTOCOL)
                    for first in range(0, len(nodes), 2048):
                        _SourceLinkedPickler(stream, references).dump(nodes[first:first + 2048])
                elif isinstance(fom, MihomoRoutingMixin) and isinstance(nodes, list) and _independent_nodes(nodes, header):
                    # A fresh pickle memo per block bounds transient allocation.
                    # YAML data and all other managed aliases stay in one graph.
                    pickle.dump(('routing-nodes-v1', header, len(nodes)), stream, protocol=pickle.HIGHEST_PROTOCOL)
                    for first in range(0, len(nodes), 2048):
                        pickle.dump(nodes[first:first + 2048], stream, protocol=pickle.HIGHEST_PROTOCOL)
                else:
                    pickle.dump(state, stream, protocol=pickle.HIGHEST_PROTOCOL)
            hex_sha = self.git_store.store_private_state_from_file(tmp_path)
        finally:
            _remove_state(tmp_path)

        path = self.git_store.object_path(hex_sha)
        return SpilledFOM(fom.filepath, type(fom), path, self, hex_sha=hex_sha, codec_stamp=stamp)


class SpilledFOM(FOMBase):
    """Immutable state reference used only inside the workspace and writer.

    Public cache access materializes the original adapter and pins its identity.
    Pickle inputs are exclusively files just written by this process in its
    private temporary directory; external files and recovery journals are never
    deserialized through this boundary.
    """

    def __init__(self, filepath, model_type, state_path, owner, hex_sha=None, codec_stamp=()):
        self.filepath = filepath
        self.model_type = model_type
        self.state_path = state_path
        self._owner = owner
        self.hex_sha = hex_sha
        self._codec_stamp = codec_stamp
        self._closed_state = None
        if hex_sha is None:
            self._cleanup = weakref.finalize(self, _remove_state, state_path)

    def mark_closed_pristine(self, byte_path: str, settings: dict):
        self._closed_state = _ClosedPristineState(byte_path, settings, self.model_type)
        self._cleanup_bytes = weakref.finalize(self, _remove_state, byte_path)

    def has_valid_closed_pristine(self, current_settings=None):
        closed = getattr(self, '_closed_state', None)
        if closed is None:
            return False
        return closed.is_valid(current_settings=current_settings, current_model_type=self.model_type)

    def read_state(self):
        for cls, name, method, code in self._codec_stamp:
            current = getattr(cls, name, None)
            if current is not method or getattr(current, '__code__', None) is not code:
                raise ValueError('Private managed state codec changed; preserve its source data')
        temp_path = None
        if self.hex_sha is not None and hasattr(self._owner, 'git_store'):
            stream = self._owner.git_store.open_private_state_stream(self.hex_sha)
            should_close = True
            temp_path = getattr(stream, 'name', None)
        else:
            stream = open(self.state_path, 'rb')
            should_close = True
        try:
            state = pickle.load(stream)
            if isinstance(state, dict):
                return state
            linked = isinstance(state, tuple) and len(state) == 4 and state[0] == 'routing-source-nodes-v1'
            flat = isinstance(state, tuple) and len(state) == 3 and state[0] == 'routing-nodes-v1'
            if (not (linked or flat) or not isinstance(state[1], dict)
                    or type(state[2]) is not int or state[2] < 0):
                raise ValueError('Invalid private managed state file')
            result, count = state[1:3]
            values = result.get('data', {}).get(state[3], ()) if linked else ()
            if linked and not isinstance(values, list):
                raise ValueError('Invalid private routing source sequence')
            nodes = []
            while len(nodes) < count:
                block = _SourceLinkedUnpickler(stream, values).load() if linked else pickle.load(stream)
                if not isinstance(block, list) or not 0 < len(block) <= min(2048, count - len(nodes)):
                    raise ValueError('Invalid private routing node block')
                nodes.extend(block)
            result['nodes'] = nodes
            return result
        finally:
            if should_close and hasattr(stream, 'close'):
                stream.close()
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    def materialize(self):
        self._closed_state = None
        fom = self.model_type(self.filepath)
        fom.__dict__.update(self.read_state())
        fom.filepath = self.filepath
        if hasattr(self, 'settings'):
            fom.settings = self.settings
        return fom

    def snapshot_state(self, *, memo=None):
        return self

    def restore_state(self, state, *, memo=None):
        if state is not self:
            raise ValueError('Immutable managed state reference cannot be replaced in place')

    def validate(self):
        if self.has_valid_closed_pristine(getattr(self, 'settings', None)):
            return
        self.materialize().validate()

    def validate_complete(self):
        if self.has_valid_closed_pristine(getattr(self, 'settings', None)):
            return
        fom = self.materialize()
        validate = getattr(fom, 'validate_complete', None)
        if callable(validate):
            validate()

    def render_bytes(self):
        if self.has_valid_closed_pristine(getattr(self, 'settings', None)):
            with open(self._closed_state.byte_path, 'rb') as stream:
                return stream.read()
        fom = self.materialize()
        render = getattr(fom, 'render_bytes', None)
        if callable(render):
            return render()
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            fom.save_to(tmp_path)
            with open(tmp_path, 'rb') as f:
                return f.read()
        finally:
            _remove_state(tmp_path)

    def save_to(self, path: str):
        if self.has_valid_closed_pristine(getattr(self, 'settings', None)):
            shutil.copyfile(self._closed_state.byte_path, path)
            return
        self.materialize().save_to(path)

    def save(self):
        with open(self.filepath, 'wb') as stream:
            stream.write(self.render_bytes())


class _StagedFOMMap(MutableMapping):
    """Internal staged-source map that defers materialization for spilled FOMs."""

    def __init__(self, entries=None, *, spool=None, owned_loader=None):
        self._entries = dict(entries or {})
        self._spool = spool
        self._owned_loader = owned_loader
        self._workspace = None
        self._exposed = set()

    def _raw_entries(self):
        return self._entries

    def _bind_workspace(self, workspace):
        self._workspace = workspace

    def _find_key(self, path):
        if path in self._entries:
            return path
        norm = os.path.normcase(os.path.normpath(path)).replace('\\', '/')
        for k in self._entries:
            if os.path.normcase(os.path.normpath(k)).replace('\\', '/') == norm:
                return k
        return path

    def __getitem__(self, path):
        if self._workspace is not None:
            resolved = self._workspace.fom_cache._path(path)
            if resolved in self._workspace.fom_cache._files:
                return self._workspace.get_fom(resolved)
        key = self._find_key(path)
        entry = self._entries[key]
        if isinstance(entry, SpilledFOM):
            fom = entry.materialize()
            self._entries[key] = fom
            self._exposed.add(key)
            return fom
        return entry

    def __setitem__(self, path, fom):
        key = self._find_key(path)
        self._entries[key] = fom
        self._exposed.add(key)
        if self._workspace is not None:
            self._workspace.register_fom(key, fom)

    def __delitem__(self, path):
        key = self._find_key(path)
        del self._entries[key]
        self._exposed.discard(key)
        if self._workspace is not None:
            resolved = self._workspace.fom_cache._path(path)
            if resolved in self._workspace.fom_cache._files:
                del self._workspace.fom_cache[resolved]

    def __iter__(self):
        return iter(self._entries)

    def __len__(self):
        return len(self._entries)

    def __contains__(self, path):
        key = self._find_key(path)
        if key in self._entries:
            return True
        if self._workspace is not None:
            resolved = self._workspace.fom_cache._path(path)
            return resolved in self._workspace.fom_cache._files
        return False

    def keys(self):
        return self._entries.keys()

    def copy(self):
        return {k: self[k] for k in self._entries}

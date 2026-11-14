"""Durable completion receipts for managed built-in actions."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
import re
from bisect import bisect_right
from itertools import islice

from rule_framework.fom import FOMBase

RECEIPTS_FILENAME = '.rule-framework-actions.json'


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _json_reads(action, fom):
    """Resolve the inputs a stock JSON operation reads in the current document."""
    from rule_framework.actions import ModifyAction, JsonRemoveAction
    from rule_framework.fom import JSONFileFOM
    from rule_framework.text_json import json_spans, validate_text_operation
    if type(fom) is not JSONFileFOM:
        return None
    if type(action) is JsonRemoveAction:
        return {('value', tuple(action.path))}
    if type(action) is not ModifyAction:
        return None
    validate_text_operation(action.search, action.replace, action.is_regex, action.count)
    # Track the selected effect's JSON paths, including contextual regexes.
    # Replay also requires the unchanged final document; earlier writes that
    # restore a selected input are checked separately before reusing its receipt.
    fom.validate()
    root = json_spans(fom.content)
    nodes = []
    decoder = json.JSONDecoder()

    def visit(span, path, parent):
        index = len(nodes)
        nodes.append((span.start, span.end, ('value', path), parent))
        keys = [key for key, _ in span.children]
        if len(keys) != len(set(keys)):
            raise ValueError('Ambiguous JSON receipt input')
        for key, child in span.children:
            child_path = path + (key,)
            if isinstance(span.value, dict):
                _, end = decoder.raw_decode(fom.content, child.entry_start)
                nodes.append((child.entry_start, end, ('key', child_path), index))
            visit(child, child_path, index)

    try:
        visit(root, (), None)
    except ValueError:
        return None
    starts = [node[0] for node in nodes]
    pattern = action.search if action.is_regex else re.escape(action.search)
    reads = set()
    matches = re.finditer(pattern, fom.content)
    if action.count:
        matches = islice(matches, action.count)
    for match in matches:
        index = bisect_right(starts, match.start()) - 1
        if index < 0:
            return None
        while nodes[index][1] < match.end() or nodes[index][1] <= match.start():
            index = nodes[index][3]
            if index is None:
                return None
        reads.add(nodes[index][2])
    # Cross-token text edits retain the existing whole-document contract.
    return None if ('value', ()) in reads else reads


def _json_inputs_changed(reads, writes):
    for read_kind, read_path in reads:
        for write_kind, write_path in writes:
            if read_kind == 'key':
                if (read_path[:len(write_path)] == write_path
                        and (len(write_path) < len(read_path) or write_kind == 'all')):
                    return True
            elif (read_path[:len(write_path)] == write_path
                  or write_path[:len(read_path)] == read_path):
                return True
    return False


def _declaration_value(value):
    """Type-tag declarations so bytes and user JSON objects never collide."""
    if isinstance(value, bytes):
        return ['bytes', _digest(value)]
    if isinstance(value, dict):
        pairs = [(_declaration_value(key), _declaration_value(item)) for key, item in value.items()]
        return ['dict', sorted(pairs, key=lambda pair: json.dumps(pair[0], sort_keys=True))]
    if isinstance(value, (list, tuple)):
        return [type(value).__name__, [_declaration_value(item) for item in value]]
    if value is None or isinstance(value, (str, bool, int, float)):
        return [type(value).__name__, value]
    # Extension values keep their established action validation. Unstable
    # representations can only prevent reuse, never grant completion.
    return [type(value).__module__ + '.' + type(value).__qualname__, repr(value)]


class ActionReceipts:
    def __init__(self, base_dir, records=None):
        self.base_dir = base_dir
        self.records = records or {}
        self.seen = set()
        self.initial = {}
        self.executed_paths = set()
        self.invalidated_paths = set()
        self.learning = set()
        self.scope = None
        self.task_keys = {}
        self.task_occurrences = {}
        self.json_writes = {}

    @classmethod
    def load(cls, base_dir):
        path = os.path.join(base_dir, RECEIPTS_FILENAME)
        if not os.path.isfile(path):
            return cls(base_dir)
        with open(path, encoding='utf8') as stream:
            value = json.load(stream)
        if (not isinstance(value, dict) or value.get('version') != 1
                or not isinstance(value.get('records'), dict)):
            raise ValueError('Invalid built-in action receipts')
        for key, record in value['records'].items():
            if (not isinstance(key, str) or len(key) != 64
                    or any(c not in '0123456789abcdef' for c in key)
                    or not isinstance(record, dict) or not isinstance(record.get('files'), dict)
                    or not record['files']):
                raise ValueError('Invalid built-in action receipt entry')
            if 'json_reads' in record:
                reads = record['json_reads']
                if (not isinstance(reads, list) or any(
                        not isinstance(item, list) or len(item) != 2
                        or item[0] not in ('value', 'key') or not isinstance(item[1], list)
                        or any(not isinstance(part, str) and (type(part) is not int or part < 0)
                               for part in item[1])
                        or (item[0] == 'key' and (not item[1] or not isinstance(item[1][-1], str)))
                        for item in reads)):
                    raise ValueError('Invalid built-in action JSON dependencies')
            if 'post' in record and (not isinstance(record['post'], dict)
                                     or set(record['post']) != set(record['files'])):
                raise ValueError('Invalid built-in action receipt post fingerprint')
            stages = record.get('stages', [])
            if (not isinstance(stages, list) or any(
                    not isinstance(stage, dict) or set(stage) != set(record['files'])
                    for stage in stages)):
                raise ValueError('Invalid built-in action receipt stage fingerprint')
            fingerprints = list(record['files'].items()) + list(record.get('post', {}).items())
            fingerprints += [item for stage in stages for item in stage.items()]
            for path, digest in fingerprints:
                if (not isinstance(path, str) or not path or '\0' in path or ':' in path
                        or os.path.isabs(path) or '..' in path.replace('\\', '/').split('/')
                        or not isinstance(digest, str) or len(digest) != 64
                        or any(c not in '0123456789abcdef' for c in digest)):
                    raise ValueError('Invalid built-in action receipt fingerprint')
        return cls(base_dir, value['records'])

    def snapshot(self):
        return deepcopy((self.records, self.seen, self.initial, self.executed_paths, self.invalidated_paths, self.learning, self.json_writes))

    def restore(self, state):
        (self.records, self.seen, self.initial, self.executed_paths,
         self.invalidated_paths, self.learning, self.json_writes) = deepcopy(state)

    @contextmanager
    def action_scope(self, task, action, target):
        previous = self.scope
        declarations = [_declaration_value(item.definition) for item in task.actions]
        if task.id not in self.task_keys:
            signature = _digest(json.dumps(_declaration_value(
                (task.patterns, task.source_ids, declarations)), sort_keys=True).encode('utf8'))
            occurrence = self.task_occurrences.get(signature, 0)
            self.task_occurrences[signature] = occurrence + 1
            self.task_keys[task.id] = (signature, occurrence)
        # Equal declarations are separate intentional actions. Their ordinal
        # counts only equal declarations, so unrelated positions are irrelevant.
        declaration = _declaration_value(action.definition)
        occurrence = 0
        for item, value in zip(task.actions, declarations):
            if item.id == action.id:
                break
            if value == declaration:
                occurrence += 1
        self.scope = (self.task_keys[task.id], occurrence, action.definition)
        try:
            yield
        finally:
            self.scope = previous

    def _relative(self, path):
        return os.path.relpath(os.path.realpath(path), os.path.realpath(self.base_dir)).replace('\\', '/')

    def _current(self, workspace, relative):
        path = workspace.resolve_path(relative)
        key = workspace.fom_cache._path(path)
        if key in workspace.fom_cache._files:
            # Spilled entries render through a temporary model and keep the
            # workspace's bounded working set intact.
            return _digest(workspace.fom_cache._files[key].render_bytes())
        if os.path.isfile(path):
            with open(path, 'rb') as stream:
                return _digest(stream.read())
        return None

    def _json_completion_proof(self, action, fom, workspace, target, record):
        """Recognize an actual prior output without executing a managed action."""
        from rule_framework.actions import ModifyAction, JsonRemoveAction
        from rule_framework.fom import _apply_text_replacement
        from rule_framework.text_json import encode_text, load_json, remove_json_path
        post = record.get('post')
        if not post or target not in post:
            return None
        current = {path: self._current(workspace, path) for path in post}
        if current == post:
            return True
        try:
            fom.validate()
            if type(action) is ModifyAction:
                content, _ = _apply_text_replacement(fom.content, action.search, action.replace,
                                                      action.is_regex, action.count)
            elif type(action) is JsonRemoveAction:
                content = remove_json_path(fom.content, action.path)
            else:
                return None
            load_json(content)
            candidate = dict(current)
            candidate[target] = _digest(encode_text(content, fom.text_encoding, fom.text_bom))
        except (ValueError, TypeError, UnicodeError):
            return None
        return False if candidate == post else None

    def execute(self, action, ctx):
        workspace = ctx.workspace
        target = self._relative(ctx.fom.filepath)
        declaration = self.scope or (type(action).__name__, getattr(action, '_declaration', {}))
        identity = _digest(json.dumps(_declaration_value((declaration, target)), sort_keys=True,
                                      ensure_ascii=False).encode('utf8'))
        hook = type(action).__name__ == 'CustomHookAction'
        json_reads = _json_reads(action, ctx.fom)
        record = self.records.get(identity)
        replay = False
        if record is not None:
            for path in record['files']:
                workspace._record_access(workspace.fom_cache._path(workspace.resolve_path(path)), expose=False)
                if path not in self.initial:
                    self.initial[path] = self._current(workspace, path)
            replay = (not self.invalidated_paths.intersection(record['files'])
                      and all(self.initial[path] == digest for path, digest in record['files'].items()))
            if replay and json_reads is not None and 'json_reads' in record:
                json_reads = {(kind, tuple(path)) for kind, path in record['json_reads']}
            # Native actions replay for intermediate observers. JSON value/key
            # operations retain their selected input paths across runs; other
            # text operations retain their existing byte-state witnesses.
            if json_reads is not None:
                completed_state = not _json_inputs_changed(json_reads, self.json_writes.get(target, ()))
                if replay:
                    proof = self._json_completion_proof(action, ctx.fom, workspace, target, record)
                    if proof is not None:
                        completed_state = proof
            elif not self.executed_paths.intersection(record['files']):
                completed_state = True
            else:
                stages = record.get('stages', [])
                if 'post' in record:
                    stages = [record['post'], *stages]
                completed_state = any(all(self._current(workspace, path) == digest
                                          for path, digest in stage.items())
                                      for stage in stages)
            if replay and action.requires_completion_receipt and completed_state:
                if json_reads is not None and 'json_reads' not in record:
                    record['json_reads'] = [[kind, list(path)] for kind, path in sorted(json_reads, key=repr)]
                self.seen.add(identity)
                return
        if target not in self.initial:
            try:
                self.initial[target] = self._current(workspace, target)
            except ValueError:
                self.initial[target] = None
        hook_before = {}
        if hook:
            for path in workspace._escaped_paths:
                if path in workspace.fom_cache._files:
                    relative = self._relative(path)
                    hook_before[relative] = self._hook_fingerprint(workspace, relative)
        action_before = {} if hook else {
            path: self._hook_fingerprint(workspace, path)
            for path in ({target} | set(record['files'] if record else ()))
        }
        from rule_framework.actions import JsonSetAction, JsonRemoveAction
        from rule_framework.fom import JSONFileFOM
        json_write = None
        if type(ctx.fom) is JSONFileFOM and type(action) in (JsonSetAction, JsonRemoveAction):
            json_path = tuple(action.path)
            json_write = ('value', json_path)
            if type(action) is JsonRemoveAction:
                json_write = ('value', json_path[:-1]) if json_path and isinstance(json_path[-1], int) else ('all', json_path)
        action.execute(ctx)
        paths = {self._relative(p) for p in (workspace._action_paths or ())}
        paths.add(target)
        if hook:
            paths.update(hook_before)
            paths = {path for path in paths
                     if path not in hook_before or self._hook_fingerprint(workspace, path) != hook_before[path]}
            for key, item in list(self.records.items()):
                if paths.intersection(item['files']):
                    self.records.pop(key)
                    self.seen.discard(key)
                    self.learning.discard(key)
            for path in paths:
                self.initial.pop(path, None)
                self.json_writes.pop(path, None)
        else:
            # Trusted native replay still executes for intermediate observers,
            # while retaining its original evidence and stable on-disk metadata.
            if not replay:
                record_entry = {
                    'files': {path: '' for path in paths},
                    'post': {path: self._current(workspace, path) for path in paths}
                }
                if json_reads is not None:
                    record_entry['json_reads'] = [[kind, list(path)] for kind, path in sorted(json_reads, key=repr)]
                if action.requires_completion_receipt and json_reads is None:
                    self.learning.add(identity)
                self.records[identity] = record_entry
            self.seen.add(identity)
        changed = paths if hook else {
            path for path in paths
            if path not in action_before or self._hook_fingerprint(workspace, path) != action_before[path]
        }
        self.executed_paths.update(changed)
        if not hook and target in changed:
            writes = self.json_writes.setdefault(target, set())
            if json_write is not None:
                writes.add(json_write)
            elif json_reads is not None:
                writes.update(('all', path[:-1]) if kind == 'key' else (kind, path)
                              for kind, path in json_reads)
            else:
                writes.add(('all', ()))
        if hook or not replay:
            self.invalidated_paths.update(changed)
        if not hook:
            for key in self.learning:
                item = self.records[key]
                if changed.intersection(item['files']):
                    stage = {path: self._current(workspace, path) for path in item['files']}
                    if stage != item['post'] and stage not in item.get('stages', []):
                        item.setdefault('stages', []).append(stage)

    def _hook_fingerprint(self, workspace, path):
        try:
            return self._current(workspace, path)
        except Exception:
            # Hook extension adapters may have no renderer; the normal Task
            # validator retains responsibility for malformed Hook state.
            return object()

    def as_adapter(self, workspace):
        records = {}
        for key in sorted(self.records):
            files = {p: self._current(workspace, p) for p in self.records[key]['files']}
            if (all(value is not None for value in files.values())
                    and (key in self.seen or files == self.records[key]['files'])):
                records[key] = {'files': files}
                if 'json_reads' in self.records[key]:
                    records[key]['json_reads'] = self.records[key]['json_reads']
                if 'post' in self.records[key]:
                    records[key]['post'] = self.records[key]['post']
                if 'stages' in self.records[key]:
                    records[key]['stages'] = self.records[key]['stages']
        return ReceiptsAdapter(os.path.join(self.base_dir, RECEIPTS_FILENAME), records)


class ReceiptsAdapter(FOMBase):
    def __init__(self, filepath, records):
        self.filepath = filepath
        self.records = records
        self.is_dirty = True

    def render_bytes(self):
        return (json.dumps({'version': 1, 'records': self.records}, sort_keys=True, indent=2) + '\n').encode('utf8')

    def save_to(self, path):
        from rule_framework.managed_io import ensure_framework_io
        ensure_framework_io('ReceiptsAdapter.save_to()')
        with open(path, 'wb') as stream:
            stream.write(self.render_bytes())

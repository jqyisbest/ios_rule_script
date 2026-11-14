"""Bind acquired candidates to the first Task that consumes them."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import logging
import os
import hashlib
from ruamel.yaml.error import YAMLError

from rule_framework.sources import SourceStatus, stage_source_content
from rule_framework.fom import FOMBase


class _AcceptedSourceBytes(FOMBase):
    """Preserve an unparsable prior copy without granting it new editing semantics."""

    transaction_fields = FOMBase.transaction_fields + ('_accepted_bytes',)

    def __init__(self, path, raw):
        self.filepath = path
        self._accepted_bytes = raw
        self._accepted_digest = hashlib.sha256(raw).digest()
        self.is_dirty = False

    def validate(self):
        super().validate()
        if (not isinstance(self._accepted_bytes, bytes)
                or hashlib.sha256(self._accepted_bytes).digest() != self._accepted_digest):
            raise ValueError('Restored source bytes must remain unchanged')

    def render_bytes(self):
        self.validate()
        return self._accepted_bytes


class SourceAdmission:
    def __init__(self, context, workspace):
        self.context = context
        self.workspace = workspace
        self.pending = {workspace.fom_cache._path(p): original
                        for p, original in getattr(context, 'prior_files', {}).items()}
        self.claimed = None
        for path, digest in getattr(context, 'rejected_new_files', {}).items():
            key = workspace.fom_cache._path(path)
            workspace._pending_deletions[key] = digest
            workspace.missing_source_targets.add(key)
            self.pending.pop(key, None)

    def claim(self, path):
        if self.claimed is not None and path in self.pending:
            self.claimed.add(path)

    @contextmanager
    def task(self, result, resolve_targets):
        self.claimed = set()
        try:
            targets = []
            if self.pending:
                if result.task.validation_error:
                    for pattern in result.task.patterns:
                        try:
                            resolved, _ = resolve_targets(replace(result.task, patterns=(pattern,)))
                            targets.extend(resolved)
                        except (ValueError, OSError):
                            # The runner reports the declaration error locally;
                            # valid peer targets still join admission rollback.
                            continue
                else:
                    targets, _ = resolve_targets(result.task)
            for target in targets:
                self.claim(self.workspace.fom_cache._path(target.path))
            yield
        finally:
            claimed, self.claimed = self.claimed, None
            for path in claimed:
                original = self.pending.pop(path)
                if result.status != 'success':
                    self._restore(path, original)

    def _restore(self, path, original):
        workspace = self.workspace
        raw = original.read_bytes()
        if raw is not None:
            try:
                fom = stage_source_content(path, raw, settings=workspace.settings,
                                           base_dir=workspace.base_dir)
            except (ValueError, YAMLError):
                # A prior disk copy may predate today's parser/validation contract.
                # Rollback must still preserve its exact bytes and earlier Tasks.
                fom = _AcceptedSourceBytes(path, raw)
            current = workspace.fom_cache._files.get(path)
            if path in workspace._escaped_paths and type(current) is type(fom):
                current.restore_state(fom.snapshot_state())
            else:
                workspace._register_fom(path, fom, expose=False)
        else:
            if path in workspace.fom_cache._files:
                del workspace.fom_cache[path]
                # Framework admission rollback restores the original absence,
                # including the candidate's managed registration.
                workspace.fom_cache._registered_paths.discard(path)
            workspace.missing_source_targets.add(path)
            if os.path.isfile(path):
                with open(path, 'rb') as stream:
                    workspace._pending_deletions[path] = hashlib.sha256(stream.read()).hexdigest()
        self._restore_manifest(path, original.existed)
        logging.getLogger('RuleFramework').warning(
            'Task source admission rolled back to accepted state: %s', path)

    def _restore_manifest(self, path, existed):
        context = self.context
        manifest = context.manifest
        if manifest is None:
            return
        relative = os.path.relpath(path, self.workspace.base_dir).replace('\\', '/')
        prior = context.prior_manifest or {'targets': {}, 'sources': {}}
        current = manifest.targets.get(relative, {})
        source_id = current.get('source_id')
        previous = prior['targets'].get(relative)
        if previous is None:
            manifest.targets.pop(relative, None)
            if source_id in manifest.sources:
                manifest.sources[source_id]['targets'] = [
                    p for p in manifest.sources[source_id]['targets'] if p != relative]
        else:
            manifest.targets[relative] = deepcopy(previous)
        if source_id in manifest.sources:
            source = manifest.sources[source_id]
            versions = {v.get('last_version') for v in manifest.targets.values()
                        if v.get('source_id') == source_id}
            old_source = prior['sources'].get(source_id, {})
            source['last_version'] = (next(iter(versions)) if len(versions) == 1
                                      else old_source.get('last_version'))
            source['last_status'] = old_source.get('last_status')
        for index, result in enumerate(context.source_results):
            if result.target == relative:
                context.source_results[index] = replace(
                    result, status=(SourceStatus.USING_REPOSITORY_COPY if existed
                                    else SourceStatus.MISSING),
                    version=previous.get('last_version') if previous else None,
                    reason='Task source admission rolled back')

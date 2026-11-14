"""Recoverable multi-file saves, separate from in-memory Task rollback."""
from contextlib import nullcontext
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import logging
import os

from rule_framework.managed_io import ensure_framework_io

logger = logging.getLogger('RuleFramework')
RECOVERY_DIRECTORY = '.rule-framework-save'


@dataclass(frozen=True)
class ManagedDeletion:
    """Remove only the expected candidate, with the save journal's rollback."""
    expected_sha256: str

    def __post_init__(self):
        if (not isinstance(self.expected_sha256, str) or len(self.expected_sha256) != 64
                or any(c not in '0123456789abcdef' for c in self.expected_sha256)):
            raise ValueError('Managed deletion requires a SHA-256 digest')


def _stage_deletion(entry, adapter):
    if not isinstance(adapter, ManagedDeletion):
        return False
    if entry['old_sha256'] != adapter.expected_sha256:
        raise ValueError(f'Deletion target differs from expected candidate: {entry["target"]}')
    entry['delete'] = True
    entry['changed'] = True
    return True


@dataclass(frozen=True)
class SaveResult:
    status: str
    state: str
    processed_files: tuple[str, ...] = ()
    changed_files: tuple[str, ...] = ()
    recovery_path: str | None = None
    reason: str | None = None


class SaveStorage:
    """Filesystem boundary used for durable writes and fault injection."""

    def read_bytes(self, path):
        with open(path, 'rb') as source:
            return source.read()

    def write_bytes(self, path, data):
        ensure_framework_io('SaveStorage.write_bytes()')
        with open(path, 'wb') as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())

    def stage(self, fom, path):
        ensure_framework_io('SaveStorage.stage()')
        render = getattr(fom, 'render_bytes', None)
        if callable(render):
            data = render()
            if not isinstance(data, bytes):
                raise ValueError('render_bytes() must return bytes')
            self.write_bytes(path, data)
        else:
            fom.save_to(path)
            with open(path, 'r+b') as staged:
                os.fsync(staged.fileno())

    def replace(self, source, destination):
        ensure_framework_io('SaveStorage.replace()')
        os.replace(source, destination)
        self.sync_directory(os.path.dirname(destination))

    def mkdir(self, path):
        ensure_framework_io('SaveStorage.mkdir()')
        os.mkdir(path)
        self.sync_directory(os.path.dirname(path))

    def remove(self, path):
        ensure_framework_io('SaveStorage.remove()')
        os.remove(path)
        self.sync_directory(os.path.dirname(path))

    def rmdir(self, path):
        ensure_framework_io('SaveStorage.rmdir()')
        os.rmdir(path)
        self.sync_directory(os.path.dirname(path))

    def sync_directory(self, path):
        # POSIX supports directory fsync. Windows keeps the durable file writes;
        # abrupt host/power loss still depends on the filesystem and device.
        if os.name != 'nt':
            descriptor = os.open(path, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


_STOCK_STORAGE_TYPE = SaveStorage
_STOCK_STORAGE_METHODS = {name: getattr(SaveStorage, name) for name in
                          ('read_bytes', 'write_bytes', 'stage', 'replace', 'mkdir', 'remove', 'rmdir', 'sync_directory')}


def _is_stock_storage(storage):
    return (type(storage) is _STOCK_STORAGE_TYPE and all(
        name not in vars(storage) and getattr(type(storage), name) is implementation
        and getattr(getattr(storage, name), '__func__', None) is implementation
        for name, implementation in _STOCK_STORAGE_METHODS.items()))


def _stream_digest(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        while True:
            block = source.read(65536)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _stream_backup(source, destination):
    digest = hashlib.sha256()
    with open(source, 'rb') as incoming, open(destination, 'wb') as outgoing:
        while True:
            block = incoming.read(65536)
            if not block:
                break
            digest.update(block)
            outgoing.write(block)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    return digest.hexdigest()


def _same_file_bytes(left, right):
    if os.path.getsize(left) != os.path.getsize(right):
        return False
    with open(left, 'rb') as first, open(right, 'rb') as second:
        while True:
            block = first.read(65536)
            if block != second.read(65536):
                return False
            if not block:
                return True


def _restore_streamed(storage, directory, entries):
    plans = []
    # Validate every destination/backup before changing the first file.
    for index, entry in enumerate(entries):
        target = entry['target']
        backup = os.path.join(directory, entry['backup']) if entry['backup'] is not None else None
        if backup is not None and _stream_digest(backup) != entry['old_sha256']:
            raise ValueError(f'Original backup digest differs: {target}')
        exists = os.path.exists(target)
        current_digest = _stream_digest(target) if exists else None
        if current_digest is not None and current_digest not in {entry['old_sha256'], entry['new_sha256']}:
            raise ValueError(f'Destination changed outside this save: {target}')
        if not exists and backup is not None and not entry.get('delete'):
            raise ValueError(f'Existing destination is missing: {target}')
        same = _same_file_bytes(backup, target) if backup is not None and exists else backup is None and not exists
        plans.append((index, entry, backup, same))
    for index, entry, backup, same in reversed(plans):
        if same:
            continue
        if backup is None:
            storage.remove(entry['target'])
        else:
            pending = os.path.join(directory, f'{index}.restore.tmp')
            if _stream_backup(backup, pending) != entry['old_sha256']:
                raise ValueError(f'Original backup changed during restoration: {entry["target"]}')
            storage.replace(pending, entry['target'])


def _recovery_directory(base_dir):
    try:
        path = os.fspath(base_dir)
    except TypeError as error:
        raise ValueError('Save root must be a non-empty text directory path') from error
    if not isinstance(path, str) or not path.strip() or '\0' in path or not os.path.isdir(path):
        raise ValueError('Save root must be an existing non-empty text directory path')
    return os.path.join(os.path.abspath(path), RECOVERY_DIRECTORY)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _journal_path(directory):
    return os.path.join(directory, 'journal.json')


def _write_journal(storage, directory, journal):
    pending = os.path.join(directory, 'journal.tmp')
    storage.write_bytes(pending, json.dumps(journal, ensure_ascii=False, indent=2).encode('utf-8'))
    storage.replace(pending, _journal_path(directory))


def _read_journal(storage, directory):
    path = _journal_path(directory)
    pending = not os.path.exists(path)
    if pending:
        path = os.path.join(directory, 'journal.tmp')
        if not os.path.isfile(path):
            raise ValueError('Recovery directory has no recognized journal; preserve its files for inspection')
    journal = json.loads(storage.read_bytes(path))
    if pending and (not isinstance(journal, dict) or journal.get('state') != 'staging'):
        raise ValueError('Initial pending journal requires inspection')
    if (not isinstance(journal, dict) or journal.get('version') != 1
            or journal.get('state') not in {'staging', 'replacing', 'restored', 'saved'}
            or not isinstance(journal.get('entries'), list)
            or not isinstance(journal.get('directories'), list)):
        raise ValueError('Unrecognized save recovery journal; preserve it for inspection')
    seen = set()
    for index, entry in enumerate(journal['entries']):
        if (not isinstance(entry, dict) or not isinstance(entry.get('target'), str)
                or not os.path.isabs(entry['target']) or '\0' in entry['target']
                or entry.get('stage') != f'{index}.tmp'
                or entry.get('backup') not in (None, f'{index}.backup')
                or not isinstance(entry.get('changed'), bool)):
            raise ValueError('Invalid file entry in save recovery journal')
        target = os.path.normcase(os.path.abspath(entry['target']))
        if target in seen:
            raise ValueError('Repeated target in save recovery journal')
        seen.add(target)
        for field in ('old_sha256', 'new_sha256'):
            value = entry.get(field)
            if value is not None and (not isinstance(value, str) or len(value) != 64
                                      or any(char not in '0123456789abcdef' for char in value)):
                raise ValueError('Invalid content digest in save recovery journal')
        if entry['backup'] is not None and entry.get('old_sha256') is None:
            raise ValueError('Missing original digest in save recovery journal')
        if 'delete' in entry and (entry['delete'] is not True or entry.get('backup') is None or entry.get('new_sha256') is not None):
            raise ValueError('Invalid deletion entry in save recovery journal')
        if journal['state'] in {'replacing', 'saved'} and entry.get('new_sha256') is None and not entry.get('delete'):
            raise ValueError('Missing staged digest in save recovery journal')
    for path in journal['directories']:
        if (not isinstance(path, str) or not os.path.isabs(path)
                or not any(os.path.normcase(os.path.commonpath((path, entry['target']))) == os.path.normcase(os.path.normpath(path))
                           and path != entry['target'] for entry in journal['entries'])):
            raise ValueError('Invalid directory entry in save recovery journal')
    _assert_known_recovery_files(directory, journal)
    return journal


def _assert_known_recovery_files(directory, journal):
    owned = {'journal.json', 'journal.tmp'}
    for index, entry in enumerate(journal['entries']):
        owned.update((entry['stage'], f'{index}.backup', f'{index}.restore.tmp'))
    unknown = set(os.listdir(directory)) - owned
    if unknown:
        raise ValueError(f'Unrecognized recovery files: {sorted(unknown)}')
    return owned


def _cleanup(storage, directory, journal, *, remove_new_directories):
    owned = _assert_known_recovery_files(directory, journal)
    if remove_new_directories:
        for path in sorted(journal['directories'], key=len, reverse=True):
            if os.path.isdir(path):
                storage.rmdir(path)
    for name in sorted(owned - {'journal.json'}):
        path = os.path.join(directory, name)
        if os.path.lexists(path):
            storage.remove(path)
    if os.path.lexists(_journal_path(directory)):
        storage.remove(_journal_path(directory))
    storage.rmdir(directory)


def recover_saved_files(base_dir, *, storage=None, dry_run=False):
    """Restore an interrupted replacement, or finish known-safe cleanup.

    A saved journal retains the new products. A replacing journal restores the
    prior products. Unexpected destination bytes retain the journal for review.
    """
    if not dry_run:
        ensure_framework_io('recover_saved_files()')
    storage = storage or SaveStorage()
    try:
        directory = _recovery_directory(base_dir)
    except ValueError as error:
        return SaveResult('failed', 'unchanged', reason=str(error))
    if not os.path.lexists(directory):
        return SaveResult('success', 'not_needed')
    if dry_run:
        return SaveResult('failed', 'recovery_required', recovery_path=directory,
                          reason='Pending save recovery requires a write-enabled recovery run')
    state = 'recovery_required'
    try:
        if os.path.islink(directory) or not os.path.isdir(directory):
            raise ValueError('Recovery path must be a regular directory')
        if not os.listdir(directory):
            storage.rmdir(directory)
            return SaveResult('success', 'cleanup_complete')
        journal = _read_journal(storage, directory)
        entries = journal['entries']
        if journal['state'] == 'replacing':
            if _is_stock_storage(storage):
                _restore_streamed(storage, directory, entries)
            else:
                # Check the entire batch before restoring any destination.
                originals = {}
                for entry in entries:
                    target = entry['target']
                    original = None
                    if entry['backup'] is not None:
                        original = storage.read_bytes(os.path.join(directory, entry['backup']))
                        if _digest(original) != entry['old_sha256']:
                            raise ValueError(f'Original backup digest differs: {target}')
                    current = storage.read_bytes(target) if os.path.exists(target) else None
                    if current is not None and _digest(current) not in {
                            entry['old_sha256'], entry['new_sha256']}:
                        raise ValueError(f'Destination changed outside this save: {target}')
                    if current is None and original is not None and not entry.get('delete'):
                        raise ValueError(f'Existing destination is missing: {target}')
                    originals[target] = (original, current)
                for index, entry in reversed(list(enumerate(entries))):
                    original, current = originals[entry['target']]
                    if current == original:
                        continue
                    if original is None:
                        storage.remove(entry['target'])
                    else:
                        restore = os.path.join(directory, f'{index}.restore.tmp')
                        storage.write_bytes(restore, original)
                        storage.replace(restore, entry['target'])
            journal['state'] = 'restored'
            _write_journal(storage, directory, journal)
        if journal['state'] in {'saved', 'restored'}:
            digest_field = 'new_sha256' if journal['state'] == 'saved' else 'old_sha256'
            for entry in entries:
                current = storage.read_bytes(entry['target']) if os.path.exists(entry['target']) else None
                digest = _digest(current) if current is not None else None
                if digest != entry[digest_field]:
                    raise ValueError(f'Completed destination changed outside this save: {entry["target"]}')
        state = 'restored' if journal['state'] == 'restored' else (
            'saved' if journal['state'] == 'saved' else 'unchanged')
        _cleanup(storage, directory, journal, remove_new_directories=state != 'saved')
        logger.info('Save recovery completed: state=%s', state)
        return SaveResult('success', state)
    except Exception as error:
        logger.error('Save recovery requires attention: state=%s journal=%s reason=%s',
                     state, directory, error)
        return SaveResult('failed', state, recovery_path=directory, reason=str(error))


def save_managed_files(foms, *, base_dir, storage=None, context=None):
    """Stage validated FOMs and persist recovery evidence before replacement."""
    ensure_framework_io('save_managed_files()')
    storage = storage or SaveStorage()
    try:
        directory = _recovery_directory(base_dir)
    except ValueError as error:
        return SaveResult('failed', 'unchanged', reason=str(error))
    if os.path.lexists(directory):
        return SaveResult('failed', 'recovery_required', recovery_path=directory,
                          reason='Pending recovery must complete before saving')
    if not isinstance(foms, Mapping):
        return SaveResult('failed', 'unchanged', reason='Managed files must be a mapping')
    paths = tuple(foms)
    if any(not isinstance(path, str) or not os.path.isabs(path) or '\0' in path for path in paths):
        return SaveResult('failed', 'unchanged', reason='Managed file paths must be absolute text paths')
    if any(not isinstance(foms[path], ManagedDeletion) and not callable(getattr(foms[path], 'save_to', None)) for path in paths):
        return SaveResult('failed', 'unchanged', reason='Managed files require FOM adapters')
    # Atomic replacement targets a directory entry. Resolve file aliases once
    # so saved bytes and recovery journals refer to the same physical file.
    destinations, identities = {}, set()
    for path in paths:
        physical = os.path.realpath(path)
        identity = os.path.normcase(physical)
        if identity in identities:
            return SaveResult('failed', 'unchanged', reason=f'Repeated physical save destination: {path}')
        identities.add(identity)
        if os.path.lexists(path + '.tmp'):
            return SaveResult('failed', 'unchanged', reason=f'Temporary path already exists: {path}.tmp')
        destination = path if os.path.normcase(os.path.normpath(path)) == identity else (
            physical.replace('\\', '/') if '/' in path else physical)
        destinations[destination] = foms[path]
    foms = destinations
    paths = tuple(foms)
    for path in paths:
        try:
            overlaps_recovery = os.path.normcase(os.path.commonpath((os.path.realpath(directory), os.path.realpath(path)))) == os.path.normcase(os.path.realpath(directory))
        except ValueError:
            overlaps_recovery = False
        if overlaps_recovery:
            return SaveResult('failed', 'unchanged', reason=f'Managed output overlaps the reserved recovery directory: {path}')

    is_stock_storage = _is_stock_storage(storage)
    entries, originals, directories = [], {}, set()
    journal = None
    if not paths:
        return SaveResult('success', 'no_changes')
    try:
        if is_stock_storage:
            for index, target in enumerate(paths):
                if os.path.lexists(target + '.tmp'):
                    raise FileExistsError(f'Temporary path already exists: {target}.tmp')
                exists = os.path.exists(target)
                entries.append({'target': target, 'stage': f'{index}.tmp',
                                'backup': f'{index}.backup' if exists else None,
                                'old_sha256': _stream_digest(target) if exists else None,
                                'new_sha256': None, 'changed': False})
                parent = os.path.dirname(target)
                while not os.path.exists(parent):
                    directories.add(parent)
                    parent = os.path.dirname(parent)
            storage.mkdir(directory)
            journal = {'version': 1, 'state': 'staging', 'entries': entries,
                       'directories': sorted(directories, key=len)}
            _write_journal(storage, directory, journal)
            # Persist all originals before invoking any adapter's staging callbacks.
            for entry in entries:
                if entry['backup'] is not None:
                    backup = os.path.join(directory, entry['backup'])
                    if _stream_backup(entry['target'], backup) != entry['old_sha256']:
                        raise ValueError(f'Original changed during save snapshot: {entry["target"]}')
            for entry in entries:
                target = entry['target']
                with context(target) if context else nullcontext():
                    try:
                        stage = os.path.join(directory, entry['stage'])
                        if _stage_deletion(entry, foms[target]):
                            continue
                        storage.stage(foms[target], stage)
                        entry['new_sha256'] = _stream_digest(stage)
                        entry['changed'] = (entry['backup'] is None or not
                            _same_file_bytes(os.path.join(directory, entry['backup']), stage))
                        logger.info('Staged managed file: changed=%s target=%s', entry['changed'], target)
                    except Exception as error:
                        logger.error('Error staging %s: %s', target, error)
                        raise
        else:
            for index, target in enumerate(paths):
                # Respect legacy temporary paths, whose ownership is unknown.
                if os.path.lexists(target + '.tmp'):
                    raise FileExistsError(f'Temporary path already exists: {target}.tmp')
                original = storage.read_bytes(target) if os.path.exists(target) else None
                originals[target] = original
                entries.append({'target': target, 'stage': f'{index}.tmp',
                                'backup': f'{index}.backup' if original is not None else None,
                                'old_sha256': _digest(original) if original is not None else None,
                                'new_sha256': None, 'changed': False})
                parent = os.path.dirname(target)
                while not os.path.exists(parent):
                    directories.add(parent)
                    parent = os.path.dirname(parent)
            storage.mkdir(directory)
            journal = {'version': 1, 'state': 'staging', 'entries': entries,
                       'directories': sorted(directories, key=len)}
            _write_journal(storage, directory, journal)
            for entry in entries:
                target = entry['target']
                with context(target) if context else nullcontext():
                    try:
                        if entry['backup'] is not None:
                            storage.write_bytes(os.path.join(directory, entry['backup']), originals[target])
                        stage = os.path.join(directory, entry['stage'])
                        if _stage_deletion(entry, foms[target]):
                            continue
                        storage.stage(foms[target], stage)
                        data = storage.read_bytes(stage)
                        entry['new_sha256'] = _digest(data)
                        entry['changed'] = data != originals[target]
                        logger.info('Staged managed file: changed=%s target=%s', entry['changed'], target)
                    except Exception as error:
                        logger.error('Error staging %s: %s', target, error)
                        raise
        journal['state'] = 'replacing'
        _write_journal(storage, directory, journal)
        for path in journal['directories']:
            if not os.path.isdir(path):
                storage.mkdir(path)
        for entry in entries:
            with context(entry['target']) if context else nullcontext():
                if entry['changed']:
                    try:
                        if entry.get('delete'):
                            current = storage.read_bytes(entry['target'])
                            if _digest(current) != entry['old_sha256']:
                                raise ValueError(f'Deletion target changed during save: {entry["target"]}')
                            storage.remove(entry['target'])
                        else:
                            storage.replace(os.path.join(directory, entry['stage']), entry['target'])
                    except Exception as error:
                        logger.error('Error replacing %s: %s', entry['target'], error)
                        raise
                logger.info('Successfully processed %s', entry['target'])
        journal['state'] = 'saved'
        _write_journal(storage, directory, journal)
        changed = tuple(entry['target'] for entry in entries if entry['changed'])
        _cleanup(storage, directory, journal, remove_new_directories=False)
        return SaveResult('success', 'saved' if changed else 'no_changes', paths, changed)
    except Exception as error:
        logger.error('Managed save failed: %s', error)
        recovery = recover_saved_files(base_dir, storage=storage)
        state = recovery.state if recovery.state != 'not_needed' else 'unchanged'
        if journal and journal['state'] == 'saved':
            try:
                if all(_digest(storage.read_bytes(entry['target'])) == entry['new_sha256'] for entry in entries):
                    state = 'saved'
            except Exception:
                pass
        return SaveResult('failed', state,
                          processed_files=paths if state == 'saved' else (),
                          changed_files=tuple(entry['target'] for entry in entries if entry['changed'])
                          if state == 'saved' else (),
                          recovery_path=recovery.recovery_path,
                          reason=f'{error}' + (f'; recovery: {recovery.reason}' if recovery.reason else ''))

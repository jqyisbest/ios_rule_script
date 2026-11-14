"""Private bare Git object and version backing store for managed states."""
import hashlib
import json
import logging
import os
import pickle
import tempfile
import zlib
from typing import Any, Optional

logger = logging.getLogger('RuleFramework')
_PRIVATE_STATE_MAGIC = b'RF_PRIVATE_STATE_V1\n'
_CHUNK_SIZE = 65536


def _is_hex_sha(value: Any) -> bool:
    return (isinstance(value, str)
            and len(value) == 40
            and all(c in '0123456789abcdefABCDEF' for c in value))


class GitStateStore:
    """Owns a private bare Git repository for content-addressed loose objects."""

    def __init__(self, directory: Optional[str] = None):
        if directory is None:
            self._temp_dir = tempfile.TemporaryDirectory(prefix='rule-framework-git-state-')
            self.root = os.path.abspath(self._temp_dir.name)
        else:
            path = os.fspath(directory)
            if not isinstance(path, str) or not path.strip() or '\0' in path:
                raise ValueError('Private Git state directory must be a non-empty text path')
            self.root = os.path.abspath(path)
            if os.path.lexists(self.root) and (os.path.islink(self.root) or not os.path.isdir(self.root)
                                               or os.listdir(self.root)):
                raise ValueError('Private Git state directory must be new or empty')
            self._temp_dir = None
        self.objects_dir = os.path.join(self.root, 'objects')
        self.refs_dir = os.path.join(self.root, 'refs')
        self.heads_dir = os.path.join(self.refs_dir, 'heads')
        self.tags_dir = os.path.join(self.refs_dir, 'tags')
        self._private_state_shas = set()
        self._init_bare_repository()

    def _init_bare_repository(self):
        for path in (self.objects_dir, self.heads_dir, self.tags_dir):
            os.makedirs(path, exist_ok=True)
        head_path = os.path.join(self.root, 'HEAD')
        if not os.path.exists(head_path):
            with open(head_path, 'w', encoding='ascii') as stream:
                stream.write('ref: refs/heads/main\n')
        config_path = os.path.join(self.root, 'config')
        if not os.path.exists(config_path):
            with open(config_path, 'w', encoding='ascii') as stream:
                stream.write(
                    '[core]\n'
                    '\trepositoryformatversion = 0\n'
                    '\tfilemode = false\n'
                    '\tbare = true\n'
                )

    def object_path(self, hex_sha: str) -> str:
        if not _is_hex_sha(hex_sha):
            raise ValueError(f'Invalid Git object hash: {hex_sha!r}')
        hex_sha = hex_sha.lower()
        return os.path.join(self.objects_dir, hex_sha[:2], hex_sha[2:])

    def has_object(self, hex_sha: str) -> bool:
        if not _is_hex_sha(hex_sha):
            return False
        return os.path.isfile(self.object_path(hex_sha))

    def write_loose_object(self, obj_type: str, payload: bytes) -> str:
        """Write a canonical Git loose object with zlib level 1 compression."""
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError('Git object payload must be bytes')
        payload_bytes = bytes(payload)
        header = f'{obj_type} {len(payload_bytes)}\x00'.encode('ascii')
        full_content = header + payload_bytes
        hex_sha = hashlib.sha1(full_content).hexdigest()
        dest_path = self.object_path(hex_sha)
        if os.path.exists(dest_path):
            return hex_sha

        dest_dir = os.path.dirname(dest_path)
        os.makedirs(dest_dir, exist_ok=True)
        compressed = zlib.compress(full_content, level=1)
        temp_file = tempfile.NamedTemporaryFile(dir=self.objects_dir, delete=False)
        temp_path = temp_file.name
        try:
            with temp_file as stream:
                stream.write(compressed)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, dest_path)
        except BaseException:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise
        return hex_sha

    def write_loose_object_from_file(self, obj_type: str, file_path: str, prefix: bytes = b'', compression: int = 1) -> str:
        """Stream a canonical Git loose object directly from an uncompressed file."""
        file_size = os.path.getsize(file_path)
        total_len = len(prefix) + file_size
        header = f'{obj_type} {total_len}\x00'.encode('ascii')

        temp_file = tempfile.NamedTemporaryFile(dir=self.objects_dir, delete=False)
        temp_path = temp_file.name
        compressor = zlib.compressobj(level=compression)
        hasher = hashlib.sha1()

        try:
            hasher.update(header)
            temp_file.write(compressor.compress(header))
            if prefix:
                hasher.update(prefix)
                compressed_prefix = compressor.compress(prefix)
                if compressed_prefix:
                    temp_file.write(compressed_prefix)

            with open(file_path, 'rb') as src:
                while True:
                    chunk = src.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    compressed_chunk = compressor.compress(chunk)
                    if compressed_chunk:
                        temp_file.write(compressed_chunk)

            tail = compressor.flush()
            if tail:
                temp_file.write(tail)
            temp_file.flush()
            os.fsync(temp_file.fileno())
            temp_file.close()

            hex_sha = hasher.hexdigest()
            dest_path = self.object_path(hex_sha)
            if os.path.exists(dest_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            else:
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                os.replace(temp_path, dest_path)
            return hex_sha
        except BaseException:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise

    def read_loose_object(self, hex_sha: str) -> tuple[str, bytes]:
        """Read and verify exact SHA-1 and payload length of a loose object."""
        path = self.object_path(hex_sha)
        if not os.path.isfile(path):
            raise FileNotFoundError(f'Git loose object not found: {hex_sha}')
        with open(path, 'rb') as stream:
            compressed = stream.read()
        try:
            decompressed = zlib.decompress(compressed)
        except zlib.error as error:
            raise ValueError(f'Corrupt Git loose object compression: {hex_sha}') from error

        actual_sha = hashlib.sha1(decompressed).hexdigest()
        if actual_sha != hex_sha.lower():
            raise ValueError(f'Git loose object hash mismatch: expected {hex_sha}, got {actual_sha}')

        null_pos = decompressed.find(b'\x00')
        if null_pos == -1:
            raise ValueError(f'Invalid Git loose object header in {hex_sha}: missing NUL separator')
        header_bytes = decompressed[:null_pos]
        payload = decompressed[null_pos + 1:]
        try:
            header_str = header_bytes.decode('ascii')
            obj_type, len_str = header_str.split(' ')
            expected_len = int(len_str)
        except Exception as error:
            raise ValueError(f'Invalid Git loose object header format in {hex_sha}') from error

        if len(payload) != expected_len:
            raise ValueError(f'Git loose object length mismatch in {hex_sha}: header={expected_len}, actual={len(payload)}')
        return obj_type, payload

    def open_verified_blob_stream(self, hex_sha: str, expected_prefix: bytes = b'') -> Any:
        """Verify framing and inflate in bounded output blocks before exposing any state."""
        if not _is_hex_sha(hex_sha):
            raise ValueError(f'Invalid Git object hash: {hex_sha!r}')
        hex_sha = hex_sha.lower()
        path = self.object_path(hex_sha)
        decompressor = zlib.decompressobj()
        hasher = hashlib.sha1()
        destination = tempfile.NamedTemporaryFile(dir=self.objects_dir, delete=False)
        header = bytearray()
        expected_length = None
        payload_length = 0
        prefix_offset = 0

        def consume(data):
            nonlocal expected_length, payload_length, prefix_offset
            hasher.update(data)
            if expected_length is None:
                boundary = data.find(b'\0')
                header.extend(data if boundary < 0 else data[:boundary])
                if len(header) > 80:
                    raise ValueError('Invalid Git object header length')
                if boundary < 0:
                    return
                fields = bytes(header).split(b' ')
                if len(fields) != 2 or fields[0] != b'blob' or not fields[1].isdigit():
                    raise ValueError('Invalid Git blob header')
                expected_length = int(fields[1])
                data = data[boundary + 1:]
            payload_length += len(data)
            if payload_length > expected_length:
                raise ValueError('Git blob exceeds its declared length')
            if prefix_offset < len(expected_prefix):
                take = min(len(data), len(expected_prefix) - prefix_offset)
                if data[:take] != expected_prefix[prefix_offset:prefix_offset + take]:
                    raise ValueError('Private state magic prefix mismatch')
                prefix_offset += take
                data = data[take:]
            if data:
                destination.write(data)

        try:
            with open(path, 'rb') as source:
                while True:
                    compressed = source.read(_CHUNK_SIZE)
                    if not compressed:
                        break
                    if decompressor.eof:
                        raise ValueError('Trailing bytes after the Git object compression stream')
                    pending = compressed
                    while True:
                        block = decompressor.decompress(pending, _CHUNK_SIZE)
                        consume(block)
                        pending = decompressor.unconsumed_tail
                        if decompressor.unused_data:
                            raise ValueError('Trailing bytes after the Git object compression stream')
                        if not pending and len(block) < _CHUNK_SIZE:
                            break
            if not decompressor.eof:
                raise ValueError('Truncated Git object compression stream')
            if expected_length is None or payload_length != expected_length:
                raise ValueError('Git blob length differs from its header')
            if prefix_offset != len(expected_prefix):
                raise ValueError('Truncated private state prefix')
            if hasher.hexdigest() != hex_sha:
                raise ValueError('Git blob hash mismatch')
            destination.flush()
            destination.seek(0)
            return destination
        except BaseException as error:
            name = destination.name
            destination.close()
            try:
                os.remove(name)
            except FileNotFoundError:
                pass
            if isinstance(error, zlib.error):
                raise ValueError('Corrupt Git object compression stream') from error
            raise

    def store_blob(self, payload: bytes) -> str:
        return self.write_loose_object('blob', payload)

    def read_blob(self, hex_sha: str) -> bytes:
        obj_type, payload = self.read_loose_object(hex_sha)
        if obj_type != 'blob':
            raise ValueError(f'Expected blob object for {hex_sha}, got {obj_type}')
        return payload

    def store_tree(self, entries: dict[str, str]) -> str:
        """Write a standard Git tree object from a dict of {name: hex_sha}."""
        parts = []
        for name in sorted(entries.keys()):
            if not isinstance(name, str) or '/' in name or '\0' in name:
                raise ValueError(f'Invalid tree entry name: {name!r}')
            hex_sha = entries[name]
            if not _is_hex_sha(hex_sha):
                raise ValueError(f'Invalid tree entry hash for {name}: {hex_sha!r}')
            raw_sha = bytes.fromhex(hex_sha)
            parts.append(f'100644 {name}\x00'.encode('utf-8') + raw_sha)
        payload = b''.join(parts)
        return self.write_loose_object('tree', payload)

    def read_tree(self, hex_sha: str) -> dict[str, str]:
        obj_type, payload = self.read_loose_object(hex_sha)
        if obj_type != 'tree':
            raise ValueError(f'Expected tree object for {hex_sha}, got {obj_type}')
        entries = {}
        index = 0
        total = len(payload)
        while index < total:
            space_pos = payload.find(b' ', index)
            if space_pos == -1:
                raise ValueError(f'Malformed tree object {hex_sha}')
            mode = payload[index:space_pos].decode('ascii')
            null_pos = payload.find(b'\x00', space_pos)
            if null_pos == -1:
                raise ValueError(f'Malformed tree object {hex_sha}')
            name = payload[space_pos + 1:null_pos].decode('utf-8')
            raw_sha = payload[null_pos + 1:null_pos + 21]
            if len(raw_sha) != 20:
                raise ValueError(f'Truncated SHA in tree object {hex_sha}')
            entries[name] = raw_sha.hex()
            index = null_pos + 21
        return entries

    def store_commit(self, tree_sha: str, parent_sha: Optional[str] = None,
                     message: str = 'State checkpoint') -> str:
        """Write a standard Git commit object."""
        if not _is_hex_sha(tree_sha):
            raise ValueError(f'Invalid commit tree hash: {tree_sha!r}')
        lines = [f'tree {tree_sha}']
        if parent_sha:
            if not _is_hex_sha(parent_sha):
                raise ValueError(f'Invalid commit parent hash: {parent_sha!r}')
            lines.append(f'parent {parent_sha}')
        lines.append('author RuleFramework <rule_framework@local> 0 +0000')
        lines.append('committer RuleFramework <rule_framework@local> 0 +0000')
        lines.append('')
        lines.append(message.strip())
        lines.append('')
        payload = '\n'.join(lines).encode('utf-8')
        return self.write_loose_object('commit', payload)

    def store_private_state(self, serialized_state: bytes) -> str:
        """Wrap and write native state data. Only these states may be unpickled."""
        envelope = _PRIVATE_STATE_MAGIC + serialized_state
        hex_sha = self.write_loose_object('blob', envelope)
        self._private_state_shas.add(hex_sha)
        return hex_sha

    def store_private_state_from_file(self, file_path: str) -> str:
        """Wrap and write native state data from an uncompressed file."""
        hex_sha = self.write_loose_object_from_file('blob', file_path, prefix=_PRIVATE_STATE_MAGIC, compression=0)
        self._private_state_shas.add(hex_sha)
        return hex_sha

    def read_private_state(self, hex_sha: str) -> bytes:
        """Verify provenance and unwrap native state data as bytes."""
        if hex_sha not in self._private_state_shas:
            raise ValueError(f'Object {hex_sha} was not stored as private state by this process')
        obj_type, payload = self.read_loose_object(hex_sha)
        if obj_type != 'blob' or not payload.startswith(_PRIVATE_STATE_MAGIC):
            raise ValueError(f'Invalid private state envelope for {hex_sha}')
        return payload[len(_PRIVATE_STATE_MAGIC):]

    def open_private_state_stream(self, hex_sha: str) -> Any:
        """Verify provenance and open an uncompressed stream directly to a seekable file."""
        if hex_sha not in self._private_state_shas:
            raise ValueError(f'Object {hex_sha} was not stored as private state by this process')
        return self.open_verified_blob_stream(hex_sha, expected_prefix=_PRIVATE_STATE_MAGIC)

    def write_render_cache(self, raw_bytes: bytes) -> tuple[str, str]:
        """Store raw rendered bytes as a Git blob and return (hex_sha, object_path)."""
        hex_sha = self.store_blob(raw_bytes)
        return hex_sha, self.object_path(hex_sha)

    def close(self):
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
            self._temp_dir = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

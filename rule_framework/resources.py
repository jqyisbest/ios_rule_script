"""Opaque byte resources staged through the same managed Task protocol."""

import os
import logging
import re
import hashlib

logger = logging.getLogger('RuleFramework')

from rule_framework.fom import FOMBase

IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico',
                    '.tif', '.tiff', '.avif', '.heic'}
BINARY_EXTENSIONS = IMAGE_EXTENSIONS | {'.bin', '.pdf', '.zip', '.gz', '.mrs', '.woff', '.woff2', '.mmdb'}
TEXT_EXTENSIONS = {'.js', '.py', '.md', '.json', '.txt', '.svg', '.html', '.css',
                   '.list', '.yaml', '.yml', '.stoverride', '.conf', '.plugin',
                   '.lnplugin', '.lnscript', '.sgmodule', '.snippet', '.qxrewrite'}


def is_binary_resource(filepath, data=None):
    """Known resources or opaque unknown files; labelled text retains its decoder."""
    extension = os.path.splitext(filepath)[1].lower()
    if extension in BINARY_EXTENSIONS:
        return True
    if extension in TEXT_EXTENSIONS:
        return False
    if data is not None:
        raw = data
    elif os.path.isfile(filepath):
        with open(filepath, 'rb') as source:
            raw = source.read()
    else:
        return False
    # BOM-labelled Unicode text is handled by the text adapter before NUL sniffing.
    if raw.startswith((b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff', b'\x00\x00\xfe\xff')):
        return False
    if b'\0' in raw:
        return True
    try:
        raw.decode('utf-8')
    except UnicodeDecodeError:
        return True
    return False


class BinaryResourceFOM(FOMBase):
    """Preserve resource bytes; payload and existence participate in rollback."""

    transaction_fields = FOMBase.transaction_fields + ('payload', 'resource_exists', 'loaded_payload')

    def __init__(self, filepath):
        self.filepath = filepath
        self.payload = b''
        self.loaded_payload = None
        self.resource_exists = False
        self.is_dirty = False

    def load(self):
        with open(self.filepath, 'rb') as source:
            self.payload = source.read()
        self.loaded_payload = self.payload
        self.resource_exists = True
        self.is_dirty = False

    def scaffold(self, base_name):
        # A missing resource has no implicit content or parent directory.
        self.payload = b''
        self.loaded_payload = None
        self.resource_exists = False
        self.is_dirty = False

    def validate(self):
        super().validate()
        if not isinstance(self.payload, bytes):
            raise ValueError('Binary resource payload must be bytes')
        if not isinstance(self.resource_exists, bool):
            raise ValueError('Binary resource existence must be a boolean')
        if self.loaded_payload is not None and not isinstance(self.loaded_payload, bytes):
            raise ValueError('Binary loaded payload must be bytes or None')
        if self.resource_exists and not self.payload and self.loaded_payload != b'':
            raise ValueError('Resource data must be non-empty bytes')

    def render_bytes(self):
        self.validate()
        if not self.resource_exists:
            raise ValueError('Binary resource requires explicit create_resource or copy_resource input')
        return self.payload

    def validate_complete(self):
        """At Task completion every registered resource must have an explicit payload."""
        self.render_bytes()

    def remove_rule(self, rule_type, value=None):
        if not self.resource_exists:
            raise ValueError('Binary resource requires explicit create_resource or copy_resource input')
        if isinstance(rule_type, str) and rule_type.lower() == 'domain':
            logger.info('Binary resource has known-empty domain references: %s', self.filepath)
            return
        raise ValueError('BinaryResourceFOM supports only abstract domain removal as a known-empty reference query')

    def save(self):
        data = self.render_bytes()
        with open(self.filepath, 'wb') as destination:
            destination.write(data)


def validate_resource_target(workspace, path):
    """Require a concrete file within the actual managed project tree."""
    path = workspace.resolve_path(path)
    base = os.path.realpath(workspace.base_dir)
    resolved = os.path.realpath(path)
    try:
        relative = os.path.relpath(resolved, base)
        inside = os.path.commonpath((os.path.normcase(base), os.path.normcase(resolved))) == os.path.normcase(base)
    except ValueError:
        inside = False
        relative = ''
    parts = relative.replace('\\', '/').split('/')
    if not inside or len(parts) < 2 or os.path.normcase(parts[0]) not in {'rule', 'rewrite', 'script'}:
        raise ValueError(f'Resource target must be a file under rule, rewrite or script: {path}')
    for part in parts:
        if any(character in part for character in '<>:"|?*') or part.endswith((' ', '.')):
            raise ValueError(f'Resource target contains an invalid filename: {path}')
        if re.fullmatch(r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', part, re.IGNORECASE):
            raise ValueError(f'Resource target contains an invalid reserved filename: {path}')
    if os.path.splitext(path)[1].lower() in TEXT_EXTENSIONS:
        raise ValueError(f'Target is a known text format; use its text/FOM operations: {path}')
    if os.path.isdir(path):
        raise ValueError(f'Resource target must be a file, received directory: {path}')
    parent = os.path.dirname(path)
    while parent and not os.path.exists(parent):
        previous = parent
        parent = os.path.dirname(parent)
        if parent == previous:
            break
    if parent and not os.path.isdir(parent):
        raise ValueError(f'Resource target parent must be a directory: {parent}')
    return path


def create_resource(workspace, path, data):
    """Stage new bytes, allowing a repeated identical creation to remain stable."""
    if not isinstance(data, (bytes, bytearray, memoryview)) or not data:
        raise ValueError('Resource data must be non-empty bytes')
    data = bytes(data)
    path = validate_resource_target(workspace, path)
    fom = workspace.get_fom(path, factory=BinaryResourceFOM)
    if not isinstance(fom, BinaryResourceFOM):
        raise ValueError(f'Target is not a binary resource: {path}')
    if fom.resource_exists and fom.payload != data:
        raise ValueError(f'Resource already exists with different bytes: {path}')
    changed = not fom.resource_exists or fom.payload != data
    fom.is_dirty = fom.is_dirty or changed
    logger.info('Resource %s: target=%s bytes=%d sha256=%s',
                'created' if changed else 'unchanged', path, len(data), hashlib.sha256(data).hexdigest())
    fom.payload = data
    fom.resource_exists = True
    return fom


def replace_resource(workspace, path, data):
    """Stage a replacement of an existing resource."""
    from rule_framework.workspace import MissingSourceInputError
    if not isinstance(data, (bytes, bytearray, memoryview)) or not data:
        raise ValueError('Resource data must be non-empty bytes')
    path = validate_resource_target(workspace, path)
    if workspace.is_missing_source_input(path):
        raise MissingSourceInputError(path)
    fom = workspace.get_fom(path, factory=BinaryResourceFOM)
    if not isinstance(fom, BinaryResourceFOM):
        raise ValueError(f'Target is not a binary resource: {path}')
    if not fom.resource_exists:
        raise ValueError(f'Resource target does not exist: {path}')
    data = bytes(data)
    changed = fom.payload != data
    fom.is_dirty = fom.is_dirty or changed
    logger.info('Resource %s: target=%s bytes=%d sha256=%s',
                'replaced' if changed else 'unchanged', path, len(data), hashlib.sha256(data).hexdigest())
    fom.payload = data
    return fom


def validate_resource_declaration(definition):
    """Validate resource Action inputs before resolving any target content."""
    kind = definition.get('action') or definition.get('type')
    if kind == 'copy_resource':
        if 'source' not in definition or 'data' in definition:
            raise ValueError('copy_resource requires source only')
    elif ('source' in definition) == ('data' in definition):
        raise ValueError(f'{kind} requires exactly one of data or source')
    if 'source' in definition:
        source = definition['source']
        if not isinstance(source, str) or not source.strip() or '\0' in source:
            raise ValueError('Resource source must be a non-empty text path without NUL characters')
    if 'data' in definition and (not isinstance(definition['data'], (bytes, bytearray, memoryview)) or not definition['data']):
        raise ValueError('Resource data must be non-empty bytes; use YAML !!binary or a source path')


def execute_resource_action(ctx, definition):
    validate_resource_declaration(definition)
    if ctx.workspace is None:
        raise ValueError('Resource Actions require a ManagedWorkspace')
    kind = definition.get('action') or definition.get('type')
    if kind == 'copy_resource':
        ctx.workspace.copy_resource(definition.get('source'), ctx.fom.filepath)
    else:
        operation = getattr(ctx.workspace, kind)
        data = (ctx.workspace.read_bytes(definition['source']) if 'source' in definition
                else definition.get('data'))
        operation(ctx.fom.filepath, data)

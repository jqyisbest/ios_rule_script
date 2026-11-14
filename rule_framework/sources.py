"""Domain models, validation and HTTP acquisition for Maintenance Sources."""

import os
import re
import hashlib
import urllib.request
import urllib.error
import json
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence
from urllib.parse import urlparse
from rule_framework.source_limits import SourceBudget, parse_limits

SOURCES_STATE_FILENAME = '.rule-framework-sources.json'

DEFAULT_PRIMARY_SOURCE_ID = 'blackmatrix7'
DEFAULT_PRIMARY_SOURCE_URL = 'https://github.com/blackmatrix7/ios_rule_script.git'
DEFAULT_PRIMARY_SOURCE_REF = 'master'
DEFAULT_PRIMARY_SOURCE_REMOTE = 'upstream'
ALLOWED_PRIMARY_SOURCE_KEYS = {'id', 'type', 'url', 'ref', 'enabled', 'remote', 'purpose', 'allow_empty', 'limits'}


class SourceStatus:
    SUCCESS = 'success'
    USING_REPOSITORY_COPY = 'using_repository_copy'
    MISSING = 'missing'
    DISABLED = 'disabled'

    CANONICAL = {SUCCESS, USING_REPOSITORY_COPY, MISSING, DISABLED}


@dataclass(frozen=True)
class MaintenanceSource:
    id: str
    url: str
    target: Optional[str] = None
    type: str = 'http'
    enabled: bool = True
    ref: Optional[str] = None
    mappings: tuple = ()
    primary: bool = False
    remote: Optional[str] = None
    purpose: str = 'auto'
    allow_empty: bool = False
    limits: dict = field(default_factory=dict)


def validate_manifest_target_path(target_path: str, context: str):
    if not isinstance(target_path, str) or not target_path.strip() or '\0' in target_path:
        raise ValueError(f"{context}: Target path must be a non-empty string without NUL characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in target_path):
        raise ValueError(f"{context}: Target path contains control characters: {target_path}")
    if os.path.isabs(target_path) or target_path.startswith(('/', '\\')):
        raise ValueError(f"{context}: Target path must be a relative path: {target_path}")
    norm = os.path.normpath(target_path).replace('\\', '/')
    if norm != target_path.replace('\\', '/') or '..' in norm.split('/'):
        raise ValueError(f"{context}: Target path must be normalized: {target_path}")
    parts = norm.split('/')
    if parts[0] not in {'rule', 'rewrite', 'script'} or len(parts) < 2:
        raise ValueError(f"{context}: Target path must be under rule, rewrite or script: {target_path}")
    if norm == SOURCES_STATE_FILENAME or parts[0] == '.rule-framework-save':
        raise ValueError(f"{context}: Target path cannot be a reserved path: {target_path}")


class SourcesManifest:
    def __init__(self, version: int = 1, sources: dict = None, targets: dict = None):
        self.version = version
        self.sources = sources if sources is not None else {}
        self.targets = targets if targets is not None else {}

    @classmethod
    def load_or_create(cls, base_dir: str, create: bool = False) -> Optional['SourcesManifest']:
        manifest_path = os.path.join(base_dir, SOURCES_STATE_FILENAME)
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception as error:
                raise ValueError(f"Failed to load source state manifest '{manifest_path}': {error}") from error
            if not isinstance(data, dict):
                raise ValueError(f"Source state manifest must be a JSON object: {manifest_path}")
            if data.get('version') != 1:
                raise ValueError(f"Unsupported source state manifest version: {data.get('version')}")
            if not isinstance(data.get('sources'), dict) or not isinstance(data.get('targets'), dict):
                raise ValueError(f"Source state manifest 'sources' and 'targets' must be dictionaries: {manifest_path}")

            # Validate each source
            for s_id, s_data in data['sources'].items():
                if not isinstance(s_id, str) or not s_id.strip() or '\0' in s_id or any(ord(c) < 32 or ord(c) == 127 for c in s_id):
                    raise ValueError(f"Invalid source id in manifest: '{s_id}'")
                if not isinstance(s_data, dict):
                    raise ValueError(f"Source '{s_id}' in manifest must be a dictionary")
                if s_data.get('id') != s_id:
                    raise ValueError(f"Source id mismatch in manifest: key '{s_id}' vs record id '{s_data.get('id')}'")
                s_type = s_data.get('type')
                if not isinstance(s_type, str) or s_type.strip().lower() not in {'http', 'https', 'git'}:
                    raise ValueError(f"Source '{s_id}' in manifest missing or invalid 'type'")
                url = s_data.get('url')
                if not isinstance(url, str) or not url.strip() or '\0' in url or any(ord(c) < 32 or ord(c) == 127 for c in url):
                    raise ValueError(f"Source '{s_id}' in manifest missing or invalid 'url'")
                parsed_url = urlparse(url)
                if parsed_url.username or parsed_url.password:
                    raise ValueError(f"Source '{s_id}' in manifest url contains embedded credentials")
                if parsed_url.scheme.lower() not in {'http', 'https'} or not parsed_url.netloc or not parsed_url.hostname:
                    raise ValueError(f"Source '{s_id}' in manifest has invalid url: '{url}'")
                if 'primary' in s_data and not isinstance(s_data['primary'], bool):
                    raise ValueError(f"Source '{s_id}' in manifest has invalid 'primary' boolean")
                is_primary = bool(s_data.get('primary', False))
                has_directory_mapping = False
                if 'mappings' in s_data:
                    m_list = s_data['mappings']
                    if not isinstance(m_list, list) or not m_list:
                        raise ValueError(f"Source '{s_id}' in manifest has invalid mappings list")
                    for m_item in m_list:
                        if not isinstance(m_item, dict):
                            raise ValueError(f"Source '{s_id}' in manifest has invalid mapping entry")
                        m_path = m_item.get('path')
                        if not isinstance(m_path, str) or not m_path.strip() or '\0' in m_path or any(ord(c) < 32 or ord(c) == 127 for c in m_path):
                            raise ValueError(f"Source '{s_id}' mapping missing or invalid 'path'")
                        if os.path.isabs(m_path) or m_path.startswith(('/', '\\')) or '..' in os.path.normpath(m_path).replace('\\', '/').split('/'):
                            raise ValueError(f"Source '{s_id}' mapping path must be relative inside repository: '{m_path}'")
                        m_target = m_item.get('target')
                        if not isinstance(m_target, str) or not m_target.strip():
                            raise ValueError(f"Source '{s_id}' mapping missing or invalid 'target'")
                        validate_manifest_target_path(m_target, f"Source '{s_id}' mapping")
                        m_kind = m_item.get('kind', 'file')
                        if m_kind not in {'file', 'directory'}:
                            raise ValueError(f"Source '{s_id}' mapping has invalid kind: '{m_kind}'")
                        if m_kind == 'directory':
                            has_directory_mapping = True
                targets = s_data.get('targets')
                if not isinstance(targets, list) or (not targets and not is_primary and not (s_type.strip().lower() == 'git' and has_directory_mapping)):
                    raise ValueError(f"Source '{s_id}' in manifest must have a non-empty 'targets' list")
                for t in targets:
                    validate_manifest_target_path(t, f"Source '{s_id}'")
                if not isinstance(s_data.get('enabled'), bool):
                    raise ValueError(f"Source '{s_id}' in manifest missing or invalid 'enabled' boolean")
                last_ver = s_data.get('last_version')
                if last_ver is not None and (not isinstance(last_ver, str) or not last_ver.strip()):
                    raise ValueError(f"Source '{s_id}' in manifest has invalid 'last_version'")
                last_stat = s_data.get('last_status')
                if last_stat is not None and (not isinstance(last_stat, str) or not last_stat.strip()):
                    raise ValueError(f"Source '{s_id}' in manifest has invalid 'last_status'")

            # Validate each target
            seen_target_normcases = {}
            for t_path, t_data in data['targets'].items():
                validate_manifest_target_path(t_path, "Manifest target")
                t_normcase = os.path.normcase(t_path)
                if t_normcase in seen_target_normcases:
                    raise ValueError(f"Duplicate target path alias in manifest targets: '{t_path}' vs '{seen_target_normcases[t_normcase]}'")
                seen_target_normcases[t_normcase] = t_path

                if not isinstance(t_data, dict):
                    raise ValueError(f"Target '{t_path}' entry in manifest must be a dictionary")
                owner = t_data.get('source_id')
                if not isinstance(owner, str) or owner not in data['sources']:
                    raise ValueError(f"Target '{t_path}' in manifest references unknown source_id '{owner}'")
                last_ver = t_data.get('last_version')
                if last_ver is not None and (not isinstance(last_ver, str) or not last_ver.strip()):
                    raise ValueError(f"Target '{t_path}' in manifest has invalid 'last_version'")

                owner_targets_normcase = {os.path.normcase(x) for x in data['sources'][owner]['targets']}
                if t_normcase not in owner_targets_normcase:
                    raise ValueError(f"Target '{t_path}' owned by '{owner}' is not listed in source targets: {data['sources'][owner]['targets']}")

            # Strict nested ownership consistency: verify source targets map back to target entries
            all_targets_normcase = {os.path.normcase(t): td.get('source_id') for t, td in data['targets'].items()}
            for s_id, s_data in data['sources'].items():
                for st in s_data.get('targets', []):
                    st_norm = os.path.normcase(st)
                    if st_norm not in all_targets_normcase:
                        raise ValueError(f"Source '{s_id}' target '{st}' is not present in manifest targets")
                    if all_targets_normcase[st_norm] != s_id:
                        raise ValueError(f"Source '{s_id}' target '{st}' has conflicting owner '{all_targets_normcase[st_norm]}'")

            return cls(version=data.get('version', 1),
                       sources=dict(data.get('sources', {})),
                       targets=dict(data.get('targets', {})))
        if create:
            return cls(version=1, sources={}, targets={})
        return None

    def register_source(self, source: MaintenanceSource, targets: Optional[Sequence[str]] = None):
        if targets is None:
            if source.target:
                targets = [source.target.replace('\\', '/')]
            elif source.mappings:
                targets = [m.target.replace('\\', '/') for m in source.mappings if getattr(m, 'kind', 'file') == 'file']
            else:
                targets = []
        existing_s = self.sources.get(source.id, {})
        targets_list = list(existing_s.get('targets', []))
        for t in targets:
            norm_t = t.replace('\\', '/')
            if norm_t not in targets_list:
                targets_list.append(norm_t)

        mappings_list = None
        if source.mappings:
            mappings_list = [
                {
                    'path': m.path,
                    'target': m.target.replace('\\', '/'),
                    'kind': getattr(m, 'kind', 'file')
                }
                for m in source.mappings
            ]
        elif existing_s.get('mappings'):
            mappings_list = list(existing_s['mappings'])

        source_dict = {
            'id': source.id,
            'type': source.type,
            'url': source.url,
            'targets': targets_list,
            'enabled': source.enabled,
            'last_version': existing_s.get('last_version'),
            'last_status': existing_s.get('last_status'),
        }
        if source.primary or existing_s.get('primary'):
            source_dict['primary'] = True
        if mappings_list is not None:
            source_dict['mappings'] = mappings_list
        if source.ref is not None:
            source_dict['ref'] = source.ref
        self.sources[source.id] = source_dict

        for norm_target in targets:
            norm_t = norm_target.replace('\\', '/')
            existing_t = self.targets.get(norm_t, {})
            self.targets[norm_t] = {
                'source_id': source.id,
                'last_version': existing_t.get('last_version'),
            }

    def register_target(self, source_id: str, target: str):
        norm_t = target.replace('\\', '/')
        if source_id in self.sources:
            t_list = self.sources[source_id].setdefault('targets', [])
            if norm_t not in t_list:
                t_list.append(norm_t)
        existing_t = self.targets.get(norm_t, {})
        self.targets[norm_t] = {
            'source_id': source_id,
            'last_version': existing_t.get('last_version'),
        }

    def record_refresh(self, source_id: str, target: str, status: str, version: Optional[str] = None):
        norm_target = target.replace('\\', '/')
        if source_id in self.sources:
            s = self.sources[source_id]
            s['last_status'] = status
            if version is not None:
                s['last_version'] = version
        if norm_target in self.targets:
            t = self.targets[norm_target]
            if version is not None:
                t['last_version'] = version

    def get_target_owner(self, target: str) -> Optional[str]:
        norm_target = target.replace('\\', '/')
        if norm_target in self.targets:
            return self.targets[norm_target].get('source_id')
        return None

    def get_last_version(self, target: str) -> Optional[str]:
        norm_target = target.replace('\\', '/')
        if norm_target in self.targets:
            return self.targets[norm_target].get('last_version')
        return None

    def to_dict(self) -> dict:
        return {
            'version': self.version,
            'sources': {
                k: dict(v)
                for k, v in sorted(self.sources.items())
                if (v.get('targets') or v.get('primary')
                    or (v.get('type', '').strip().lower() == 'git'
                        and any(mapping.get('kind') == 'directory'
                                for mapping in v.get('mappings', []))))
            },
            'targets': {k: dict(v) for k, v in sorted(self.targets.items())},
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + '\n'

    @classmethod
    def summarize_removed(cls, base_dir: str, active_ids: set[str]) -> tuple[list[str], int]:
        manifest_path = os.path.join(base_dir, SOURCES_STATE_FILENAME)
        if not os.path.isfile(manifest_path):
            return [], 0
        try:
            with open(manifest_path, 'r', encoding='utf-8') as mf:
                m_data = json.load(mf)
            if not isinstance(m_data, dict):
                return [], 0
            sources_dict = m_data.get('sources')
            if not isinstance(sources_dict, dict):
                return [], 0
            removed_ids = []
            removed_target_count = 0
            for sid, sdata in sorted(sources_dict.items()):
                if sid not in active_ids:
                    removed_ids.append(sid)
                    if isinstance(sdata, dict):
                        removed_target_count += len(sdata.get('targets') or [])
            return removed_ids, removed_target_count
        except Exception:
            return [], 0


from rule_framework.fom import FOMBase

class SourcesStateAdapter(FOMBase):
    def __init__(self, filepath: str, manifest: SourcesManifest):
        self.filepath = filepath
        self.manifest = manifest
        self.is_dirty = True

    def render_bytes(self) -> bytes:
        return self.manifest.to_json().encode('utf-8')

    def save_to(self, path: str):
        from rule_framework.managed_io import ensure_framework_io
        ensure_framework_io('SourcesStateAdapter.save_to()')
        with open(path, 'wb') as f:
            f.write(self.render_bytes())

    def save(self):
        self.save_to(self.filepath)



@dataclass(frozen=True)
class SourceResult:
    source: MaintenanceSource
    status: str
    target: str
    version: Optional[str] = None
    reason: Optional[str] = None

    @property
    def source_id(self) -> str:
        return self.source.id


@dataclass
class SourceExecutionContext:
    staged_foms: dict = field(default_factory=dict)
    missing_source_targets: set = field(default_factory=set)
    missing_source_directories: set = field(default_factory=set)
    ownership_map: dict = field(default_factory=dict)
    _state_spool: Optional[Any] = field(default=None, repr=False)
    prior_manifest: Optional[dict] = None
    prior_files: dict = field(default_factory=dict)
    rejected_new_files: dict = field(default_factory=dict)
    manifest: Optional[Any] = field(default=None, repr=False)
    source_results: list = field(default_factory=list, repr=False)


def validate_source_ids(source_ids, *, task_name: str = ''):
    """Validate source_ids list and elements for task declarations."""
    if not isinstance(source_ids, list):
        if task_name:
            raise ValueError(f"Invalid source_ids in task '{task_name}': must be a list")
        raise ValueError('source_ids must be a list')
    if not source_ids:
        if task_name:
            raise ValueError(f"Invalid source_ids in task '{task_name}': must be a non-empty list")
        raise ValueError('source_ids must be a non-empty list')
    for sid in source_ids:
        if not isinstance(sid, str) or not sid.strip():
            if task_name:
                raise ValueError(f"Invalid source_ids in task '{task_name}': elements must be non-empty strings")
            raise ValueError('Each source_id must be a non-empty string')
        if '\0' in sid or any(ord(c) < 32 or ord(c) == 127 for c in sid):
            if task_name:
                raise ValueError(f"source_ids in task '{task_name}' contains control or NUL characters")
            raise ValueError('source_ids contains control or NUL characters')


def count_source_statuses(source_results: Sequence[SourceResult]) -> dict[str, int]:
    """Return dictionary of status counts across all SourceResults."""
    counts = {
        'success': 0,
        'using_repository_copy': 0,
        'missing': 0,
        'disabled': 0,
    }
    for sr in source_results:
        if sr.status == SourceStatus.SUCCESS:
            counts['success'] += 1
        elif sr.status == SourceStatus.USING_REPOSITORY_COPY:
            counts['using_repository_copy'] += 1
        elif sr.status == SourceStatus.MISSING:
            counts['missing'] += 1
        elif sr.status == SourceStatus.DISABLED:
            counts['disabled'] += 1
    counts['failed'] = counts['missing']
    return counts


def resolve_repository_copy_fallback(
    source: MaintenanceSource,
    target: str,
    *,
    base_dir: str,
    manifest: Optional[SourcesManifest] = None,
    default_version: Optional[str] = None,
    reason: Optional[str] = None,
    missing_source_targets: Optional[set] = None,
    register_target: bool = False,
) -> SourceResult:
    """Resolve repository copy fallback or record missing target status."""
    norm_target_path = os.path.normpath(os.path.join(base_dir, target)).replace('\\', '/')
    if os.path.isfile(norm_target_path):
        hist_ver = manifest.get_last_version(target) if manifest else None
        result_ver = hist_ver or default_version
        if result_ver is None:
            try:
                with open(norm_target_path, 'rb') as f:
                    result_ver = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                result_ver = None
        if manifest is not None:
            if register_target:
                manifest.register_target(source.id, target)
            manifest.record_refresh(source.id, target, SourceStatus.USING_REPOSITORY_COPY, version=hist_ver)
        return SourceResult(
            source,
            SourceStatus.USING_REPOSITORY_COPY,
            target=target,
            version=result_ver,
            reason=reason,
        )
    else:
        if manifest is not None:
            if register_target:
                manifest.register_target(source.id, target)
            manifest.record_refresh(source.id, target, SourceStatus.MISSING)
        if missing_source_targets is not None:
            missing_source_targets.add(norm_target_path)
        return SourceResult(
            source,
            SourceStatus.MISSING,
            target=target,
            reason=reason,
        )


def validate_source_target(target_path: str, base_dir: str, allow_directory: bool = False):
    """Ensure target path is an actual file (or directory if allow_directory) within base_dir and under rule, rewrite or script."""
    if not isinstance(target_path, str) or not target_path.strip() or '\0' in target_path:
        raise ValueError('Source target must be a non-empty text path without NUL characters')
    if any(ord(c) < 32 or ord(c) == 127 for c in target_path):
        raise ValueError('Source target contains control characters')
    if not allow_directory and target_path.endswith(('/', '\\')):
        raise ValueError(f'Source target must be a file, not a directory: {target_path}')

    base = os.path.realpath(base_dir)
    target_abs = os.path.realpath(os.path.join(base, target_path) if not os.path.isabs(target_path) else target_path)

    try:
        inside = os.path.commonpath((os.path.normcase(base), os.path.normcase(target_abs))) == os.path.normcase(base)
    except ValueError:
        inside = False

    if not inside:
        raise ValueError(f'Source target path escapes or is outside base_dir: {target_path}')

    relative = os.path.relpath(target_abs, base).replace('\\', '/')
    parts = relative.split('/')
    if parts[0] not in {'rule', 'rewrite', 'script'}:
        raise ValueError(f'Source target must be located within managed directories (rule, rewrite, script): {target_path}')

    if len(parts) < 2 or relative in {'rule', 'rewrite', 'script'}:
        raise ValueError(f'Source target cannot be a bare managed root directory: {target_path}')

    if not allow_directory and os.path.isdir(target_abs):
        raise ValueError(f'Source target must be a file, but resolves to an existing directory: {target_path}')
    if allow_directory and os.path.isfile(target_abs):
        raise ValueError(f'Source target must be a directory, but resolves to an existing file: {target_path}')

    if not parts[-1].strip():
        raise ValueError(f'Source target cannot have an empty filename: {target_path}')

    declared_base = os.path.abspath(base_dir)
    declared_abs = os.path.abspath(os.path.join(declared_base, target_path))
    declared_relative = os.path.relpath(declared_abs, declared_base).replace('\\', '/')
    validate_manifest_target_path(declared_relative, 'Source target')
    return declared_relative


@dataclass(frozen=True)
class SourceTargetClaim:
    path: str
    source_id: str
    kind: str = 'file'


def source_target_claims(sources=(), manifest: Optional[SourcesManifest] = None):
    """Collect declared layouts and the actual files retained by source history."""
    claims = []
    if manifest is not None:
        claims.extend(SourceTargetClaim(path, entry['source_id'])
                      for path, entry in manifest.targets.items())
    for source in sources:
        if source.target:
            claims.append(SourceTargetClaim(source.target, source.id))
        claims.extend(SourceTargetClaim(mapping.target, source.id, mapping.kind)
                      for mapping in source.mappings)
    return claims


def validate_source_target_claims(claims, *, base_dir: str):
    """Reject impossible file layouts while allowing directory roots to expand."""
    from itertools import groupby

    keyed = []
    for claim in claims:
        validate_source_target(claim.path, base_dir, allow_directory=claim.kind == 'directory')
        physical = os.path.normcase(os.path.realpath(os.path.join(base_dir, claim.path))).replace('\\', '/')
        keyed.append((tuple(physical.split('/')), claim))
    keyed.sort(key=lambda item: item[0])

    def conflict(first, second):
        raise ValueError(
            f"Source target overlap conflict between '{first.path}' from '{first.source_id}' "
            f"and '{second.path}' from '{second.source_id}'"
        )

    previous_file = None
    for key, entries in groupby(keyed, key=lambda item: item[0]):
        group = [entry[1] for entry in entries]
        first = group[0]
        for other in group[1:]:
            first_spelling = os.path.normpath(first.path).replace('\\', '/')
            other_spelling = os.path.normpath(other.path).replace('\\', '/')
            if (first.source_id != other.source_id or first.kind != other.kind
                    or first_spelling != other_spelling):
                conflict(first, other)
        if previous_file is not None:
            previous_key, previous_claim = previous_file
            if len(previous_key) < len(key) and key[:len(previous_key)] == previous_key:
                conflict(previous_claim, first)
        if first.kind == 'file':
            previous_file = (key, first)


ALLOWED_HTTP_SOURCE_KEYS = {'id', 'type', 'url', 'target', 'enabled', 'purpose', 'allow_empty', 'limits'}
ALLOWED_GIT_SOURCE_KEYS = {'id', 'type', 'url', 'ref', 'mappings', 'enabled', 'purpose', 'allow_empty', 'limits'}


def _validate_public_http_url(url: str, source_id: str):
    if not isinstance(url, str) or not url.strip() or '\0' in url:
        raise ValueError(f"Source '{source_id}' url must be a non-empty string without NUL characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError(f"Source '{source_id}' url contains control characters")

    parsed_url = urlparse(url)
    if parsed_url.username or parsed_url.password:
        raise ValueError(f"Source '{source_id}' url contains embedded credentials; only anonymous public URLs are supported")
    if parsed_url.scheme.lower() not in {'http', 'https'} or not parsed_url.netloc:
        raise ValueError(f"Source '{source_id}' url must be a valid HTTP or HTTPS address with a host: {url}")
    if not parsed_url.hostname:
        raise ValueError(f"Source '{source_id}' url must contain a valid hostname: {url}")

    try:
        port = parsed_url.port
    except ValueError as port_err:
        raise ValueError(f"Source '{source_id}' url has a malformed port: {port_err}") from port_err
    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Source '{source_id}' url port out of range: {port}")


def parse_primary_source(config: dict, *, base_dir: str, seen_ids: Optional[set] = None,
                         manifest: Optional[SourcesManifest] = None) -> Optional[MaintenanceSource]:
    if 'primary_source' not in config:
        return None
    raw = config.get('primary_source')
    if isinstance(raw, bool):
        decl = {'enabled': raw}
    elif isinstance(raw, dict):
        decl = raw
    else:
        raise ValueError("'primary_source' must be a dictionary or boolean")

    unsupported = set(decl.keys()) - ALLOWED_PRIMARY_SOURCE_KEYS
    if unsupported:
        raise ValueError(f"Unsupported keys in primary_source declaration: {sorted(unsupported)}")

    source_id = decl.get('id', DEFAULT_PRIMARY_SOURCE_ID)
    if not isinstance(source_id, str) or not source_id.strip() or '\0' in source_id:
        raise ValueError("Primary source 'id' must be a non-empty string without NUL characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in source_id):
        raise ValueError("Primary source 'id' contains control characters")
    if seen_ids is not None:
        if source_id in seen_ids:
            raise ValueError(f"Duplicate source id declared: {source_id}")
        seen_ids.add(source_id)

    source_type = decl.get('type', 'git')
    if not isinstance(source_type, str) or source_type.lower() != 'git':
        raise ValueError(f"Primary source '{source_id}' type must be 'git'")

    url = decl.get('url', DEFAULT_PRIMARY_SOURCE_URL)
    _validate_public_http_url(url, source_id)

    ref = decl.get('ref', DEFAULT_PRIMARY_SOURCE_REF)
    if not isinstance(ref, str) or not ref.strip() or '\0' in ref or any(ord(c) < 32 or ord(c) == 127 for c in ref):
        raise ValueError(f"Primary source '{source_id}' ref must be a non-empty string without control characters")
    ref = ref.strip()
    if ref.startswith('-'):
        raise ValueError(f"Primary source '{source_id}' ref must start with a name character")

    enabled = decl.get('enabled', True)
    if not isinstance(enabled, bool):
        raise ValueError(f"Primary source '{source_id}' enabled setting must be a boolean")

    remote = decl.get('remote', DEFAULT_PRIMARY_SOURCE_REMOTE)
    if remote is not None:
        if not isinstance(remote, str) or not remote.strip() or '\0' in remote or any(ord(c) < 32 or ord(c) == 127 for c in remote):
            raise ValueError(f"Primary source '{source_id}' remote must be a non-empty string without control characters")
        remote = remote.strip()
        if remote.startswith('-') or '/' in remote or '\\' in remote:
            raise ValueError(f"Primary source '{source_id}' remote must be a valid remote alias")

    if manifest is not None and source_id in manifest.sources:
        hist_entry = manifest.sources[source_id]
        if not hist_entry.get('primary', False):
            raise ValueError(f"Primary source id '{source_id}' conflicts with historical secondary source '{source_id}'")

    from rule_framework.source_policy import parse_content_policy
    purpose, allow_empty = parse_content_policy(decl, f'Primary source {source_id}')
    return MaintenanceSource(
        id=source_id,
        url=url,
        type='git',
        purpose=purpose, allow_empty=allow_empty, limits=parse_limits(decl.get('limits', {})),
        ref=ref,
        enabled=enabled,
        primary=True,
        remote=remote,
    )


def validate_source_declaration(decl: dict, *, base_dir: str, seen_ids: set, seen_targets: dict, manifest: Optional[SourcesManifest] = None):
    if not isinstance(decl, dict):
        raise ValueError('Each source declaration must be a dictionary')

    if 'id' not in decl:
        raise ValueError("Source declaration missing required 'id'")
    source_id = decl['id']
    if not isinstance(source_id, str) or not source_id.strip() or '\0' in source_id:
        raise ValueError('Source id must be a non-empty string without NUL characters')
    if any(ord(c) < 32 or ord(c) == 127 for c in source_id):
        raise ValueError('Source id contains control characters')
    if source_id in seen_ids:
        raise ValueError(f'Duplicate source id declared: {source_id}')
    seen_ids.add(source_id)

    if manifest is not None and source_id in manifest.sources:
        if manifest.sources[source_id].get('primary', False):
            raise ValueError(f"Secondary source id '{source_id}' conflicts with historical primary source '{source_id}'")

    source_type = decl.get('type', 'http')
    if not isinstance(source_type, str) or source_type.lower() not in {'http', 'https', 'git'}:
        raise ValueError(f"Source '{source_id}' type must be 'http', 'https' or 'git'")
    source_type = source_type.lower()

    allowed_keys = ALLOWED_GIT_SOURCE_KEYS if source_type == 'git' else ALLOWED_HTTP_SOURCE_KEYS
    unsupported = set(decl.keys()) - allowed_keys
    if unsupported:
        raise ValueError(f'Unsupported keys in source declaration: {sorted(unsupported)}')

    if 'url' not in decl:
        raise ValueError(f"Source '{source_id}' missing required 'url'")
    url = decl['url']
    _validate_public_http_url(url, source_id)

    enabled = decl.get('enabled', True)
    if not isinstance(enabled, bool):
        raise ValueError(f"Source '{source_id}' enabled setting must be a boolean")

    from rule_framework.source_policy import parse_content_policy
    purpose, allow_empty = parse_content_policy(decl, f'Source {source_id}')

    if source_type in {'http', 'https'}:
        if 'target' not in decl:
            raise ValueError(f"Source '{source_id}' missing required 'target'")
        target_path = decl['target']

        norm_target = validate_source_target(target_path, base_dir, allow_directory=False)
        target_key = os.path.normcase(norm_target)
        if target_key in seen_targets:
            raise ValueError(f"Source target overlap conflict on '{norm_target}' between '{seen_targets[target_key]}' and '{source_id}'")
        seen_targets[target_key] = source_id

        return MaintenanceSource(
            id=source_id,
            url=url,
            target=norm_target,
            purpose=purpose, allow_empty=allow_empty, limits=parse_limits(decl.get('limits', {})),
            type=source_type,
            enabled=enabled,
        )

    # Git source
    if 'mappings' not in decl:
        raise ValueError(f"Source '{source_id}' missing required 'mappings'")
    raw_mappings = decl['mappings']
    if not isinstance(raw_mappings, list) or not raw_mappings:
        raise ValueError(f"Source '{source_id}' mappings must be a non-empty list")

    from rule_framework.sources_git import GitMapping
    mappings = []
    for idx, m_decl in enumerate(raw_mappings):
        if not isinstance(m_decl, dict):
            raise ValueError(f"Source '{source_id}' mapping #{idx+1} must be a dictionary")
        unsupported_m = set(m_decl.keys()) - {'path', 'target', 'kind', 'purpose', 'allow_empty'}
        if unsupported_m:
            raise ValueError(f"Source '{source_id}' mapping #{idx+1} has unsupported keys: {sorted(unsupported_m)}")
        if 'path' not in m_decl or not isinstance(m_decl['path'], str) or not m_decl['path'].strip():
            raise ValueError(f"Source '{source_id}' mapping #{idx+1} missing or invalid 'path'")
        m_path = m_decl['path'].strip()
        if '\0' in m_path or any(ord(c) < 32 or ord(c) == 127 for c in m_path):
            raise ValueError(f"Source '{source_id}' mapping path contains control or NUL characters")
        if os.path.isabs(m_path) or m_path.startswith(('/', '\\')):
            raise ValueError(f"Source '{source_id}' mapping path must be relative: {m_path}")
        norm_m_path = os.path.normpath(m_path).replace('\\', '/')
        if '..' in norm_m_path.split('/'):
            raise ValueError(f"Source '{source_id}' mapping path escapes repository: {m_path}")

        if 'target' not in m_decl:
            raise ValueError(f"Source '{source_id}' mapping #{idx+1} missing required 'target'")
        m_target = m_decl['target']
        kind = m_decl.get('kind', 'file')
        if not isinstance(kind, str) or kind.lower() not in {'file', 'directory'}:
            raise ValueError(f"Source '{source_id}' mapping kind must be 'file' or 'directory', got: {kind}")
        kind = kind.lower()

        norm_target = validate_source_target(m_target, base_dir, allow_directory=(kind == 'directory'))
        target_key = os.path.normcase(norm_target)
        if target_key in seen_targets:
            raise ValueError(f"Source target overlap conflict on '{norm_target}' between '{seen_targets[target_key]}' and '{source_id}'")
        seen_targets[target_key] = source_id

        m_purpose, m_allow_empty = parse_content_policy(m_decl, f'Source {source_id} mapping {idx+1}', default_purpose=purpose, default_allow_empty=allow_empty)
        mappings.append(GitMapping(path=norm_m_path, target=norm_target, kind=kind, purpose=m_purpose, allow_empty=m_allow_empty))

    ref = decl.get('ref', 'HEAD')
    if ref is not None:
        if not isinstance(ref, str) or not ref.strip() or '\0' in ref or any(ord(c) < 32 or ord(c) == 127 for c in ref):
            raise ValueError(f"Source '{source_id}' ref must be a non-empty string without control characters")
        ref = ref.strip()

    return MaintenanceSource(
        id=source_id,
        url=url,
        type=source_type,
        mappings=tuple(mappings),
        purpose=purpose, allow_empty=allow_empty, limits=parse_limits(decl.get('limits', {})),
        ref=ref,
        enabled=enabled,
    )


def parse_sources(config: dict, *, base_dir: str, manifest: Optional[SourcesManifest] = None,
                  seen_ids: Optional[set] = None) -> tuple[MaintenanceSource, ...]:
    if 'sources' not in config:
        return ()
    raw_sources = config.get('sources')
    if raw_sources is None or not isinstance(raw_sources, list):
        raise ValueError("'sources' must be a list, got null or invalid type")

    if seen_ids is None:
        seen_ids = set()
    seen_targets = {}
    sources = []
    for item in raw_sources:
        source = validate_source_declaration(item, base_dir=base_dir, seen_ids=seen_ids, seen_targets=seen_targets, manifest=manifest)
        sources.append(source)
    validate_source_target_claims(source_target_claims(sources, manifest), base_dir=base_dir)
    return tuple(sources)


def _check_item_source_ids(decl: dict, known_sources: set):
    if 'source_ids' in decl:
        try:
            validate_source_ids(decl['source_ids'])
        except ValueError:
            # Malformed Task fields are reported by build_tasks at its own
            # failure boundary. Only valid cross-source references are global.
            return
    if 'source_ids' in decl and isinstance(decl['source_ids'], list):
        for sid in decl['source_ids']:
            if sid not in known_sources:
                task_name = decl.get('name') or decl.get('task') or ''
                raise ValueError(f"Unknown source id '{sid}' referenced in task '{task_name}'; known sources: {sorted(known_sources)}")


def validate_source_references_and_manifest(config: dict, *, base_dir: str, sources: tuple[MaintenanceSource, ...],
                                            manifest: Optional[SourcesManifest] = None,
                                            primary_source: Optional[MaintenanceSource] = None):
    """Validate cross-source references and historical ownership after recovery."""
    validate_source_target_claims(source_target_claims(sources, manifest), base_dir=base_dir)
    known_sources = {s.id for s in sources}
    if primary_source is not None:
        known_sources.add(primary_source.id)
    if manifest is not None:
        known_sources.update(manifest.sources.keys())

    from rule_framework.tasks import selected_task_declarations
    _config_key, task_items = selected_task_declarations(config)
    for item in task_items:
        if not isinstance(item, dict):
            continue
        _check_item_source_ids(item, known_sources)
        if 'tasks' in item and isinstance(item['tasks'], list):
            for sub_item in item['tasks']:
                if isinstance(sub_item, dict):
                    _check_item_source_ids(sub_item, known_sources)



class HttpFetcher:
    """Standard HTTP/HTTPS fetcher boundary with configurable timeout."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.budget = None

    def fetch(self, url: str) -> bytes:
        budget = self.budget
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'RuleFramework/1.0 (Maintenance)'}
        )
        timeout = min(self.timeout, budget.remaining('http_connect')) if budget else self.timeout
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            chunks = []
            while True:
                if budget:
                    remaining = budget.remaining('http_read')
                    # A short read preserves the total deadline even for trickling peers.
                    try:
                        resp.fp.raw._sock.settimeout(min(self.timeout, remaining))
                    except AttributeError:
                        pass
                data = resp.read1(65536)
                if not data:
                    break
                if budget:
                    budget.charge(len(data), 'http_read')
                chunks.append(data)
        return b''.join(chunks)


def _http_response_content(res, source, boundary):
    if isinstance(res, bytes):
        raw = res
    elif hasattr(res, 'content'):
        raw = res.content
    elif hasattr(res, 'read'):
        raw = res.read()
    elif isinstance(res, str):
        raw = res.encode('utf-8')
    else:
        raise ValueError(f'Unexpected response type from {boundary}: {type(res)}')
    if hasattr(res, 'status_code') and res.status_code >= 400:
        raise RuntimeError(f'HTTP {res.status_code} error fetching {source.url}')
    return raw


def fetch_source_content(source: MaintenanceSource, http=None) -> bytes:
    """Fetch source bytes via injected boundary or default HttpFetcher."""
    budget = SourceBudget(source)
    fetcher = http or HttpFetcher()
    if type(fetcher) is HttpFetcher:
        fetcher.budget = budget
        try:
            raw = fetcher.fetch(source.url)
        except (TimeoutError, urllib.error.URLError):
            budget.remaining('http_timeout')
            raise
        if not isinstance(raw, bytes):
            raise ValueError(f'Fetched source content must be bytes, got {type(raw)}')
        budget.charge(max(0, len(raw) - budget.bytes), 'http_complete', files=1)
        return raw
    if hasattr(fetcher, 'fetch'):
        raw = fetcher.fetch(source.url)
    elif hasattr(fetcher, 'get'):
        res = fetcher.get(source.url)
        raw = _http_response_content(res, source, 'http.get')
    elif callable(fetcher):
        res = fetcher(source.url)
        raw = _http_response_content(res, source, 'http callable')
    else:
        raise ValueError(f'Invalid http boundary object: {fetcher}')

    if not isinstance(raw, bytes):
        raise ValueError(f'Fetched source content must be bytes, got {type(raw)}')
    budget.charge(len(raw), 'http_complete', files=1)
    return raw


def stage_source_content(target_path: str, data: bytes, *, settings=None, base_dir=None):
    """Instantiate and stage a FOM from raw downloaded bytes in an isolated candidate state."""
    import tempfile
    from copy import deepcopy
    from rule_framework.resources import is_binary_resource, BinaryResourceFOM

    if is_binary_resource(target_path, data=data):
        fom = BinaryResourceFOM(target_path)
        fom.payload = data
        fom.loaded_payload = data
        fom.resource_exists = True
        fom.is_dirty = True
        fom.settings = deepcopy(settings or {})
        return fom

    from rule_framework.main import get_fom_for_file, _load_native_source_bytes
    fom = get_fom_for_file(target_path, base_dir=base_dir, data=data)
    fom.settings = deepcopy(settings or {})
    initial_client = getattr(fom, 'client', None)

    if not _load_native_source_bytes(fom, target_path, data):
        # Load candidate bytes via isolated temporary file to preserve parser abstractions
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_file = os.path.join(tmp_dir, os.path.basename(target_path))
            with open(tmp_file, 'wb') as f:
                f.write(data)
            fom.filepath = tmp_file
            fom.load()
            fom.filepath = target_path

    if initial_client and initial_client != 'unknown':
        fom.client = initial_client
    else:
        from rule_framework.client_paths import client_for_path
        fom.client = client_for_path(target_path, base_dir=base_dir, data=data)
    if callable(getattr(fom, 'update_metadata', None)) or callable(getattr(fom, '_apply_metadata', None)):
        fom._metadata_origin = getattr(fom, '_raw_bytes', getattr(fom, '_metadata_baseline', data))
    fom.is_dirty = True
    return fom

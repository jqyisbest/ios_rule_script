import sys
import os
import logging
from pathlib import Path

# Ensure rule_framework is in path if executed directly, but remove the local script dir
# to prevent 'rule_framework/ast.py' from shadowing the stdlib 'ast' module.
script_dir = os.path.abspath(os.path.dirname(__file__))
if sys.path[0] == script_dir:
    sys.path.pop(0)
    
sys.path.insert(0, os.path.abspath(os.path.join(script_dir, '..')))

from ruamel.yaml import YAML

from rule_framework.fom import (
    ListFileBase, StandardListFile, QuanXListFile, INIFileFOM, SgmoduleFile, PluginFile, 
    QuanXConfFile, ClashYamlFile, ClashTextPayloadFile, ClashClassicalListFile, AdGuardFile, StashOverrideFile,
    PlainFileFOM, JSONFileFOM
)
from rule_framework.surge import SurgeFile
from rule_framework.loon import LoonFile
from rule_framework.shadowrocket import ShadowrocketFile
from rule_framework.resources import BinaryResourceFOM, is_binary_resource
from rule_framework.quantumult_lists import is_quantumult_path
from rule_framework.client_paths import client_for_path
from rule_framework.storage import RECOVERY_DIRECTORY, SaveResult, recover_saved_files, save_managed_files
from rule_framework.publication import PublicationOptions, PublicationResult, publish_saved_files
from rule_framework.managed_io import ensure_framework_io
from rule_framework.source_limits import parse_limits
from rule_framework.tasks import MaintenanceResult, Target, build_tasks
from rule_framework.task_runner import ProvenanceFilter, execute_tasks, log_task_results, task_logging
from rule_framework.sources import (
    DEFAULT_PRIMARY_SOURCE_ID,
    DEFAULT_PRIMARY_SOURCE_REF,
    DEFAULT_PRIMARY_SOURCE_REMOTE,
    DEFAULT_PRIMARY_SOURCE_URL,
    SOURCES_STATE_FILENAME,
    SourcesManifest,
    SourcesStateAdapter,
    SourceStatus,
    count_source_statuses,
    parse_primary_source,
    parse_sources,
    validate_source_ids,
    validate_source_references_and_manifest,
)

logger = logging.getLogger('RuleFramework')

def setup_logging(settings):
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()
    logger.propagate = False
    
    log_level_str = settings.get('log_level', 'INFO').upper()
    level = getattr(logging, log_level_str, logging.INFO)
    logger.setLevel(level)
    
    log_file = settings.get('log_file', 'modifier_logs.log')
    base_dir = settings.get('base_dir', os.getcwd())
    
    # Absolute path or relative to base_dir
    if not os.path.isabs(log_file):
        log_file = os.path.join(base_dir, log_file)
        
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.addFilter(ProvenanceFilter())
    file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(provenance)s%(message)s'))
    logger.addHandler(file_handler)


_STRUCTURED_CONFIG_MAP = {
    ('.conf', 'quantumult x'): QuanXConfFile,
    ('.conf', 'shadowrocket'): ShadowrocketFile,
    ('.conf', 'surge'): SurgeFile,
    ('.conf', 'loon'): LoonFile,
    ('.snippet', 'quantumult x'): QuanXConfFile,
    ('.snippet', 'shadowrocket'): ShadowrocketFile,
    ('.qxrewrite', 'quantumult x'): QuanXConfFile,
    ('.qxrewrite', 'shadowrocket'): ShadowrocketFile,
    ('.list', 'quantumult x'): QuanXListFile,
    ('.list', 'mihomo'): ClashClassicalListFile,
    ('.txt', 'mihomo'): ClashTextPayloadFile,
    ('.txt', 'adguard'): AdGuardFile,
    ('.sgmodule', 'shadowrocket'): ShadowrocketFile,
    ('.yaml', 'mihomo'): ClashYamlFile,
    ('.yml', 'mihomo'): ClashYamlFile,
}

def _dispatch_fom(filepath: str, client: str, data=None):
    ext = os.path.splitext(filepath)[1].lower()
    if is_binary_resource(filepath, data=data):
        return BinaryResourceFOM(filepath)
    target_cls = _STRUCTURED_CONFIG_MAP.get((ext, client))
    if target_cls is not None:
        return target_cls(filepath)
    if ext in ('.yaml', '.yml'):
        if client == 'mihomo' or (data is None and not os.path.exists(filepath)):
            return ClashYamlFile(filepath)
        from rule_framework.client_paths import recognizes_mihomo_yaml
        if recognizes_mihomo_yaml(filepath, data=data):
            return ClashYamlFile(filepath)
        return PlainFileFOM(filepath)
    if ext == '.json':
        return JSONFileFOM(filepath)
    if ext == '.stoverride':
        return StashOverrideFile(filepath)
    if ext in ('.plugin', '.lnplugin', '.lnscript'):
        return LoonFile(filepath)
    if ext == '.sgmodule':
        return SurgeFile(filepath)
    if ext == '.list':
        return StandardListFile(filepath)
    if ext == '.txt':
        return PlainFileFOM(filepath)
    if ext in ('.conf', '.snippet', '.qxrewrite'):
        return INIFileFOM(filepath)
    return None

FOM_REGISTRY = {ext: (lambda fp, r, _e=ext: _dispatch_fom(fp, r)) for ext in (
    '.json', '.list', '.yaml', '.yml', '.stoverride', '.txt',
    '.plugin', '.lnplugin', '.lnscript', '.sgmodule', '.conf', '.snippet', '.qxrewrite'
)}

_NATIVE_FOM_REGISTRY = dict(FOM_REGISTRY)
_NATIVE_SOURCE_LOADERS = {
    cls: (cls.load, cls._load_bytes)
    for cls in (ClashYamlFile, ClashTextPayloadFile, ClashClassicalListFile)
}

def get_fom_for_file(filepath: str, *, base_dir=None, data=None):
    import os
    ext = os.path.splitext(filepath)[1].lower()
    path_lower = client_for_path(filepath, base_dir=base_dir, data=data).lower()
    
    if is_binary_resource(filepath, data=data):
        return BinaryResourceFOM(filepath)

    router = FOM_REGISTRY.get(ext)
    if router:
        if data is not None and router is _NATIVE_FOM_REGISTRY.get(ext):
            return _dispatch_fom(filepath, path_lower, data=data)
        return router(filepath, path_lower)
    return PlainFileFOM(filepath)

def get_or_create_fom(filepath: str, *, settings=None):
    fom = get_fom_for_file(filepath, base_dir=(settings or {}).get('base_dir'))
    if fom is None:
        return None
    from copy import deepcopy
    fom.settings = deepcopy(settings or {})
    if os.path.exists(filepath):
        fom.load()
    else:
        base_name = os.path.splitext(os.path.basename(filepath))[0]
        if hasattr(fom, 'scaffold'):
            fom.scaffold(base_name)
    return fom

_NATIVE_GET_FOM = get_fom_for_file
_NATIVE_LOAD_FOM = get_or_create_fom


def _owns_native_load(path):
    extension = os.path.splitext(path)[1].lower()
    return (get_or_create_fom is _NATIVE_LOAD_FOM and get_fom_for_file is _NATIVE_GET_FOM
            and FOM_REGISTRY.get(extension) is _NATIVE_FOM_REGISTRY.get(extension))


def _load_native_source_bytes(fom, target_path, data):
    """Keep stock provider path context while honoring custom loader lifecycles."""
    methods = _NATIVE_SOURCE_LOADERS.get(type(fom))
    if (methods is None or not _owns_native_load(target_path)
            or getattr(fom.load, '__func__', None) is not methods[0]
            or getattr(fom._load_bytes, '__func__', None) is not methods[1]):
        return False
    fom._load_bytes(data)
    return True


def _escape_actions_annotation(message: str) -> str:
    return str(message).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def validate_config(config, *, config_path=None):
    if not isinstance(config, dict):
        raise ValueError("Config must be a dictionary")
    valid_top_level = {'missions', 'tasks', 'settings', 'sources', 'primary_source'}
    for k in config.keys():
        if k not in valid_top_level:
            raise ValueError(f"Unrecognized top-level key: {k}")
            
    if 'settings' in config and not isinstance(config['settings'], dict):
        raise ValueError('settings must be a dictionary')
    for key in ('missions', 'tasks'):
        if key in config and not isinstance(config[key], list):
            raise ValueError(f'{key} must be a list')
    if 'sources' in config:
        if config['sources'] is None or not isinstance(config['sources'], list):
            raise ValueError("'sources' must be a list, got null or invalid type")
    if not any(key in config for key in ('missions', 'tasks', 'sources', 'primary_source')):
        raise ValueError('Config must declare tasks or missions or sources')


    settings = config.get('settings', {})
    for key in ('author', 'repo'):
        if key in settings and not isinstance(settings[key], str):
            raise ValueError(f'{key} must be a string')
    from rule_framework.metadata import resolve_signature
    resolve_signature(settings)
    for key, default in (('base_dir', os.getcwd()), ('hooks_dir', 'rule_framework/hooks'),
                         ('log_file', 'modifier_logs.log')):
        value = settings.get(key, default)
        if not isinstance(value, (str, os.PathLike)) or not os.fspath(value).strip():
            raise ValueError(f'{key} must be a non-empty path')
    if not os.path.isdir(settings.get('base_dir', os.getcwd())):
        raise ValueError('base_dir must exist as a directory')
    base_dir = os.path.realpath(settings.get('base_dir', os.getcwd()))
    log_file = os.fspath(settings.get('log_file', 'modifier_logs.log'))
    log_path = os.path.normcase(os.path.realpath(log_file if os.path.isabs(log_file)
                                              else os.path.join(base_dir, log_file)))
    # A hard-linked log can append into protected files through an unrelated
    # path. Require a dedicated file before opening any logging handler.
    if os.path.isfile(log_path) and os.stat(log_path).st_nlink > 1:
        raise ValueError('log_file must use a dedicated file with a single hard link')
    if config_path is not None:
        configuration_path = os.path.normcase(os.path.realpath(config_path))
        if log_path == configuration_path:
            raise ValueError('log_file must be separate from the maintenance configuration file')
    for directory in ('rule', 'rewrite', 'script'):
        managed_path = os.path.normcase(os.path.realpath(os.path.join(base_dir, directory)))
        try:
            inside = os.path.commonpath((managed_path, log_path)) == managed_path
        except ValueError:
            inside = False
        if inside:
            raise ValueError('log_file must be outside managed directories (rule, rewrite, script)')
    recovery_path = os.path.normcase(os.path.realpath(os.path.join(base_dir, RECOVERY_DIRECTORY)))
    try:
        inside_recovery = os.path.commonpath((recovery_path, log_path)) == recovery_path
    except ValueError:
        inside_recovery = False
    if inside_recovery:
        raise ValueError('log_file must be outside the reserved save recovery directory')
    from rule_framework.sources import SOURCES_STATE_FILENAME
    manifest_path = os.path.normcase(os.path.realpath(os.path.join(base_dir, SOURCES_STATE_FILENAME)))
    if log_path == manifest_path:
        raise ValueError('log_file must be outside the reserved source state file')
    from rule_framework.action_receipts import RECEIPTS_FILENAME
    receipts_path = os.path.normcase(os.path.realpath(os.path.join(base_dir, RECEIPTS_FILENAME)))
    if log_path == receipts_path:
        raise ValueError('log_file must be outside the reserved action receipts file')
    if not isinstance(settings.get('dry_run', False), bool):
        raise ValueError('dry_run must be a boolean')
    from zoneinfo import ZoneInfo
    timezone = settings.get('timezone', 'Asia/Shanghai')
    try:
        ZoneInfo(timezone)
    except Exception as error:
        raise ValueError(f'Invalid timezone: {timezone}') from error
    log_level = settings.get('log_level', 'INFO')
    if not isinstance(log_level, str) or log_level.upper() not in logging.getLevelNamesMapping():
        raise ValueError('log_level must name a logging level')
    from rule_framework.sources import parse_primary_source, parse_sources
    seen_ids = set()
    if 'primary_source' in config:
        parse_primary_source(config, base_dir=base_dir, seen_ids=seen_ids, manifest=None)
    if 'sources' in config:
        parse_sources(config, base_dir=base_dir, manifest=None, seen_ids=seen_ids)

def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Run ordered maintenance Tasks and optionally publish saved products.')
    parser.add_argument('config_path', nargs='?')
    parser.add_argument('--publish', action='store_true', help='Commit saved managed products and push the configured branch')
    parser.add_argument('--sync-upstream', action='store_true', help='Synchronize the primary upstream repository before running maintenance Tasks')
    parser.add_argument('--upstream-max-seconds', type=float, help='Override the primary source preparation time budget in seconds (positive finite number)')
    parser.add_argument('--remote', default='origin')
    parser.add_argument('--branch', default='master')
    parser.add_argument('--commit-message', default='Sync from upstream and modify files')
    parser.add_argument('--log-file', help='Override the maintenance log path for this execution')
    parser.add_argument('--recover-only', action='store_true', help='Recover an interrupted save and exit')
    parser.add_argument('--base-dir', help='Recovery root used with --recover-only; defaults to the working directory')
    args = parser.parse_args(argv)
    if args.upstream_max_seconds is not None:
        try:
            parse_limits({'max_seconds': args.upstream_max_seconds})
        except ValueError as error:
            parser.error(str(error))
    if args.recover_only:
        if args.config_path or args.publish or args.upstream_max_seconds is not None:
            parser.error('--recover-only uses --base-dir and its own recovery operation')
        base_dir = os.path.abspath(args.base_dir or os.getcwd())
        if not os.path.isdir(base_dir):
            print(f'Recovery root must exist as a directory: {base_dir}', file=sys.stderr)
            sys.exit(1)
        recovery_settings = {'base_dir': base_dir, 'log_file': args.log_file or 'modifier_logs.log'}
        try:
            validate_config({'settings': recovery_settings, 'tasks': []})
            setup_logging(recovery_settings)
        except Exception as error:
            print(f'Save recovery configuration failed: {error}', file=sys.stderr)
            sys.exit(1)
        recovery = recover_saved_files(base_dir)
        print(f'Save recovery status={recovery.status} state={recovery.state} journal={recovery.recovery_path}')
        if recovery.status == 'failed':
            print(f'Save recovery failed: {recovery.reason}', file=sys.stderr)
            sys.exit(1)
        return recovery
    if args.base_dir:
        parser.error('--base-dir is used with --recover-only')
    if not args.config_path:
        parser.print_usage(sys.stderr)
        sys.exit(1)
    config_path = args.config_path
    if not os.path.isfile(config_path):
        print(f'Config file not found: {config_path}', file=sys.stderr)
        sys.exit(1)
    try:
        yaml = YAML()
        with open(config_path, 'r', encoding='utf-8-sig') as source:
            config = yaml.load(source)
    except Exception as error:
        print(f'Configuration load failed: {error}', file=sys.stderr)
        sys.exit(1)
    if args.log_file and isinstance(config, dict) and isinstance(config.get('settings', {}), dict):
        config = dict(config, settings=dict(config.get('settings', {}), log_file=args.log_file))
    if args.sync_upstream and isinstance(config, dict) and 'primary_source' not in config:
        config = dict(config, primary_source={
            'id': DEFAULT_PRIMARY_SOURCE_ID,
            'url': DEFAULT_PRIMARY_SOURCE_URL,
            'ref': DEFAULT_PRIMARY_SOURCE_REF,
            'enabled': True,
            'remote': DEFAULT_PRIMARY_SOURCE_REMOTE,
        })
    if args.upstream_max_seconds is not None:
        if not isinstance(config, dict) or not isinstance(config.get('primary_source'), dict):
            parser.error('--upstream-max-seconds requires --sync-upstream or a primary_source configuration')
        primary = dict(config['primary_source'])
        limits = primary.get('limits', {})
        if not isinstance(limits, dict):
            parser.error('primary_source limits must be a dictionary')
        try:
            primary['limits'] = parse_limits(dict(limits, max_seconds=args.upstream_max_seconds))
        except ValueError as error:
            parser.error(str(error))
        config = dict(config, primary_source=primary)
    publication = PublicationOptions(args.remote, args.branch, args.commit_message) if args.publish else None
    result = run_maintenance(config, config_path=os.path.abspath(config_path), publication=publication)

    from rule_framework.sources import SourceStatus, SOURCES_STATE_FILENAME
    seen_warnings = set()
    for sr in result.source_results:
        if sr.status in (SourceStatus.USING_REPOSITORY_COPY, SourceStatus.MISSING):
            is_upstream_removed = sr.reason and 'Upstream removed file' in sr.reason
            if sr.source.primary and not is_upstream_removed:
                w_key = (sr.source.id, sr.status, sr.reason)
                w_msg = f"Source '{sr.source.id}' status={sr.status}: {sr.reason or 'refresh failed'}"
            else:
                w_key = (sr.source.id, sr.status, sr.target, sr.reason)
                w_msg = f"Source '{sr.source.id}' status={sr.status} target={sr.target}: {sr.reason or 'refresh failed'}"
            if w_key not in seen_warnings:
                seen_warnings.add(w_key)
                print(f"::warning::{_escape_actions_annotation(w_msg)}")

    counts = {state: sum(task.status == state for task in result.task_results)
              for state in ('success', 'failed', 'skipped')}
    print(f'Maintenance status={result.status} Tasks success={counts["success"]} '
          f'failed={counts["failed"]} skipped={counts["skipped"]}; '
          f'storage={result.save_result.state if result.save_result else "not_attempted"}; dry_run={result.dry_run}')

    removed_source_ids = []
    removed_target_count = 0
    if isinstance(config, dict) and result.save_result is not None:
        base_dir = os.path.abspath((config.get('settings') or {}).get('base_dir', os.getcwd()) if isinstance(config.get('settings'), dict) else os.getcwd())
        active_ids = {sr.source.id for sr in result.source_results}
        if isinstance(config.get('sources'), list):
            for item in config['sources']:
                if isinstance(item, dict) and isinstance(item.get('id'), str):
                    active_ids.add(item['id'])
        if isinstance(config.get('primary_source'), dict) and isinstance(config['primary_source'].get('id'), str):
            active_ids.add(config['primary_source']['id'])
        from rule_framework.sources import SourcesManifest
        removed_source_ids, removed_target_count = SourcesManifest.summarize_removed(base_dir, active_ids)

    if result.source_results or removed_source_ids:
        from rule_framework.sources import count_source_statuses
        scounts = count_source_statuses(result.source_results)
        print(f'Sources success={scounts["success"]} repository_copy={scounts["using_repository_copy"]} '
              f'failed={scounts["failed"]} disabled={scounts["disabled"]}'
              + (f' removed_sources={len(removed_source_ids)} removed_files={removed_target_count}' if removed_source_ids else ''))

    if result.publication_result:
        published = result.publication_result
        print(f'Git status={published.status} remote={published.remote} branch={published.branch} '
              f'commit={published.commit_state} local_commit={published.local_commit} '
              f'push={published.push_state} index={published.index_state}')
    if result.status == 'failed':
        print(f'Maintenance failed: {_escape_actions_annotation(result.reason)}', file=sys.stderr)
        sys.exit(1)
    return result


def run_maintenance(config, *, config_path=None, storage=None, publication=None, git=None, http=None, git_fetcher=None):
    """Apply maintenance, return known phase results and release the run's log."""
    ensure_framework_io('run_maintenance()')
    try:
        return _run_maintenance(config, config_path=config_path, storage=storage,
                                publication=publication, git=git, http=http, git_fetcher=git_fetcher)
    finally:
        for handler in tuple(logger.handlers):
            handler.close()
            logger.removeHandler(handler)


def _run_maintenance(config, *, config_path=None, storage=None, publication=None, git=None, http=None, git_fetcher=None):
    from contextlib import ExitStack
    from dataclasses import replace

    resources = ExitStack()
    result = None
    try:
        result = _perform_maintenance(config, config_path=config_path, storage=storage,
                                      publication=publication, git=git, http=http,
                                      git_fetcher=git_fetcher, _resources=resources)
    finally:
        try:
            resources.close()
        except Exception as error:
            reason = f'Temporary maintenance state cleanup failed: {error}'
            logger.error(reason)
            if result is not None:
                result = replace(result, status='failed',
                                 reason=f'{result.reason}; {reason}' if result.reason else reason)
    return result


def _perform_maintenance(config, *, config_path=None, storage=None, publication=None, git=None,
                         http=None, git_fetcher=None, _resources):
    prep = None
    try:
        validate_config(config, config_path=config_path)
        if publication is not None:
            if not isinstance(publication, PublicationOptions):
                raise ValueError('publication must be PublicationOptions')
            publication.validate()
        settings = dict(config.get('settings', {}))
        base_dir = os.path.abspath(settings.get('base_dir', os.getcwd()))
        settings['base_dir'] = base_dir
        hooks_dir = settings.get('hooks_dir', os.path.join('rule_framework', 'hooks'))
        settings['hooks_dir'] = hooks_dir if os.path.isabs(hooks_dir) else os.path.join(base_dir, hooks_dir)
        setup_logging(settings)
        recovery = recover_saved_files(base_dir, storage=storage, dry_run=settings.get('dry_run', False))
        if recovery.status == 'failed':
            return MaintenanceResult('failed', (), reason=recovery.reason, save_result=recovery)

        from rule_framework.state_spool import StateSpool
        spool = StateSpool()
        _resources.callback(spool.close)
        from rule_framework.action_receipts import ActionReceipts
        receipts = ActionReceipts.load(base_dir)
        has_sources = ('sources' in config) or ('primary_source' in config)
        manifest_path = os.path.join(base_dir, SOURCES_STATE_FILENAME)
        manifest_file_exists = os.path.isfile(manifest_path)

        if not has_sources and not manifest_file_exists and git_fetcher is None:
            validate_source_references_and_manifest(
                config, base_dir=base_dir, sources=(), manifest=None, primary_source=None
            )
            prep = None
            source_results = ()
            manifest = None
            source_context = None
        else:
            from rule_framework.source_maintenance import prepare_sources
            prep = prepare_sources(
                config, base_dir=base_dir, settings=settings, git_fetcher=git_fetcher, http=http,
                _allow_spill=True, _owned_loader=_owns_native_load, _state_spool=spool,
            )
            source_results = prep.source_results
            manifest = prep.manifest
            source_context = prep.context

        tasks = build_tasks(config, config_path=config_path)
        execution = execute_tasks(tasks, settings=settings,
                                  load_fom=lambda path: get_or_create_fom(path, settings=settings),
                                  _owned_loader=_owns_native_load,
                                  source_context=source_context,
                                  _state_spool=spool, action_receipts=receipts)
        if prep is not None:
            prep.context = None
        source_context = None
    except Exception as error:
        print(f'Global maintenance failure: {error}', file=sys.stderr)
        return MaintenanceResult('failed', (), reason=str(error))
    finally:
        if prep is not None and prep.owned_fetcher is not None:
            prep.owned_fetcher.close()

    for sr in source_results:
        logger.info("Source Result: source=%s status=%s target=%s version=%s%s",
                    sr.source.id, sr.status, sr.target, sr.version or 'none',
                    f"; reason={sr.reason}" if sr.reason else "")
    if source_results:
        from rule_framework.sources import count_source_statuses
        scounts = count_source_statuses(source_results)
        logger.info("Source Results: total=%d, success=%d, using_repository_copy=%d, missing=%d, disabled=%d",
                    len(source_results), scounts['success'], scounts['using_repository_copy'], scounts['missing'], scounts['disabled'])


    log_task_results(execution)
    if settings.get('dry_run'):
        logger.info('Dry run completed; managed products unchanged')
        preview = PublicationResult('skipped', publication.remote, publication.branch) if publication else None
        if preview:
            logger.info('Git Publication: status=skipped remote=%s branch=%s commit=not_attempted push=not_attempted reason=dry_run',
                        preview.remote, preview.branch)
        return MaintenanceResult('success', execution.task_results, dry_run=True,
                                 save_result=SaveResult('success', 'unchanged'), publication_result=preview,
                                 source_results=tuple(source_results))

    foms_to_save = execution.fom_cache._save_view()
    try:
        receipt_adapter = receipts.as_adapter(execution.workspace)
    except Exception as error:
        return MaintenanceResult('failed', execution.task_results, reason=str(error),
                                 save_result=SaveResult('failed', 'unchanged', reason=str(error)),
                                 source_results=tuple(source_results))
    if receipt_adapter.records or os.path.isfile(receipt_adapter.filepath):
        foms_to_save[receipt_adapter.filepath] = receipt_adapter
    if manifest is not None:
        manifest_abs = os.path.normpath(os.path.join(base_dir, SOURCES_STATE_FILENAME)).replace('\\', '/')
        manifest_adapter = SourcesStateAdapter(manifest_abs, manifest)
        foms_to_save[manifest_abs] = manifest_adapter

    saved = save_managed_files(
        foms_to_save, base_dir=base_dir, storage=storage,
        context=lambda path: task_logging(target=Target(path, (), base_dir=base_dir),
                                         tasks=execution.file_tasks.get(path, tasks)),
    )
    logger.info('Storage Result: status=%s state=%s processed=%d changed=%d recovery=%s reason=%s',
                saved.status, saved.state, len(saved.processed_files), len(saved.changed_files),
                saved.recovery_path, saved.reason)
    product_paths = tuple(path for path in saved.processed_files
                          if os.path.normcase(os.path.abspath(path)) !=
                          os.path.normcase(os.path.abspath(receipt_adapter.filepath)))
    product_changes = tuple(path for path in saved.changed_files if path in product_paths)
    product_save = SaveResult(saved.status, saved.state, product_paths, product_changes,
                              saved.recovery_path, saved.reason)
    if saved.status == 'failed':
        return MaintenanceResult('failed', execution.task_results, product_paths,
                                 reason=saved.reason, save_result=product_save,
                                 source_results=tuple(source_results))
    published = publish_saved_files(base_dir, saved.processed_files, options=publication, git=git) if publication else None
    return MaintenanceResult(published.status if published else 'success', execution.task_results,
                             product_paths, reason=published.reason if published else None,
                             save_result=product_save, publication_result=published,
                             source_results=tuple(source_results))


if __name__ == '__main__':
    main()

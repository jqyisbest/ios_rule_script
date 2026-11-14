"""Orchestration and preparation for maintenance sources."""

import hashlib
import copy
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from rule_framework.source_limits import SourceBudget

from rule_framework.sources import (
    MaintenanceSource,
    SourceExecutionContext,
    SourceResult,
    SourceStatus,
    SourceTargetClaim,
    SourcesManifest,
    SOURCES_STATE_FILENAME,
    fetch_source_content,
    parse_primary_source,
    parse_sources,
    resolve_repository_copy_fallback,
    stage_source_content,
    source_target_claims,
    validate_source_references_and_manifest,
    validate_source_target,
    validate_source_target_claims,
)

logger = logging.getLogger('RuleFramework')


class _SourceMappingError(ValueError):
    """An invalid or ambiguous expanded mapping is a configuration error."""


@dataclass
class SourcePreparationResult:
    source_results: list[SourceResult]
    manifest: Optional[SourcesManifest]
    context: Optional[SourceExecutionContext]
    owned_fetcher: Optional[Any] = None
    _state_spool: Optional[Any] = None


def _record_primary_fallback_results(
    *,
    primary_source: MaintenanceSource,
    fallback_targets: Sequence[str],
    base_dir: str,
    manifest: Optional[SourcesManifest],
    head_sha_local: Optional[str],
    reason_str: str,
    primary_source_results: list[SourceResult],
    missing_source_targets: set[str],
):
    if manifest is not None:
        manifest.register_source(primary_source, targets=fallback_targets)

    if not fallback_targets:
        if manifest is not None:
            manifest.record_refresh(primary_source.id, '.', SourceStatus.USING_REPOSITORY_COPY, version=head_sha_local)
        primary_source_results.append(
            SourceResult(
                primary_source,
                SourceStatus.USING_REPOSITORY_COPY,
                target='.',
                version=head_sha_local,
                reason=reason_str,
            )
        )
        logger.warning(
            "Primary source '%s' refresh fallback; maintaining existing repository copies: %s",
            primary_source.id,
            reason_str,
        )
        return

    for t in fallback_targets:
        sr = resolve_repository_copy_fallback(
            primary_source,
            t,
            base_dir=base_dir,
            manifest=manifest,
            default_version=head_sha_local,
            reason=reason_str,
            missing_source_targets=missing_source_targets,
        )
        primary_source_results.append(sr)

    logger.warning(
        "Primary source '%s' refresh fallback across %d target(s); maintaining existing repository copies: %s",
        primary_source.id,
        len(fallback_targets),
        reason_str,
    )


def _stage_and_maybe_spill(
    path: str,
    data: bytes,
    *,
    settings: dict,
    base_dir: str,
    staged_map: Any,
    allow_spill: bool,
    owned_loader: Optional[Any],
    spool: Optional[Any],
):
    import pickle
    from rule_framework.workspace import _native_model
    fom = stage_source_content(path, data, settings=settings, base_dir=base_dir)
    if (allow_spill and spool is not None and owned_loader is not None
            and owned_loader(path) and _native_model(fom)):
        try:
            spilled = spool.store(fom)
            if hasattr(staged_map, '_entries'):
                staged_map._entries[path] = spilled
            else:
                staged_map[path] = spilled
            return spilled
        except (pickle.PickleError, TypeError, AttributeError):
            pass
    staged_map[path] = fom
    return fom


def prepare_sources(
    config: dict,
    *,
    base_dir: str,
    settings: dict,
    manifest: Optional[SourcesManifest] = None,
    git_fetcher: Optional[Any] = None,
    http: Optional[Any] = None,
    _allow_spill: bool = False,
    _owned_loader: Optional[Any] = None,
    _state_spool: Optional[Any] = None,
) -> SourcePreparationResult:
    """Acquire, validate and prepare source inputs for task execution."""
    manifest_file_exists = os.path.isfile(os.path.join(base_dir, SOURCES_STATE_FILENAME))
    has_sources_config = 'sources' in config or 'primary_source' in config

    if not has_sources_config and not manifest_file_exists:
        return SourcePreparationResult(
            source_results=[],
            manifest=None,
            context=SourceExecutionContext(),
            owned_fetcher=None,
            _state_spool=_state_spool,
        )

    if manifest is None:
        manifest = SourcesManifest.load_or_create(base_dir, create=has_sources_config or manifest_file_exists)

    prior_manifest = copy.deepcopy(manifest.to_dict()) if manifest_file_exists and manifest is not None else None
    prior_files = {}
    rejected_new_files = {}

    def capture_original(path):
        from rule_framework.source_policy import OriginalSourceFile
        normalized = os.path.normpath(os.path.abspath(path)).replace('\\', '/')
        if normalized in prior_files:
            return
        if os.path.isfile(normalized):
            with open(normalized, 'rb') as original_stream:
                original = original_stream.read()
            if _state_spool is not None:
                prior_files[normalized] = OriginalSourceFile(True, spool_path=_state_spool.write_render_cache(original))
            else:
                prior_files[normalized] = OriginalSourceFile(True, data=original)
        else:
            prior_files[normalized] = OriginalSourceFile(False)

    seen_ids = set()
    primary_source = parse_primary_source(config, base_dir=base_dir, seen_ids=seen_ids, manifest=manifest)
    sources = parse_sources(config, base_dir=base_dir, manifest=manifest, seen_ids=seen_ids)
    validate_source_references_and_manifest(
        config, base_dir=base_dir, sources=sources, manifest=manifest, primary_source=primary_source
    )

    needs_git = (primary_source is not None) or any(s.type == 'git' and s.enabled for s in sources)
    owned_fetcher = None
    if needs_git and git_fetcher is None:
        from rule_framework.sources_git import GitFetcher
        git_fetcher = GitFetcher()
        owned_fetcher = git_fetcher

    try:
        active_source_ids = {s.id for s in sources}
        if primary_source is not None:
            active_source_ids.add(primary_source.id)
        if manifest is not None:
            for hist_sid, hist_sdata in sorted(manifest.sources.items()):
                if hist_sid not in active_source_ids:
                    hist_targets = hist_sdata.get('targets', [])
                    logger.info(
                        "Source '%s' removed from configuration; retaining historical ownership for %d target(s): %s",
                        hist_sid,
                        len(hist_targets),
                        ', '.join(hist_targets),
                    )

        primary_source_results = []
        secondary_source_results = []
        if _allow_spill:
            from rule_framework.state_spool import StateSpool, _StagedFOMMap
            if _state_spool is None:
                _state_spool = StateSpool()
            staged_foms = _StagedFOMMap(spool=_state_spool, owned_loader=_owned_loader)
        else:
            staged_foms = {}
        missing_source_targets = set()
        missing_source_directories = set()
        claimed_targets = {}
        target_claims = source_target_claims(sources, manifest)

        def claim_source_target(target, source_id):
            target_claims.append(SourceTargetClaim(target, source_id))
            target_key = os.path.normcase(target)
            if target_key in claimed_targets and claimed_targets[target_key] != source_id:
                raise ValueError(
                    f"Source target overlap conflict on '{target}' between '{claimed_targets[target_key]}' and '{source_id}'"
                )
            claimed_targets[target_key] = source_id

        if manifest is not None:
            for hist_t, hist_data in manifest.targets.items():
                claimed_targets[os.path.normcase(hist_t)] = hist_data.get('source_id')

        secondary_static_targets = set()
        for s in sources:
            if s.target:
                secondary_static_targets.add(os.path.normcase(s.target))
            for m in s.mappings:
                secondary_static_targets.add(os.path.normcase(m.target))

        # Step 2A: Isolated primary preview & target ownership reservation (no production writes yet)
        primary_preview = None
        primary_budget = None
        primary_retry_targets = set()
        primary_fetch_error = None
        prior_primary_targets = (
            list(manifest.sources[primary_source.id]['targets'])
            if (primary_source is not None and manifest is not None and primary_source.id in manifest.sources)
            else []
        )
        head_sha_local, head_managed_files = (
            git_fetcher.list_local_head_managed_files(base_dir) if primary_source is not None else (None, [])
        )
        fallback_primary_targets = list(prior_primary_targets)
        if primary_source is not None and not fallback_primary_targets:
            for hf in head_managed_files:
                hf_key = os.path.normcase(hf)
                if hf_key in claimed_targets and claimed_targets[hf_key] != primary_source.id:
                    continue
                if hf_key in secondary_static_targets or any(
                    hf_key.startswith(st.rstrip('/') + '/') for st in secondary_static_targets
                ):
                    continue
                fallback_primary_targets.append(hf)

        if primary_source is not None:
            if not primary_source.enabled:
                for t_rel in fallback_primary_targets:
                    claim_source_target(t_rel, primary_source.id)
                if manifest is not None:
                    manifest.register_source(primary_source, targets=fallback_primary_targets)
                if fallback_primary_targets:
                    for t_rel in fallback_primary_targets:
                        if manifest is not None:
                            manifest.record_refresh(primary_source.id, t_rel, SourceStatus.DISABLED)
                        primary_source_results.append(
                            SourceResult(primary_source, SourceStatus.DISABLED, target=t_rel, reason='Source is disabled')
                        )
                else:
                    if manifest is not None:
                        manifest.record_refresh(primary_source.id, '.', SourceStatus.DISABLED)
                    primary_source_results.append(
                        SourceResult(primary_source, SourceStatus.DISABLED, target='.', reason='Source is disabled')
                    )
                logger.info("Primary source '%s' is disabled; maintaining existing repository copies", primary_source.id)
            else:
                try:
                    primary_budget = SourceBudget(primary_source)
                    git_fetcher.budget = primary_budget
                    primary_preview = git_fetcher.preview_primary_sync(base_dir, primary_source)
                    if prior_manifest is not None:
                        for target, upstream_oid in primary_preview.upstream_managed_oids.items():
                            if target in primary_preview.merged_changed_blobs:
                                continue
                            record = prior_manifest.get('targets', {}).get(target)
                            needs_retry = record is None or record.get('last_version') is None
                            if record and not needs_retry and record.get('last_version') != primary_preview.upstream_sha:
                                previous_version = record.get('last_version')
                                if previous_version:
                                    previous_blob = git_fetcher.run_git(primary_preview.preview_repo,
                                        ['rev-parse', '--verify', '--end-of-options', f'{previous_version}:{target}'])
                                    needs_retry = (previous_blob.returncode != 0 or
                                        previous_blob.stdout.decode('ascii', errors='replace').strip() != upstream_oid)
                                else:
                                    needs_retry = True
                            if needs_retry:
                                primary_preview.merged_changed_blobs[target] = git_fetcher.read_blob(
                                    primary_preview.preview_repo, upstream_oid)
                                primary_retry_targets.add(target)
                except Exception as p_err:
                    primary_fetch_error = p_err
                finally:
                    if primary_budget is not None:
                        primary_budget.pause()
                    git_fetcher.budget = None

                if primary_preview is not None:
                    primary_claimed_list = list(primary_preview.upstream_managed_oids.keys())
                    for extra_t in prior_primary_targets + primary_preview.merge_deleted_managed_paths:
                        if extra_t not in primary_preview.upstream_managed_oids and extra_t not in primary_claimed_list:
                            primary_claimed_list.append(extra_t)
                    for t_rel in primary_claimed_list:
                        claim_source_target(t_rel, primary_source.id)
                else:
                    for t_rel in fallback_primary_targets:
                        claim_source_target(t_rel, primary_source.id)

        # Step 2B & Step 3: Secondary source acquisition and full cross-source overlap validation
        for source in sources:
            if git_fetcher is not None:
                git_fetcher.budget = SourceBudget(source)
            if source.type in ('http', 'https'):
                norm_target_path = os.path.normpath(os.path.join(base_dir, source.target)).replace('\\', '/')
                t_key = os.path.normcase(source.target)
                if t_key in claimed_targets and claimed_targets[t_key] != source.id:
                    raise ValueError(f"Source target overlap conflict on '{source.target}' between '{claimed_targets[t_key]}' and '{source.id}'")
                claimed_targets[t_key] = source.id

                if manifest is not None:
                    manifest.register_source(source)
                if not source.enabled:
                    if manifest is not None:
                        manifest.record_refresh(source.id, source.target, SourceStatus.DISABLED)
                    secondary_source_results.append(SourceResult(source, SourceStatus.DISABLED, target=source.target, reason='Source is disabled'))
                    continue
                try:
                    data = fetch_source_content(source, http=http)
                    from rule_framework.source_policy import validate_source_content
                    validate_source_content(data, norm_target_path, purpose=source.purpose, allow_empty=source.allow_empty)
                    capture_original(norm_target_path)

                    data_version = hashlib.sha256(data).hexdigest()
                    data_len = len(data)
                    _stage_and_maybe_spill(
                        norm_target_path, data, settings=settings, base_dir=base_dir,
                        staged_map=staged_foms, allow_spill=_allow_spill,
                        owned_loader=_owned_loader, spool=_state_spool,
                    )
                    data = None

                    if manifest is not None:
                        manifest.record_refresh(source.id, source.target, SourceStatus.SUCCESS, version=data_version)
                    secondary_source_results.append(SourceResult(source, SourceStatus.SUCCESS, target=source.target,
                                                                 version=data_version))
                    logger.info("Source '%s' successfully fetched: target=%s, size=%d bytes", source.id, source.target, data_len)
                except Exception as error:
                    sr = resolve_repository_copy_fallback(
                        source, source.target, base_dir=base_dir, manifest=manifest,
                        reason=str(error), missing_source_targets=missing_source_targets
                    )
                    secondary_source_results.append(sr)
                    if sr.status == SourceStatus.USING_REPOSITORY_COPY:
                        logger.warning("Source '%s' fetch failed; maintaining existing repository copy at %s: %s",
                                       source.id, source.target, error)
                    else:
                        logger.warning("Source '%s' fetch failed and repository copy missing for %s: %s",
                                       source.id, source.target, error)

            elif source.type == 'git':
                if manifest is not None:
                    manifest.register_source(source)
                if not source.enabled:
                    known_targets = (
                        list(manifest.sources[source.id]['targets'])
                        if manifest and source.id in manifest.sources and manifest.sources[source.id]['targets']
                        else [m.target for m in source.mappings]
                    )
                    for t in known_targets:
                        if manifest is not None:
                            manifest.record_refresh(source.id, t, SourceStatus.DISABLED)
                        secondary_source_results.append(SourceResult(source, SourceStatus.DISABLED, target=t, reason='Source is disabled'))
                    for m in source.mappings:
                        if getattr(m, 'kind', 'file') == 'directory':
                            missing_source_directories.add(os.path.normpath(os.path.join(base_dir, m.target)).replace('\\', '/'))
                            missing_source_directories.add(m.target.replace('\\', '/'))
                    continue

                acquired_git = {}
                acquired_policies = {}
                fetch_error = None
                seen_targets_in_source = {}

                def claim_target(mapping, target):
                    normalized = os.path.normpath(target).replace('\\', '/')
                    try:
                        validate_source_target(normalized, base_dir, allow_directory=False)
                    except ValueError as error:
                        raise _SourceMappingError(str(error)) from error
                    key = os.path.normcase(os.path.realpath(os.path.join(base_dir, normalized)))
                    if key in seen_targets_in_source:
                        previous = seen_targets_in_source[key]
                        raise _SourceMappingError(
                            f"Source '{source.id}' mapping collision on target '{normalized}' between "
                            f"'{previous.kind}:{previous.path}' and '{mapping.kind}:{mapping.path}'"
                        )
                    seen_targets_in_source[key] = mapping
                    return normalized

                try:
                    repo_path = git_fetcher.resolve_repo_path(source.url)
                    commit_sha = git_fetcher.resolve_ref(repo_path, source.ref)
                    tree_entries = git_fetcher.list_tree(repo_path, commit_sha)
                    tree_by_path = {entry[3]: entry for entry in tree_entries}

                    for m in source.mappings:
                        if m.kind == 'file':
                            if m.path in tree_by_path:
                                mode, otype, oid, path = tree_by_path[m.path]
                                if mode in ('120000', '160000'):
                                    logger.warning("Git source '%s' path '%s' is symlink/submodule; skipping", source.id, m.path)
                                    continue
                                norm_target = claim_target(m, m.target)
                                data = git_fetcher.read_blob(repo_path, oid)
                                acquired_git[norm_target] = (data, commit_sha)
                                acquired_policies[norm_target] = m
                        elif m.kind == 'directory':
                            dir_prefix = m.path.strip('/') + '/' if m.path.strip('/') and m.path != '.' else ''
                            for mode, otype, oid, path in tree_entries:
                                if mode in ('120000', '160000') or otype != 'blob':
                                    continue
                                if dir_prefix:
                                    if not path.startswith(dir_prefix):
                                        continue
                                    rel = path[len(dir_prefix):]
                                else:
                                    rel = path
                                if rel.startswith('/') or '..' in rel.split('/'):
                                    continue
                                expanded_target = claim_target(m, os.path.join(m.target, rel))
                                data = git_fetcher.read_blob(repo_path, oid)
                                acquired_git[expanded_target] = (data, commit_sha)
                                acquired_policies[expanded_target] = m
                except _SourceMappingError:
                    raise
                except Exception as error:
                    fetch_error = error

                if fetch_error is not None:
                    known_targets = list(manifest.sources[source.id]['targets']) if manifest and source.id in manifest.sources and manifest.sources[source.id]['targets'] else []
                    if not known_targets:
                        known_targets = [m.target for m in source.mappings]
                        if not known_targets and source.target:
                            known_targets = [source.target]
                    for t in known_targets:
                        sr = resolve_repository_copy_fallback(
                            source, t, base_dir=base_dir, manifest=manifest,
                            reason=str(fetch_error), missing_source_targets=missing_source_targets
                        )
                        secondary_source_results.append(sr)
                        if sr.status == SourceStatus.USING_REPOSITORY_COPY:
                            logger.warning("Git source '%s' fetch failed; maintaining existing repository copy at %s: %s", source.id, t, fetch_error)
                        else:
                            logger.warning("Git source '%s' fetch failed and repository copy missing for %s: %s", source.id, t, fetch_error)
                    for m in source.mappings:
                        if getattr(m, 'kind', 'file') == 'directory':
                            missing_source_directories.add(os.path.normpath(os.path.join(base_dir, m.target)).replace('\\', '/'))
                            missing_source_directories.add(m.target.replace('\\', '/'))
                    continue

                # Check expansion overlap conflicts before staging/saving
                for t_rel in acquired_git.keys():
                    claim_source_target(t_rel, source.id)

                # Stage acquired targets
                for t_rel, (data, version) in acquired_git.items():
                    norm_target_path = os.path.normpath(os.path.join(base_dir, t_rel)).replace('\\', '/')

                    data_version = hashlib.sha256(data).hexdigest()
                    data_len = len(data)
                    try:
                        from rule_framework.source_policy import validate_source_content
                        policy = acquired_policies[t_rel]
                        validate_source_content(data, norm_target_path, purpose=policy.purpose, allow_empty=policy.allow_empty)
                        capture_original(norm_target_path)
                        _stage_and_maybe_spill(
                            norm_target_path, data, settings=settings, base_dir=base_dir,
                            staged_map=staged_foms, allow_spill=_allow_spill,
                            owned_loader=_owned_loader, spool=_state_spool,
                        )
                        data = None

                        if manifest is not None:
                            manifest.register_target(source.id, t_rel)
                            manifest.record_refresh(source.id, t_rel, SourceStatus.SUCCESS, version=version)
                        secondary_source_results.append(SourceResult(source, SourceStatus.SUCCESS, target=t_rel, version=version))
                        logger.info("Source '%s' successfully fetched git target %s at %s", source.id, t_rel, version)
                    except Exception as error:
                        sr = resolve_repository_copy_fallback(
                            source, t_rel, base_dir=base_dir, manifest=manifest,
                            reason=str(error), missing_source_targets=missing_source_targets
                        )
                        secondary_source_results.append(sr)
                        if sr.status == SourceStatus.USING_REPOSITORY_COPY:
                            logger.warning(
                                "Git source '%s' candidate parsing failed for %s; maintaining existing repository copy: %s",
                                source.id, t_rel, error
                            )
                        else:
                            logger.warning(
                                "Git source '%s' candidate parsing failed and repository copy missing for %s: %s",
                                source.id, t_rel, error
                            )

                # Empty directory acceptance is explicit; retained local files remain usable.
                for mapping in source.mappings:
                    if mapping.kind != 'directory':
                        continue
                    mapped = [t for t in acquired_git if t.startswith(mapping.target.rstrip('/') + '/')]
                    if mapped:
                        continue
                    checker = getattr(git_fetcher, 'is_directory', None)
                    exists = checker(repo_path, commit_sha, mapping.path) if callable(checker) else False
                    if exists and mapping.allow_empty:
                        secondary_source_results.append(SourceResult(source, SourceStatus.SUCCESS, target=mapping.target, version=commit_sha, reason='Explicitly allowed empty directory'))
                        if manifest is not None:
                            manifest.record_refresh(source.id, mapping.target, SourceStatus.SUCCESS, version=commit_sha)
                    directory = os.path.join(base_dir, mapping.target)
                    if os.path.isdir(directory):
                        for folder, _dirs, names in os.walk(directory):
                            for name in sorted(names):
                                local = os.path.join(folder, name)
                                relative = os.path.relpath(local, base_dir).replace('\\', '/')
                                validate_source_target(relative, base_dir, allow_directory=False)
                                if manifest is not None:
                                    manifest.register_target(source.id, relative)

                # Check previously known targets deleted upstream
                previously_known = list(manifest.sources[source.id]['targets']) if manifest and source.id in manifest.sources else []
                for m in source.mappings:
                    if getattr(m, 'kind', 'file') == 'file' and m.target not in previously_known:
                        previously_known.append(m.target)

                for old_t in previously_known:
                    if old_t not in acquired_git:
                        sr = resolve_repository_copy_fallback(
                            source, old_t, base_dir=base_dir, manifest=manifest,
                            reason='Upstream removed file; maintaining repository copy', missing_source_targets=missing_source_targets
                        )
                        secondary_source_results.append(sr)
                        if sr.status == SourceStatus.USING_REPOSITORY_COPY:
                            logger.info("Source '%s' upstream deleted %s; maintaining repository copy", source.id, old_t)

                has_any_success = any(
                    sr.source.id == source.id and sr.status == SourceStatus.SUCCESS
                    for sr in secondary_source_results
                )
                if has_any_success and manifest is not None and source.id in manifest.sources:
                    manifest.sources[source.id]['last_status'] = SourceStatus.SUCCESS
                    manifest.sources[source.id]['last_version'] = commit_sha

                # Check for directory mappings that matched no files and had no prior targets
                for m in source.mappings:
                    if getattr(m, 'kind', 'file') == 'directory':
                        has_acquired = any(
                            t == m.target or t.startswith(m.target.rstrip('/') + '/')
                            for t in acquired_git
                        )
                        has_prior = any(
                            t == m.target or t.startswith(m.target.rstrip('/') + '/')
                            for t in previously_known
                        )
                        allowed_empty = m.allow_empty and any(r.source.id == source.id and r.target == m.target and r.status == SourceStatus.SUCCESS for r in secondary_source_results)
                        if not has_acquired and not has_prior and not allowed_empty:
                            norm_dir_path = os.path.normpath(os.path.join(base_dir, m.target)).replace('\\', '/')
                            if manifest is not None:
                                manifest.record_refresh(source.id, m.target, SourceStatus.MISSING)
                            secondary_source_results.append(SourceResult(source, SourceStatus.MISSING, target=m.target,
                                                                         reason=f"Directory mapping '{m.path}' selected no files"))
                            missing_source_targets.add(norm_dir_path)
                            missing_source_directories.add(norm_dir_path)
                            missing_source_directories.add(m.target.replace('\\', '/'))
                            logger.warning("Git source '%s' directory mapping '%s' -> '%s' selected no files", source.id, m.path, m.target)

        validate_source_target_claims(target_claims, base_dir=base_dir)

        # Step 4 & Step 5: Apply primary merge (or dry-run staging / fallback) now that all conflicts are validated
        if primary_source is not None and primary_source.enabled:
            if primary_fetch_error is not None:
                _record_primary_fallback_results(
                    primary_source=primary_source,
                    fallback_targets=fallback_primary_targets,
                    base_dir=base_dir,
                    manifest=manifest,
                    head_sha_local=head_sha_local,
                    reason_str=str(primary_fetch_error),
                    primary_source_results=primary_source_results,
                    missing_source_targets=missing_source_targets,
                )
            elif primary_preview is not None:
                git_fetcher.budget = primary_budget
                if primary_budget is not None:
                    primary_budget.resume()
                precondition_error = git_fetcher.check_working_tree_merge_preconditions(
                    base_dir,
                    primary_preview.incoming_added_paths,
                    already_up_to_date=primary_preview.already_up_to_date,
                )
                upstream_deleted_targets = []
                for dt in prior_primary_targets + primary_preview.merge_deleted_managed_paths:
                    if dt not in primary_preview.upstream_managed_oids and dt not in upstream_deleted_targets:
                        upstream_deleted_targets.append(dt)

                if settings.get('dry_run', False):
                    if precondition_error is not None or not primary_preview.merge_preview_ok:
                        fallback_reason = precondition_error or primary_preview.merge_preview_error or 'Primary merge preview failed'
                        _record_primary_fallback_results(
                            primary_source=primary_source,
                            fallback_targets=fallback_primary_targets,
                            base_dir=base_dir,
                            manifest=manifest,
                            head_sha_local=head_sha_local,
                            reason_str=fallback_reason,
                            primary_source_results=primary_source_results,
                            missing_source_targets=missing_source_targets,
                        )
                    else:
                        if manifest is not None:
                            manifest.register_source(
                                primary_source,
                                targets=list(primary_preview.upstream_managed_oids.keys()) + upstream_deleted_targets,
                            )
                        failed_primary_candidates = set()
                        for path_rel, blob_bytes in primary_preview.merged_changed_blobs.items():
                            norm_target_path = os.path.normpath(os.path.join(base_dir, path_rel)).replace('\\', '/')
                            try:
                                from rule_framework.source_policy import validate_source_content
                                validate_source_content(blob_bytes, norm_target_path, purpose=primary_source.purpose, allow_empty=primary_source.allow_empty)
                                capture_original(norm_target_path)
                                _stage_and_maybe_spill(
                                    norm_target_path, blob_bytes, settings=settings, base_dir=base_dir,
                                    staged_map=staged_foms, allow_spill=_allow_spill,
                                    owned_loader=_owned_loader, spool=_state_spool,
                                )
                            except Exception as error:
                                failed_primary_candidates.add(path_rel)
                                sr = resolve_repository_copy_fallback(
                                    primary_source, path_rel, base_dir=base_dir, manifest=manifest,
                                    default_version=primary_preview.head_sha, reason=str(error),
                                    missing_source_targets=missing_source_targets, register_target=True,
                                )
                                primary_source_results.append(sr)
                                logger.warning(
                                    "Primary source '%s' candidate parsing failed for %s; status=%s: %s",
                                    primary_source.id, path_rel, sr.status, error,
                                )
                        for t_rel in primary_preview.upstream_managed_oids.keys():
                            if t_rel in failed_primary_candidates:
                                continue
                            if manifest is not None:
                                manifest.register_target(primary_source.id, t_rel)
                                manifest.record_refresh(primary_source.id, t_rel, SourceStatus.SUCCESS, version=primary_preview.upstream_sha)
                            primary_source_results.append(
                                SourceResult(primary_source, SourceStatus.SUCCESS, target=t_rel, version=primary_preview.upstream_sha)
                            )
                        for old_t in upstream_deleted_targets:
                            sr = resolve_repository_copy_fallback(
                                primary_source, old_t, base_dir=base_dir, manifest=manifest,
                                default_version=primary_preview.head_sha,
                                reason='Upstream removed file; maintaining repository copy',
                                missing_source_targets=missing_source_targets, register_target=True
                            )
                            primary_source_results.append(sr)
                        if (manifest is not None and primary_source.id in manifest.sources
                                and (not failed_primary_candidates or any(
                                    sr.status == SourceStatus.SUCCESS for sr in primary_source_results))):
                            manifest.sources[primary_source.id]['last_status'] = SourceStatus.SUCCESS
                            manifest.sources[primary_source.id]['last_version'] = primary_preview.upstream_sha
                else:
                    if precondition_error is not None or not primary_preview.merge_preview_ok:
                        _record_primary_fallback_results(
                            primary_source=primary_source,
                            fallback_targets=fallback_primary_targets,
                            base_dir=base_dir,
                            manifest=manifest,
                            head_sha_local=head_sha_local,
                            reason_str=(precondition_error or primary_preview.merge_preview_error
                                        or 'Primary merge preview failed'),
                            primary_source_results=primary_source_results,
                            missing_source_targets=missing_source_targets,
                        )
                    else:
                        retained_deleted_bytes = {}
                        for old_t in upstream_deleted_targets:
                            norm_old_path = os.path.normpath(os.path.join(base_dir, old_t)).replace('\\', '/')
                            if os.path.isfile(norm_old_path):
                                with open(norm_old_path, 'rb') as rf:
                                    retained_deleted_bytes[old_t] = rf.read()

                        for original_target in set(primary_preview.upstream_managed_oids) | set(upstream_deleted_targets):
                            capture_original(os.path.join(base_dir, original_target))
                        rejected_primary = {}
                        for path_rel, blob_bytes in primary_preview.merged_changed_blobs.items():
                            absolute = os.path.normpath(os.path.join(base_dir, path_rel)).replace('\\', '/')
                            try:
                                from rule_framework.source_policy import validate_source_content
                                validate_source_content(blob_bytes, absolute, purpose=primary_source.purpose,
                                                        allow_empty=primary_source.allow_empty)
                                # Exercise the same parser/validator as the pure-sync path.
                                stage_source_content(absolute, blob_bytes, settings=settings, base_dir=base_dir)
                            except Exception as error:
                                rejected_primary[path_rel] = str(error)
                        merge_ok, merge_err = git_fetcher.apply_primary_merge(base_dir, primary_preview, primary_source)
                        if not merge_ok:
                            _record_primary_fallback_results(
                                primary_source=primary_source,
                                fallback_targets=fallback_primary_targets,
                                base_dir=base_dir,
                                manifest=manifest,
                                head_sha_local=head_sha_local,
                                reason_str=merge_err or primary_preview.merge_preview_error or 'Primary git merge failed',
                                primary_source_results=primary_source_results,
                                missing_source_targets=missing_source_targets,
                            )
                        else:
                            if manifest is not None:
                                manifest.register_source(
                                    primary_source,
                                    targets=list(primary_preview.upstream_managed_oids.keys()) + upstream_deleted_targets,
                                )
                            for t_rel in primary_preview.upstream_managed_oids.keys():
                                if t_rel in rejected_primary:
                                    absolute = os.path.normpath(os.path.join(base_dir, t_rel)).replace('\\', '/')
                                    original = prior_files[absolute]
                                    raw_original = original.read_bytes()
                                    status = SourceStatus.MISSING
                                    if original.existed:
                                        status = SourceStatus.USING_REPOSITORY_COPY
                                        from ruamel.yaml.error import YAMLError
                                        try:
                                            _stage_and_maybe_spill(
                                                absolute, raw_original, settings=settings, base_dir=base_dir,
                                                staged_map=staged_foms, allow_spill=_allow_spill,
                                                owned_loader=_owned_loader, spool=_state_spool)
                                        except (ValueError, YAMLError):
                                            # A historical copy can predate today's parser contract.
                                            # Retain its exact bytes through the ordinary save transaction.
                                            from rule_framework.source_admission import _AcceptedSourceBytes
                                            staged_foms[absolute] = _AcceptedSourceBytes(absolute, raw_original)
                                    else:
                                        if os.path.isfile(absolute):
                                            with open(absolute, 'rb') as merged_file:
                                                rejected_new_files[absolute] = hashlib.sha256(merged_file.read()).hexdigest()
                                        missing_source_targets.add(absolute)
                                    old_record = (prior_manifest or {}).get('targets', {}).get(t_rel, {})
                                    version = old_record.get('last_version')
                                    if manifest is not None:
                                        manifest.register_target(primary_source.id, t_rel)
                                        manifest.record_refresh(primary_source.id, t_rel, status, version=version)
                                    primary_source_results.append(SourceResult(primary_source, status, target=t_rel,
                                        version=version, reason=rejected_primary[t_rel]))
                                    logger.warning("Primary source '%s' content rejected for %s; status=%s: %s",
                                                   primary_source.id, t_rel, status, rejected_primary[t_rel])
                                    continue
                                if t_rel in primary_retry_targets:
                                    absolute = os.path.normpath(os.path.join(base_dir, t_rel)).replace('\\', '/')
                                    _stage_and_maybe_spill(
                                        absolute, primary_preview.merged_changed_blobs[t_rel],
                                        settings=settings, base_dir=base_dir, staged_map=staged_foms,
                                        allow_spill=_allow_spill, owned_loader=_owned_loader, spool=_state_spool)
                                if manifest is not None:
                                    manifest.register_target(primary_source.id, t_rel)
                                    manifest.record_refresh(primary_source.id, t_rel, SourceStatus.SUCCESS, version=primary_preview.upstream_sha)
                                primary_source_results.append(
                                    SourceResult(primary_source, SourceStatus.SUCCESS, target=t_rel, version=primary_preview.upstream_sha)
                                )
                            for old_t in upstream_deleted_targets:
                                norm_old_path = os.path.normpath(os.path.join(base_dir, old_t)).replace('\\', '/')
                                raw_retained = retained_deleted_bytes.get(old_t)
                                if raw_retained is not None and not os.path.isfile(norm_old_path):
                                    os.makedirs(os.path.dirname(norm_old_path), exist_ok=True)
                                    with open(norm_old_path, 'wb') as wf:
                                        wf.write(raw_retained)
                                    from ruamel.yaml.error import YAMLError
                                    try:
                                        _stage_and_maybe_spill(
                                            norm_old_path, raw_retained, settings=settings, base_dir=base_dir,
                                            staged_map=staged_foms, allow_spill=_allow_spill,
                                            owned_loader=_owned_loader, spool=_state_spool,
                                        )
                                    except (ValueError, YAMLError):
                                        from rule_framework.source_admission import _AcceptedSourceBytes
                                        staged_foms[norm_old_path] = _AcceptedSourceBytes(norm_old_path, raw_retained)
                                sr = resolve_repository_copy_fallback(
                                    primary_source, old_t, base_dir=base_dir, manifest=manifest,
                                    default_version=primary_preview.head_sha,
                                    reason='Upstream removed file; maintaining repository copy',
                                    missing_source_targets=missing_source_targets, register_target=True
                                )
                                primary_source_results.append(sr)
                                if sr.status == SourceStatus.USING_REPOSITORY_COPY:
                                    logger.info("Primary source '%s' upstream deleted %s; maintaining repository copy", primary_source.id, old_t)

                            if manifest is not None and primary_source.id in manifest.sources:
                                manifest.sources[primary_source.id]['last_status'] = SourceStatus.SUCCESS
                                manifest.sources[primary_source.id]['last_version'] = primary_preview.upstream_sha
                            logger.info(
                                "Primary source '%s' synchronized at %s (%d managed target(s))",
                                primary_source.id,
                                primary_preview.upstream_sha,
                                len(primary_preview.upstream_managed_oids),
                            )

        if git_fetcher is not None:
            git_fetcher.budget = None
        source_results = primary_source_results + secondary_source_results

        if manifest is not None:
            for hist_target in manifest.targets.keys():
                norm_hist_abs = os.path.normpath(os.path.join(base_dir, hist_target)).replace('\\', '/')
                if norm_hist_abs not in staged_foms and not os.path.isfile(norm_hist_abs):
                    missing_source_targets.add(norm_hist_abs)
            for hist_sid, hist_sdata in manifest.sources.items():
                if hist_sid not in active_source_ids or not hist_sdata.get('enabled', True) or not hist_sdata.get('targets'):
                    for m_item in hist_sdata.get('mappings') or ():
                        if isinstance(m_item, dict) and m_item.get('kind') == 'directory':
                            m_target = m_item.get('target')
                            if isinstance(m_target, str) and m_target:
                                norm_dir_abs = os.path.normpath(os.path.join(base_dir, m_target)).replace('\\', '/')
                                missing_source_directories.add(norm_dir_abs)
                                missing_source_directories.add(m_target.replace('\\', '/'))

        ownership_map = {}
        if manifest is not None:
            for t_path, t_info in manifest.targets.items():
                owner_id = t_info.get('source_id')
                if owner_id:
                    norm_tp = os.path.normcase(t_path).replace('\\', '/')
                    ownership_map[norm_tp] = owner_id
                    abs_t = os.path.normcase(os.path.normpath(os.path.join(base_dir, t_path))).replace('\\', '/')
                    ownership_map[abs_t] = owner_id
        if manifest is not None:
            for owner_id, source_data in manifest.sources.items():
                for mapping in source_data.get('mappings') or ():
                    if not isinstance(mapping, dict) or mapping.get('kind') != 'directory':
                        continue
                    target = mapping.get('target')
                    if not isinstance(target, str) or not target:
                        continue
                    relative = os.path.normcase(target).replace('\\', '/')
                    absolute = os.path.normcase(os.path.normpath(os.path.join(base_dir, target))).replace('\\', '/')
                    # Actual file ownership takes priority over historical namespaces.
                    ownership_map.setdefault(relative, owner_id)
                    ownership_map.setdefault(absolute, owner_id)
        if primary_source is not None:
            for pt in fallback_primary_targets:
                norm_pt = os.path.normcase(pt).replace('\\', '/')
                ownership_map[norm_pt] = primary_source.id
                abs_pt = os.path.normcase(os.path.normpath(os.path.join(base_dir, pt))).replace('\\', '/')
                ownership_map[abs_pt] = primary_source.id
        for source in sources:
            src_targets = []
            if source.target:
                src_targets.append(source.target)
            if source.mappings:
                src_targets.extend(m.target for m in source.mappings)
            for st in src_targets:
                norm_target = os.path.normcase(st).replace('\\', '/')
                ownership_map[norm_target] = source.id
                abs_t = os.path.normcase(os.path.normpath(os.path.join(base_dir, st))).replace('\\', '/')
                ownership_map[abs_t] = source.id

        context = SourceExecutionContext(
            staged_foms=staged_foms,
            missing_source_targets=missing_source_targets,
            missing_source_directories=missing_source_directories,
            ownership_map=ownership_map,
            _state_spool=_state_spool,
            prior_manifest=prior_manifest, prior_files=prior_files,
            rejected_new_files=rejected_new_files,
            manifest=manifest, source_results=source_results,
        )
        return SourcePreparationResult(
            source_results=source_results,
            manifest=manifest,
            context=context,
            owned_fetcher=owned_fetcher,
            _state_spool=_state_spool,
        )
    except Exception:
        if owned_fetcher is not None:
            owned_fetcher.close()
        raise

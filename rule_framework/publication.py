"""Explicit Git publication of saved Task products and existing local commits."""
from dataclasses import dataclass
import logging
import os
import subprocess

from rule_framework.managed_io import ensure_framework_io

logger = logging.getLogger('RuleFramework')


@dataclass(frozen=True)
class PublicationOptions:
    remote: str = 'origin'
    branch: str = 'master'
    message: str = 'Sync from upstream and modify files'

    def validate(self):
        for name in ('remote', 'branch', 'message'):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or '\0' in value:
                raise ValueError(f'Publication {name} must be a non-empty string without NUL characters')
        for name in ('remote', 'branch'):
            if getattr(self, name).startswith('-'):
                raise ValueError(f'Publication {name} must start with a name character')


@dataclass(frozen=True)
class PublicationResult:
    status: str
    remote: str
    branch: str
    commit_state: str = 'not_attempted'
    push_state: str = 'not_attempted'
    local_commit: str | None = None
    index_state: str = 'unchanged'
    reason: str | None = None


class GitRunner:
    """Git process boundary; subprocess arguments never pass through a shell."""

    def run(self, base_dir, *arguments, check=True):
        ensure_framework_io('GitRunner.run()')
        environment = dict(os.environ, GIT_TERMINAL_PROMPT='0')
        result = subprocess.run(['git', '--literal-pathspecs', '-C', os.fspath(base_dir), *arguments],
                                capture_output=True, text=True, encoding='utf-8', errors='replace',
                                env=environment, timeout=60)
        if check and result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip()
                               or f'Git {arguments[0]} failed with exit code {result.returncode}')
        return result


def _has_staged_changes(git, base_dir):
    result = git.run(base_dir, 'diff', '--cached', '--quiet', check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or 'Git could not inspect the index')
    return result.returncode == 1


def publish_saved_files(base_dir, paths, *, options, git=None):
    """Commit only the supplied saved products; push the configured local branch."""
    ensure_framework_io('publish_saved_files()')
    git = git or GitRunner()
    commit_state, push_state, index_state, head = 'not_attempted', 'not_attempted', 'unchanged', None
    before_head, relative_paths, stage_attempted, commit_attempted = None, [], False, False
    try:
        if not isinstance(options, PublicationOptions):
            raise ValueError('Publication options must be PublicationOptions')
        options.validate()
        git.run(base_dir, 'check-ref-format', '--branch', options.branch)
        branch = git.run(base_dir, 'branch', '--show-current').stdout.strip()
        if branch != options.branch:
            raise ValueError(f'Configured publication branch is {options.branch}; checkout branch is {branch or "detached HEAD"}')
        head = git.run(base_dir, 'rev-parse', 'HEAD').stdout.strip()
        before_head = head
        if _has_staged_changes(git, base_dir):
            raise ValueError('Git index contains pre-existing staged changes; review the index before publication')
        root = os.path.realpath(base_dir)
        relative_paths = []
        for path in paths:
            resolved = os.path.realpath(path)
            if os.path.commonpath((root, resolved)) != root:
                raise ValueError(f'Saved product is outside the publication checkout: {path}')
            relative = os.path.relpath(resolved, root).replace('\\', '/')
            from rule_framework.sources import SOURCES_STATE_FILENAME
            from rule_framework.action_receipts import RECEIPTS_FILENAME
            if relative not in {SOURCES_STATE_FILENAME, RECEIPTS_FILENAME} and relative.split('/')[0] not in {'rule', 'rewrite', 'script'}:
                raise ValueError(f'Published products must be under rule, rewrite or script: {path}')
            relative_paths.append(relative)
        if relative_paths:
            stage_attempted = True
            git.run(base_dir, 'add', '--', *relative_paths)
        if _has_staged_changes(git, base_dir):
            index_state = 'staged'
            commit_attempted = True
            git.run(base_dir, 'commit', '-m', options.message)
            commit_state = 'created'
            index_state = 'clean'
            head = None
            head = git.run(base_dir, 'rev-parse', 'HEAD').stdout.strip()
        else:
            commit_state = 'unchanged'
        push_state = 'attempted'
        git.run(base_dir, 'push', options.remote, f'HEAD:refs/heads/{options.branch}')
        push_state = 'succeeded'
        result = PublicationResult('success', options.remote, options.branch, commit_state,
                                   push_state, head, index_state)
    except Exception as error:
        if stage_attempted and push_state == 'not_attempted':
            try:
                observed_head = git.run(base_dir, 'rev-parse', 'HEAD').stdout.strip()
                head = observed_head
                if observed_head == before_head:
                    if commit_attempted:
                        commit_state = 'not_created'
                    git.run(base_dir, 'reset', '--quiet', 'HEAD', '--', *relative_paths)
                    index_state = 'requires_attention' if _has_staged_changes(git, base_dir) else 'restored'
                else:
                    commit_state = 'created'
                    index_state = 'requires_attention' if _has_staged_changes(git, base_dir) else 'clean'
            except Exception as index_error:
                index_state = 'requires_attention'
                error = RuntimeError(f'{error}; index recovery: {index_error}')
        if push_state == 'attempted':
            push_state = 'failed_remote_unknown'
        result = PublicationResult('failed', getattr(options, 'remote', ''), getattr(options, 'branch', ''),
                                   commit_state, push_state, head, index_state, str(error))
    logger.log(logging.INFO if result.status == 'success' else logging.ERROR,
               'Git Publication: status=%s remote=%s branch=%s commit=%s local_commit=%s push=%s index=%s reason=%s',
               result.status, result.remote, result.branch, result.commit_state, result.local_commit,
               result.push_state, result.index_state, result.reason)
    return result

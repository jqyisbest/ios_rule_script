"""Public anonymous Git repository acquisition boundary."""

import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Optional, Sequence
from urllib.parse import urlparse

from rule_framework.sources import validate_source_target


@dataclass(frozen=True)
class GitMapping:
    path: str
    target: str
    kind: str = 'file'
    purpose: str = 'auto'
    allow_empty: bool = False


@dataclass
class PrimarySyncPreview:
    head_sha: str
    upstream_sha: str
    already_up_to_date: bool
    preview_repo: str
    merge_preview_ok: bool
    merge_preview_error: Optional[str]
    upstream_managed_oids: dict[str, str]
    merged_changed_blobs: dict[str, bytes]
    merge_deleted_managed_paths: list[str]
    incoming_added_paths: list[str]


class GitFetcher:
    """Boundary for acquiring files/directories from Git repositories."""

    def __init__(self, repo_overrides: Optional[dict[str, str]] = None, timeout: int = 30):
        self.repo_overrides = repo_overrides or {}
        self.timeout = timeout
        self.budget = None
        self._temp_dirs: list[tempfile.TemporaryDirectory] = []
        self._cloned_repos: dict[str, str] = {}

    def resolve_repo_path(self, url: str) -> str:
        if url in self.repo_overrides:
            return self.repo_overrides[url]
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ('http', 'https'):
            raise ValueError(f"Only public HTTP(S) git URLs are supported in production: '{url}'")
        if parsed.username or parsed.password:
            raise ValueError("Git repository URL must not contain credentials")
        if url in self._cloned_repos:
            if self.budget is not None:
                self.budget.temp_roots.add(os.path.dirname(self._cloned_repos[url]))
                self._check_budget()
            return self._cloned_repos[url]

        temp_dir = tempfile.TemporaryDirectory(prefix='rule-git-')
        self._temp_dirs.append(temp_dir)
        if self.budget is not None:
            self.budget.temp_roots.add(temp_dir.name)
        repo_dir = os.path.join(temp_dir.name, 'repo.git')

        env = dict(
            os.environ,
            GIT_TERMINAL_PROMPT='0',
            GIT_CONFIG_NOSYSTEM='1',
            GIT_OPTIONAL_LOCKS='0',
            PRE_COMMIT_ALLOW_NO_CONFIG='1',
        )
        cmd = ['git', '-c', 'core.hooksPath=', 'clone', '--bare', '--no-checkout', url, repo_dir]
        proc = self._run_process(cmd, env=env)
        if proc.returncode != 0:
            err = proc.stderr.decode('utf-8', errors='replace').strip()
            raise RuntimeError(f"Failed to clone Git repository from '{url}': {err}")

        self._cloned_repos[url] = repo_dir
        return repo_dir

    def close(self):
        for td in self._temp_dirs:
            try:
                td.cleanup()
            except Exception:
                pass
        self._temp_dirs.clear()
        self._cloned_repos.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

    def run_git(self, repo_path: str, args: list[str]) -> subprocess.CompletedProcess:
        if not os.path.isdir(repo_path):
            raise RuntimeError(f"Repository directory does not exist: {repo_path}")
        env = dict(
            os.environ,
            GIT_TERMINAL_PROMPT='0',
            GIT_CONFIG_NOSYSTEM='1',
            GIT_OPTIONAL_LOCKS='0',
            PRE_COMMIT_ALLOW_NO_CONFIG='1',
            LC_ALL='C',
        )
        return self._run_process(['git', *args], cwd=repo_path, env=env)

    def _check_budget(self):
        if self.budget is None:
            return
        self.budget.remaining('git_process')
        total = 0
        for temporary_root in self.budget.temp_roots:
            for directory, _, names in os.walk(temporary_root):
                for name in names:
                    try:
                        total += os.path.getsize(os.path.join(directory, name))
                    except FileNotFoundError:
                        pass
        self.budget.check('max_temp_bytes', total, 'git_temporary_storage')

    def _run_process(self, command, *, cwd=None, env=None):
        self._check_budget()
        started = time.monotonic()
        with subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, start_new_session=(os.name != 'nt')) as process:
            try:
                while True:
                    self._check_budget()
                    remaining = self.timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, self.timeout)
                    try:
                        stdout, stderr = process.communicate(timeout=min(0.1, remaining))
                        self._check_budget()
                        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                    except subprocess.TimeoutExpired:
                        continue
            except BaseException:
                # Stop transport helpers as well as Git before draining inherited pipes.
                if os.name == 'nt' and process.poll() is None:
                    try:
                        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                    except (OSError, subprocess.SubprocessError):
                        # Always reap the owned process even when the OS tree command fails.
                        process.kill()
                elif os.name != 'nt':
                    import signal
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
                raise

    def resolve_ref(self, repo_path: str, ref: Optional[str] = None) -> str:
        target_ref = ref or 'HEAD'
        proc = self.run_git(repo_path, ['rev-parse', '--verify', '--end-of-options', f'{target_ref}^{{commit}}'])
        if proc.returncode != 0:
            err = proc.stderr.decode('utf-8', errors='replace').strip()
            raise RuntimeError(f"Failed to resolve git ref '{target_ref}': {err}")
        return proc.stdout.decode('utf-8', errors='replace').strip()

    def list_tree(self, repo_path: str, commit_sha: str) -> list[tuple[str, str, str, str]]:
        """Return list of (mode, type, object_id, path) from git ls-tree -r -z."""
        proc = self.run_git(repo_path, ['ls-tree', '-r', '-z', commit_sha])
        if proc.returncode != 0:
            err = proc.stderr.decode('utf-8', errors='replace').strip()
            raise RuntimeError(f"Failed to inspect git tree at {commit_sha}: {err}")
        raw = proc.stdout
        entries = []
        for chunk in raw.split(b'\0'):
            if not chunk:
                continue
            try:
                meta, path_bytes = chunk.split(b'\t', 1)
                mode_str, type_str, obj_id_str = meta.decode('ascii').split(' ', 2)
                entry_path = path_bytes.decode('utf-8', errors='surrogateescape')
                entries.append((mode_str, type_str, obj_id_str, entry_path))
            except Exception:
                continue
        return entries

    def is_directory(self, repo_path: str, commit_sha: str, path: str) -> bool:
        expression = f'{commit_sha}^{{tree}}' if path == '.' else f'{commit_sha}:{path}'
        proc = self.run_git(repo_path, ['cat-file', '-t', expression])
        return proc.returncode == 0 and proc.stdout.strip() == b'tree'

    def read_blob(self, repo_path: str, object_id: str) -> bytes:
        """Read raw blob bytes preserving exact binary data."""
        if self.budget is not None:
            size_result = self.run_git(repo_path, ['cat-file', '-s', object_id])
            if size_result.returncode:
                raise RuntimeError('Failed to inspect selected Git blob size')
            self.budget.charge(int(size_result.stdout), 'git_blob', files=1)
        proc = self.run_git(repo_path, ['cat-file', 'blob', object_id])
        if proc.returncode != 0:
            err = proc.stderr.decode('utf-8', errors='replace').strip()
            raise RuntimeError(f"Failed to read git blob {object_id}: {err}")
        return proc.stdout

    def _diff_trees(self, repo_path: str, tree_a: str, tree_b: str) -> list[tuple[str, str, str, str, str, str]]:
        proc = self.run_git(repo_path, ['diff-tree', '-r', '-z', '--no-commit-id', '--no-renames', tree_a, tree_b])
        if proc.returncode != 0:
            err = proc.stderr.decode('utf-8', errors='replace').strip()
            raise RuntimeError(f"Failed to diff git trees {tree_a}..{tree_b}: {err}")
        tokens = [t for t in proc.stdout.split(b'\0') if t]
        diffs = []
        idx = 0
        while idx + 1 < len(tokens):
            meta_bytes = tokens[idx]
            path_bytes = tokens[idx + 1]
            idx += 2
            if not meta_bytes.startswith(b':'):
                continue
            parts = meta_bytes[1:].decode('ascii', errors='replace').split(' ')
            if len(parts) < 5:
                continue
            old_mode, new_mode, old_oid, new_oid, status = parts[0], parts[1], parts[2], parts[3], parts[4]
            path_str = path_bytes.decode('utf-8', errors='surrogateescape')
            diffs.append((old_mode, new_mode, old_oid, new_oid, status, path_str))
        return diffs

    def list_local_head_managed_files(self, base_dir: str) -> tuple[Optional[str], list[str]]:
        """Return (head_sha, list of managed relative paths tracked in local HEAD)."""
        head_proc = self.run_git(base_dir, ['rev-parse', '--verify', 'HEAD^{commit}'])
        if head_proc.returncode != 0:
            return None, []
        head_sha = head_proc.stdout.decode('utf-8', errors='replace').strip()
        try:
            entries = self.list_tree(base_dir, head_sha)
        except Exception:
            return head_sha, []
        managed = []
        for mode, otype, _oid, path in entries:
            if otype != 'blob' or mode in ('120000', '160000'):
                continue
            norm_path = path.replace('\\', '/')
            parts = norm_path.split('/')
            if parts[0] in ('rule', 'rewrite', 'script') and len(parts) >= 2:
                managed.append(norm_path)
        return head_sha, managed

    def preview_primary_sync(self, base_dir: str, primary_source) -> PrimarySyncPreview:
        """Fetch primary upstream in a temporary shared bare clone and preview merge-tree."""
        head_proc = self.run_git(base_dir, ['rev-parse', '--verify', 'HEAD^{commit}'])
        if head_proc.returncode != 0:
            err = head_proc.stderr.decode('utf-8', errors='replace').strip()
            raise RuntimeError(f"Local checkout at '{base_dir}' has no valid Git HEAD: {err}")
        head_sha = head_proc.stdout.decode('utf-8', errors='replace').strip()

        if primary_source.url in self.repo_overrides:
            fetch_source = self.repo_overrides[primary_source.url]
        else:
            parsed = urlparse(primary_source.url)
            if parsed.scheme.lower() not in ('http', 'https'):
                raise ValueError(f"Only public HTTP(S) git URLs are supported in production: '{primary_source.url}'")
            if parsed.username or parsed.password:
                raise ValueError("Git repository URL must not contain credentials")
            fetch_source = primary_source.url

        temp_dir = tempfile.TemporaryDirectory(prefix='rule-primary-preview-')
        self._temp_dirs.append(temp_dir)
        if self.budget is not None:
            self.budget.temp_roots.add(temp_dir.name)
        preview_repo = os.path.join(temp_dir.name, 'preview.git')

        clone_proc = self.run_git(
            base_dir,
            ['-c', 'core.hooksPath=', 'clone', '--bare', '--shared', '--no-checkout', base_dir, preview_repo],
        )
        if clone_proc.returncode != 0:
            err = clone_proc.stderr.decode('utf-8', errors='replace').strip()
            raise RuntimeError(f"Failed to create isolated preview clone for primary source '{primary_source.id}': {err}")

        git_dir_proc = self.run_git(base_dir, ['rev-parse', '--git-dir'])
        if git_dir_proc.returncode == 0:
            git_dir = git_dir_proc.stdout.decode('utf-8', errors='replace').strip()
            git_cfg = os.path.abspath(os.path.join(base_dir, git_dir, 'config'))
            if os.path.isfile(git_cfg):
                self.run_git(preview_repo, ['config', 'include.path', git_cfg.replace('\\', '/')])

        target_ref = primary_source.ref or 'master'
        fetch_proc = self.run_git(
            preview_repo,
            ['-c', 'core.hooksPath=', 'fetch', '--no-tags', '--', fetch_source, target_ref],
        )
        if fetch_proc.returncode != 0:
            err = fetch_proc.stderr.decode('utf-8', errors='replace').strip()
            raise RuntimeError(
                f"Failed to fetch primary source '{primary_source.id}' from '{primary_source.url}' ({target_ref}): {err}"
            )

        rev_proc = self.run_git(preview_repo, ['rev-parse', '--verify', 'FETCH_HEAD^{commit}'])
        if rev_proc.returncode != 0:
            err = rev_proc.stderr.decode('utf-8', errors='replace').strip()
            raise RuntimeError(f"Failed to resolve fetched primary commit for '{primary_source.id}': {err}")
        upstream_sha = rev_proc.stdout.decode('utf-8', errors='replace').strip()

        upstream_entries = self.list_tree(preview_repo, upstream_sha)
        upstream_managed_oids: dict[str, str] = {}
        for mode, otype, oid, path in upstream_entries:
            if otype != 'blob' or mode in ('120000', '160000'):
                continue
            norm_path = path.replace('\\', '/')
            parts = norm_path.split('/')
            if parts[0] in ('rule', 'rewrite', 'script') and len(parts) >= 2:
                validate_source_target(norm_path, base_dir, allow_directory=False)
                upstream_managed_oids[norm_path] = oid

        anc_proc = self.run_git(preview_repo, ['merge-base', '--is-ancestor', upstream_sha, head_sha])
        already_up_to_date = (anc_proc.returncode == 0)
        merged_changed_blobs: dict[str, bytes] = {}
        merge_deleted_managed_paths: list[str] = []
        incoming_added_paths: list[str] = []

        if already_up_to_date:
            merge_preview_ok = True
            merge_preview_error = None
        else:
            mt_proc = self.run_git(preview_repo, ['merge-tree', '--write-tree', '-Xtheirs', head_sha, upstream_sha])
            mt_out = mt_proc.stdout.decode('utf-8', errors='replace')
            mt_err = mt_proc.stderr.decode('utf-8', errors='replace')
            if mt_proc.returncode == 0:
                merge_preview_ok = True
                merge_preview_error = None
                merged_tree_sha = mt_out.splitlines()[0].strip()
                for _old_mode, new_mode, _old_oid, new_oid, status, path in self._diff_trees(
                    preview_repo, head_sha, merged_tree_sha
                ):
                    norm_path = path.replace('\\', '/')
                    status_char = status[0] if status else ''
                    if status_char == 'A':
                        incoming_added_paths.append(norm_path)
                    parts = norm_path.split('/')
                    if parts[0] in ('rule', 'rewrite', 'script') and len(parts) >= 2:
                        if status_char == 'D':
                            merge_deleted_managed_paths.append(norm_path)
                        elif status_char in ('A', 'M', 'T') and new_mode not in ('120000', '160000'):
                            validate_source_target(norm_path, base_dir, allow_directory=False)
                            merged_changed_blobs[norm_path] = self.read_blob(preview_repo, new_oid)
            else:
                merge_preview_ok = False
                merge_preview_error = (
                    mt_err.strip()
                    or mt_out.strip()
                    or f"git merge-tree failed with exit code {mt_proc.returncode}"
                )
                for _old_mode, _new_mode, _old_oid, _new_oid, status, path in self._diff_trees(
                    preview_repo, head_sha, upstream_sha
                ):
                    norm_path = path.replace('\\', '/')
                    if status and status[0] == 'A':
                        incoming_added_paths.append(norm_path)

        return PrimarySyncPreview(
            head_sha=head_sha,
            upstream_sha=upstream_sha,
            already_up_to_date=already_up_to_date,
            preview_repo=preview_repo,
            merge_preview_ok=merge_preview_ok,
            merge_preview_error=merge_preview_error,
            upstream_managed_oids=upstream_managed_oids,
            merged_changed_blobs=merged_changed_blobs,
            merge_deleted_managed_paths=merge_deleted_managed_paths,
            incoming_added_paths=incoming_added_paths,
        )

    def _has_preexisting_merge_or_unmerged_state(self, base_dir: str) -> bool:
        for state_name in ('MERGE_HEAD', 'REBASE_HEAD', 'rebase-merge', 'rebase-apply', 'CHERRY_PICK_HEAD', 'REVERT_HEAD'):
            gp_proc = self.run_git(base_dir, ['rev-parse', '--git-path', state_name])
            if gp_proc.returncode == 0:
                rel_or_abs = gp_proc.stdout.decode('utf-8', errors='replace').strip()
                full_path = rel_or_abs if os.path.isabs(rel_or_abs) else os.path.join(base_dir, rel_or_abs)
                if os.path.lexists(full_path):
                    return True
        unmerged_proc = self.run_git(base_dir, ['ls-files', '-u'])
        if unmerged_proc.returncode == 0 and unmerged_proc.stdout.strip():
            return True
        return False

    def check_working_tree_merge_preconditions(self, base_dir: str, incoming_added_paths: Sequence[str],
                                               already_up_to_date: bool = False) -> Optional[str]:
        """Return a non-empty reason if local checkout state prevents a safe clean primary merge."""
        if self._has_preexisting_merge_or_unmerged_state(base_dir):
            return "Pre-existing merge or unmerged state detected in repository"

        if not already_up_to_date:
            staged_proc = self.run_git(base_dir, ['diff', '--name-only', '--cached'])
            if staged_proc.returncode != 0 or staged_proc.stdout.strip():
                return "Pre-existing staged index changes detected in repository"

            dirty_proc = self.run_git(base_dir, ['diff', '--name-only'])
            if dirty_proc.returncode != 0 or dirty_proc.stdout.strip():
                return "Pre-existing unstaged tracked changes detected in repository"

            base_real = os.path.realpath(base_dir)
            for rel_path in incoming_added_paths:
                abs_path = os.path.join(base_dir, rel_path)
                if os.path.lexists(abs_path):
                    return f"Local untracked or ignored file collision at '{rel_path}'"
                parent = os.path.dirname(os.path.abspath(abs_path))
                while parent and os.path.normcase(parent) != os.path.normcase(base_real):
                    if os.path.lexists(parent) and not os.path.isdir(parent):
                        return f"Local file collision at parent path of '{rel_path}'"
                    next_parent = os.path.dirname(parent)
                    if next_parent == parent:
                        break
                    parent = next_parent
        return None

    def abort_primary_merge(self, base_dir: str) -> subprocess.CompletedProcess:
        """Abort a merge started by this run."""
        return self.run_git(base_dir, ['merge', '--abort'])

    def apply_primary_merge(self, base_dir: str, preview: PrimarySyncPreview, primary_source) -> tuple[bool, Optional[str]]:
        """Apply real git merge in base_dir when safe; abort our own merge on failure."""
        if preview.already_up_to_date:
            return True, None

        head_proc = self.run_git(base_dir, ['rev-parse', '--verify', 'HEAD^{commit}'])
        current_head = head_proc.stdout.decode('utf-8', errors='replace').strip() if head_proc.returncode == 0 else ''
        if current_head != preview.head_sha:
            return False, "Repository HEAD changed before primary merge could be applied"

        from rule_framework.sources import DEFAULT_PRIMARY_SOURCE_REMOTE
        remote_name = primary_source.remote or DEFAULT_PRIMARY_SOURCE_REMOTE
        target_ref = primary_source.ref or 'master'
        rem_proc = self.run_git(base_dir, ['config', '--get', f'remote.{remote_name}.url'])
        rem_url = rem_proc.stdout.decode('utf-8', errors='replace').strip() if rem_proc.returncode == 0 else ''
        fetched = False
        try:
            if rem_proc.returncode == 0 and target_ref != 'HEAD' and rem_url == primary_source.url:
                refspec = f"{preview.upstream_sha}:refs/remotes/{remote_name}/{target_ref}"
                f_proc = self.run_git(base_dir, ['-c', 'core.hooksPath=', 'fetch', '--no-tags', '--', preview.preview_repo, refspec])
                fetched = (f_proc.returncode == 0)
            if not fetched:
                f_proc = self.run_git(
                    base_dir,
                    ['-c', 'core.hooksPath=', 'fetch', '--no-tags', '--', preview.preview_repo, preview.upstream_sha],
                )
                if f_proc.returncode != 0:
                    err = f_proc.stderr.decode('utf-8', errors='replace').strip()
                    return False, f"Failed to transfer primary objects into working repository: {err}"
        except (subprocess.SubprocessError, OSError) as f_err:
            return False, f"Failed to transfer primary objects into working repository: {f_err}"

        merge_proc = None
        merge_err = None
        try:
            merge_proc = self.run_git(
                base_dir,
                ['merge', '--no-edit', '--strategy-option', 'theirs', preview.upstream_sha],
            )
            if merge_proc.returncode == 0:
                return True, None
            merge_err = (
                merge_proc.stderr.decode('utf-8', errors='replace').strip()
                or merge_proc.stdout.decode('utf-8', errors='replace').strip()
                or f"git merge failed with exit code {merge_proc.returncode}"
            )
        except (subprocess.SubprocessError, OSError) as p_err:
            merge_err = f"git merge process error: {p_err}"

        # Abort only the merge this run started
        if self._has_preexisting_merge_or_unmerged_state(base_dir):
            try:
                abort_proc = self.abort_primary_merge(base_dir)
                if abort_proc.returncode != 0 or self._has_preexisting_merge_or_unmerged_state(base_dir):
                    abort_err = (
                        abort_proc.stderr.decode('utf-8', errors='replace').strip()
                        or abort_proc.stdout.decode('utf-8', errors='replace').strip()
                        or f"git merge --abort exited with {abort_proc.returncode}"
                    )
                    raise RuntimeError(f"Primary merge failed ({merge_err}) and merge abort cleanup failed: {abort_err}")
            except (subprocess.SubprocessError, OSError) as a_err:
                raise RuntimeError(f"Primary merge failed ({merge_err}) and merge abort cleanup failed: {a_err}")

        after_head_proc = self.run_git(base_dir, ['rev-parse', '--verify', 'HEAD^{commit}'])
        after_head = after_head_proc.stdout.decode('utf-8', errors='replace').strip() if after_head_proc.returncode == 0 else ''
        if after_head != preview.head_sha:
            raise RuntimeError(f"Primary merge failed ({merge_err}) and repository HEAD could not be restored")

        return False, merge_err

"""Prevent public adapter saves from escaping a Hook's staged Task effects."""

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps

_hook_active = ContextVar('rule_framework_managed_hook_active', default=False)


@contextmanager
def managed_hook_io():
    token = _hook_active.set(True)
    try:
        yield
    finally:
        _hook_active.reset(token)


def guard_managed_save(method):
    if getattr(method, '_managed_save_guard', False):
        return method

    @wraps(method)
    def guarded(self, *args, **kwargs):
        if _hook_active.get():
            raise ValueError(
                f'Hook {method.__name__}() would bypass Task staging; '
                'edit workspace.get_fom(path) or use workspace.register_fom(path, fom). '
                'The framework saves successful Task state after validation.'
            )
        return method(self, *args, **kwargs)

    guarded._managed_save_guard = True
    return guarded


def ensure_framework_io(operation):
    """Keep global storage/publication operations outside a managed Hook."""
    if _hook_active.get():
        raise ValueError(
            f'Hook {operation} would bypass Task staging; '
            'edit workspace.get_fom(path) or use workspace.register_fom(path, fom). '
            'The framework saves successful Task state after validation.'
        )

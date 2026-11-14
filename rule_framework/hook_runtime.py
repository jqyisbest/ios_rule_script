"""Public Hook loading and argument injection for the managed Task workspace."""

import importlib.util
import inspect
import logging
import os
import sys


from rule_framework.managed_io import managed_hook_io


def execute_hook(ctx, script, function):
    previous_bytecode_setting = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        with managed_hook_io():
            _execute_hook(ctx, script, function)
    finally:
        sys.dont_write_bytecode = previous_bytecode_setting


def _execute_hook(ctx, script, function):
    if not script or not function:
        raise ValueError("custom_hook requires 'script' and 'function' arguments")
    hooks_dir = ctx.settings.get('hooks_dir')
    if hooks_dir and not os.path.isabs(script):
        script = os.path.join(hooks_dir, script)
    spec = importlib.util.spec_from_file_location('custom_hook_mod', script)
    if spec is None or spec.loader is None:
        raise ValueError(f'Could not load script {script}')
    module = importlib.util.module_from_spec(spec)
    sys.modules['custom_hook_mod'] = module
    spec.loader.exec_module(module)
    hook = getattr(module, function, None)
    if not callable(hook):
        raise ValueError(f'Hook function {function!r} must exist and be callable in {script}')
    if inspect.iscoroutinefunction(hook):
        raise ValueError('Hook must be synchronous; stage changes through the managed workspace')
    signature = inspect.signature(hook)
    injected = {
        'fom': ctx.fom,
        'fom_objects': [ctx.fom],
        'workspace': ctx.workspace,
        'fom_cache': ctx.fom_cache,
        'logger': logging.getLogger('RuleFramework'),
    }
    args, kwargs = [], {}
    for index, parameter in enumerate(signature.parameters.values()):
        if parameter.kind == parameter.VAR_POSITIONAL:
            if index == 0:
                args.append(ctx.fom)
            continue
        if parameter.kind == parameter.VAR_KEYWORD:
            continue
        if parameter.name in injected:
            value = injected[parameter.name]
        elif index == 0 and parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD):
            value = ctx.fom
        elif parameter.default is not parameter.empty:
            if parameter.kind == parameter.POSITIONAL_ONLY:
                value = parameter.default
            else:
                continue
        else:
            raise ValueError(f'Unsupported required Hook parameter: {parameter.name}; '
                             'use fom, workspace, logger, fom_objects or fom_cache')
        if parameter.kind == parameter.POSITIONAL_ONLY:
            args.append(value)
        else:
            kwargs[parameter.name] = value
    result = hook(*args, **kwargs)
    if inspect.iscoroutine(result):
        result.close()
        raise ValueError('Hook must be synchronous; stage changes through the managed workspace')
    if result is not None:
        raise ValueError('Hook must return None; submit changes through fom or workspace '
                         'and raise an exception to fail the Task')

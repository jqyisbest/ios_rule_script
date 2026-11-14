from rule_framework.actions import parse_action, Action
import os

class ActionExecutor:
    def __init__(self, fom, fom_cache=None, settings=None, workspace=None):
        self.fom = fom
        self.fom_cache = fom_cache
        self.settings = settings or {}
        self.workspace = workspace
        from copy import deepcopy
        self.fom.settings = deepcopy(getattr(self.fom, 'settings', self.settings))

    def execute_action(self, action_input):
        if isinstance(action_input, dict):
            action = parse_action(action_input)
        elif isinstance(action_input, Action):
            action = action_input
        else:
            return

        if not action:
            return
            
        from rule_framework.actions import ExecutionContext
        ctx = ExecutionContext(fom=self.fom, fom_cache=self.fom_cache, settings=self.settings,
                               workspace=self.workspace)
        action.execute_managed(ctx)

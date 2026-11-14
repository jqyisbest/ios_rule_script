"""Per-source acquisition guards; defaults are overridable engineering limits."""
import logging
import math
import time

DEFAULT_LIMITS = {'max_seconds': 300, 'max_bytes': 1024 ** 3,
                  'max_files': 100000, 'max_temp_bytes': 4 * 1024 ** 3}


def parse_limits(value):
    if value is None:
        raise ValueError('Source limits must be a dictionary')
    if not isinstance(value, dict) or set(value) - set(DEFAULT_LIMITS):
        raise ValueError('Source limits contain invalid or unsupported keys')
    result = dict(DEFAULT_LIMITS, **value)
    for key, amount in result.items():
        if (isinstance(amount, bool) or not isinstance(amount, (int, float))
                or not math.isfinite(amount) or amount <= 0
                or (key != 'max_seconds' and not isinstance(amount, int))):
            raise ValueError(f'Source limits {key} must be a positive finite ' +
                             ('number' if key == 'max_seconds' else 'integer'))
    return result


class SourceLimitExceeded(RuntimeError):
    pass


class SourceBudget:
    def __init__(self, source):
        self.source_id = source.id
        self.limits = parse_limits(source.limits)
        self.started = time.monotonic()
        self.bytes = 0
        self.files = 0
        self.temp_roots = set()
        self.paused_at = None

    def pause(self):
        self.paused_at = time.monotonic()

    def resume(self):
        if self.paused_at is not None:
            self.started += time.monotonic() - self.paused_at
            self.paused_at = None

    def check(self, key, observed, phase):
        threshold = self.limits[key]
        if observed > threshold:
            unit = {'max_seconds': 'seconds', 'max_files': 'files'}.get(key, 'bytes')
            message = (f'Source {self.source_id} phase={phase} limit={key} unit={unit} '
                       f'threshold={threshold} observed={observed} outcome=acquisition_rejected')
            logging.getLogger('RuleFramework').warning(message)
            raise SourceLimitExceeded(message)

    def remaining(self, phase):
        elapsed = time.monotonic() - self.started
        self.check('max_seconds', elapsed, phase)
        return max(0.001, self.limits['max_seconds'] - elapsed)

    def charge(self, amount, phase, *, files=0):
        self.remaining(phase)
        self.bytes += amount
        self.files += files
        self.check('max_bytes', self.bytes, phase)
        self.check('max_files', self.files, phase)

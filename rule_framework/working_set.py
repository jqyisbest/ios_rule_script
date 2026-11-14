"""Cost-aware admission of one unexposed model into the execution working set."""
import os

COSTLY_CPU_THRESHOLD_SECONDS = 3.0
LARGE_FILE_PARSE_THRESHOLD_BYTES = 1024 * 1024
CACHE_ESTIMATE_BUDGET_BYTES = 128 * 1024 * 1024
PRESSURE_BYTES = 380 * 1024 * 1024


def _resident_bytes():
    try:
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes
            class Counters(ctypes.Structure):
                _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD)] + [
                    (name, ctypes.c_size_t) for name in ('peak', 'current', 'qpp', 'qp', 'qnp', 'qn', 'page', 'peakpage')]
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            query = ctypes.windll.psapi.GetProcessMemoryInfo
            query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            query.restype = wintypes.BOOL
            if query(wintypes.HANDLE(-1), ctypes.byref(counters), counters.cb):
                return counters.current
        elif os.path.isfile('/proc/self/statm'):
            with open('/proc/self/statm', encoding='ascii') as source:
                return int(source.read().split()[1]) * os.sysconf('SC_PAGE_SIZE')
    except (OSError, ValueError, AttributeError, IndexError):
        pass
    return None


class WorkingSetManager:
    """The cache budget is an admission estimate, independent of pinned/active objects."""

    def __init__(self, workspace, state_spool=None):
        self.workspace = workspace
        self._load_costs = {}
        self._backings = {}
        self._dirty = set()
        self._costly_path = None

    def record_load_cost(self, path, cpu_seconds):
        self._load_costs[path] = max(0.0, cpu_seconds)

    def is_costly(self, path):
        return self._load_costs.get(path, 0.0) > COSTLY_CPU_THRESHOLD_SECONDS

    def backing_for(self, path):
        return None if path in self._dirty else self._backings.get(path)

    def mark_action(self, path):
        if path in self._backings:
            self._dirty.add(path)

    def expose(self, path):
        self._backings.pop(path, None)
        self._dirty.discard(path)
        if self._costly_path == path:
            self._costly_path = None

    def before_load(self, path):
        if self._costly_path is None or self._costly_path == path:
            return
        try:
            large = os.path.getsize(path) >= LARGE_FILE_PARSE_THRESHOLD_BYTES
        except OSError:
            large = True
        resident = _resident_bytes()
        if large or resident is not None and resident >= PRESSURE_BYTES:
            self.evict()

    def _admit(self, path, fom):
        if path in self.workspace._escaped_paths or not self.is_costly(path):
            return False
        raw_size = len(getattr(fom, '_raw_bytes', b''))
        nodes = getattr(fom, 'nodes', ())
        estimate = raw_size * 12 + len(nodes) * 256
        resident = _resident_bytes()
        return estimate <= CACHE_ESTIMATE_BUDGET_BYTES and (resident is None or resident < PRESSURE_BYTES)

    def install(self, path, backing, fom, *, force=False):
        self._dirty.discard(path)
        if not force and self._admit(path, fom):
            if self._costly_path is not None and self._costly_path != path:
                self.evict()
            self._backings[path] = backing
            self._costly_path = path
            self.workspace.fom_cache._files[path] = fom
        else:
            self._backings.pop(path, None)
            if self._costly_path == path:
                self._costly_path = None
            self.workspace.fom_cache._files[path] = backing

    def evict(self):
        path = self._costly_path
        if path is None:
            return
        if path in self.workspace._escaped_paths:
            self.expose(path)
            return
        backing = self.backing_for(path)
        if backing is not None:
            self.workspace.fom_cache._files[path] = backing
            self.expose(path)
        else:
            # Force bypasses admission so the next large parse cannot stack caches.
            self.workspace._spill_owned_fom(path, force=True)

    def snapshot_entries(self):
        return {path: self.backing_for(path) or fom
                for path, fom in self.workspace.fom_cache._files.items()}

    def reset(self):
        self._backings.clear()
        self._dirty.clear()
        self._costly_path = None

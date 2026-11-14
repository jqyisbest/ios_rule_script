"""Compare business content independently of framework-owned header metadata."""
import re


def metadata_key(line, keys):
    match = re.fullmatch(r"\s*[!#]\s+([A-Za-z0-9_-]+)(:\s*)([^\r\n]*)", line)
    return match[1].upper() if match and match[1].upper() in keys else None


def _split_header_records(records):
    for index, record in enumerate(records):
        if record.strip() and not record.lstrip().startswith('#'):
            if record.startswith(('%YAML ', '%TAG ')) or re.fullmatch(r'---(?:[ \t]+#.*)?[ \t]*', record.rstrip('\r\n')):
                continue
            return records[:index], records[index:]
    return records, []


def split_header(text):
    return _split_header_records(text.splitlines(keepends=True))


def without_metadata(text, keys, *, header_only=False):
    header, body = split_header(text) if header_only else (text.splitlines(keepends=True), [])
    return ''.join(record for record in header if metadata_key(record.rstrip('\r\n'), keys) is None) + ''.join(body)



def list_header_nodes(fom):
    prefixes = ('#', '!') if fom.client == 'AdGuard' else ('#', '//', ';')
    header = []
    for node in fom.nodes:
        line = node.render()
        if getattr(node, '_metadata_header', None) is False or line.strip() and not line.lstrip().startswith(prefixes):
            break
        header.append(node)
    return header


def mark_list_header(fom):
    from rule_framework.rule_helpers import STANDARD_TYPES
    from rule_framework.quantumult_lists import QUANTUMULT_TYPES
    counters = {'TOTAL'} | (STANDARD_TYPES | QUANTUMULT_TYPES | {'AND', 'OR', 'NOT'} if fom.client != 'AdGuard' else set())
    header = set()
    seen_counters = set()
    for node in list_header_nodes(fom):
        key = metadata_key(node.render(), counters)
        if key in seen_counters:
            break
        if key and not re.fullmatch(r'\s*[!#]\s+' + re.escape(key) + r':\s*\d+[ \t]*', node.render(), re.I):
            break
        if key:
            seen_counters.add(key)
        header.add(node)
    from rule_framework.ast import CommentNode, BlankNode
    for node in fom.nodes:
        if isinstance(node, (CommentNode, BlankNode)):
            node._metadata_header = node in header
    fom._metadata_baseline_header_size = len(header)
    if '_metadata_origin' not in fom.__dict__:
        fom._metadata_origin_header_size = len(header)


def remember_list_baseline(fom):
    fom._metadata_baseline = fom.render_bytes()
    fom._metadata_baseline_header_size = len(list_header_nodes(fom))


def list_baseline_header_size(fom, baseline):
    if baseline == getattr(fom, '_metadata_origin', None) and hasattr(fom, '_metadata_origin_header_size'):
        return fom._metadata_origin_header_size
    if baseline == fom._metadata_baseline and hasattr(fom, '_metadata_baseline_header_size'):
        return fom._metadata_baseline_header_size
    from rule_framework.text_json import decode_text
    text, _, _ = decode_text(baseline)
    prefixes = ('#', '!') if fom.client == 'AdGuard' else ('#', '//', ';')
    from rule_framework.text_json import split_physical_lines
    records = split_physical_lines(text)
    return next((index for index, line in enumerate(records) if line.strip() and not line.lstrip().startswith(prefixes)), len(records))


def metadata_baselines(fom):
    origin = getattr(fom, '_metadata_origin', None)
    baseline = getattr(fom, '_metadata_baseline', b'')
    return ([origin] if origin is not None else []) + ([baseline] if baseline and baseline != origin else [])


def volatile_metadata(line):
    match = (re.fullmatch(r'\s*#!(updated|desc)\s*=\s*(.*?)[ \t]*', line, re.I)
             or re.fullmatch(r'\s*[!#](?:!)?\s+(updated|desc):\s*(.*?)[ \t]*', line, re.I))
    if not match or match[1].lower() == 'desc' and not re.fullmatch(r'最后更新时间 \d{4}-\d\d-\d\d \d\d:\d\d:\d\d', match[2]):
        return None
    return match[1].lower(), match[2]


def timestamp_records(fom, text):
    from rule_framework.text_json import split_physical_lines
    physical = ('header_nodes' in fom.__dict__ or '_metadata' not in fom.__dict__
                or getattr(fom, 'format', None) == 'text')
    records = split_physical_lines(text) if physical else text.splitlines(keepends=True)
    if 'header_nodes' in fom.__dict__:
        boundary = next((index for index, record in enumerate(records) if re.fullmatch(r'\s*\[[^\]]+\][ \t]*', record.rstrip('\r\n'))), len(records))
        header, body = records[:boundary], records[boundary:]
    elif '_metadata' in fom.__dict__:
        header, body = _split_header_records(records)
    else:
        body_size = len(fom.nodes) - len(list_header_nodes(fom))
        boundary = len(records) - body_size
        header, body = records[:boundary], records[boundary:]
    selected = [(record.rstrip('\r\n'), record[len(record.rstrip('\r\n')):]) for record in header if volatile_metadata(record.rstrip('\r\n'))]
    stable = ''.join(record for record in header if not volatile_metadata(record.rstrip('\r\n'))) + ''.join(body)
    return selected, stable


def finish_generated_metadata(fom, automatic, records, *, before=None):
    """Keep satisfied recalculation stable; preserve real explicit repairs."""
    noop = False
    if before is not None:
        from rule_framework.text_json import decode_text
        before_text, _, _ = decode_text(before)
        after_text, _, _ = decode_text(fom.render_bytes())
        old, old_stable = timestamp_records(fom, before_text)
        new, new_stable = timestamp_records(fom, after_text)
        if (old and old_stable == new_stable and
                [volatile_metadata(line)[0] for line, _ in old] == [volatile_metadata(line)[0] for line, _ in new]):
            if '_metadata' in fom.__dict__:
                for line, _ in old:
                    key, value = volatile_metadata(line)
                    if key == 'updated':
                        fom._metadata['UPDATED'] = value
            else:
                nodes = fom.header_nodes if 'header_nodes' in fom.__dict__ else list_header_nodes(fom)
                pending = iter(old)
                for node in nodes:
                    if volatile_metadata(node.render()):
                        node.content, node.line_ending = next(pending)
            pending = iter(old)
            records = tuple(next(pending) if volatile_metadata(line) else (line, ending) for line, ending in records)
            noop = True
    if not noop and (not automatic or getattr(fom, '_metadata_edit_pending', False)):
        fom._metadata_origin = fom.render_bytes()
        if 'header_nodes' not in fom.__dict__ and '_metadata' not in fom.__dict__:
            fom._metadata_origin_header_size = len(list_header_nodes(fom))
    fom._metadata_edit_pending = False
    fom._generated_metadata = records


def restore_list_metadata(fom, baseline, keys, *, header_only=False, baseline_size=None):
    """Retain live business-node aliases while restoring unchanged header bytes."""
    from rule_framework.ast import CommentNode
    from rule_framework.text_json import split_physical_lines
    if header_only:
        current_text = ''.join(node.render() + getattr(node, 'line_ending', fom._newline) for node in fom.nodes)
        current_limit = len(_split_header_records(split_physical_lines(current_text))[0])
    else:
        current_limit = len(list_header_nodes(fom))
    current = iter(node for index, node in enumerate(fom.nodes) if index >= current_limit or metadata_key(node.render(), keys) is None)
    restored = []
    baseline_limit = len(_split_header_records(split_physical_lines(baseline))[0]) if header_only else baseline_size
    for index, record in enumerate(split_physical_lines(baseline)):
        line = record.rstrip("\r\n")
        if index >= baseline_limit or metadata_key(line, keys) is None:
            node = next(current)
        else:
            node = CommentNode(line)
            node._metadata_header = True
            node.line_ending = record[len(line):]
        restored.append(node)
    fom.nodes[:] = restored


def restore_unchanged_ini_metadata(fom, count_keys):
    """Restore automatic headers against run origin or the latest Task boundary."""
    from rule_framework.ast import CommentNode
    from rule_framework.text_json import decode_text, split_physical_lines
    owned = ini_metadata_selector(count_keys)
    def split(text):
        records = split_physical_lines(text)
        boundary = next((i for i, record in enumerate(records) if re.fullmatch(r"\s*\[[^\]]+\][ \t]*", record.rstrip("\r\n"))), len(records))
        return records[:boundary], records[boundary:]
    previous, _, _ = decode_text(fom._metadata_baseline)
    previous_header, _ = split(previous)
    records = lambda header: tuple((line.rstrip('\r\n'), line[len(line.rstrip('\r\n')):]) for line in header if owned(line.rstrip('\r\n')))
    current_metadata = tuple((node.render(), getattr(node, 'line_ending', fom._newline)) for node in fom.header_nodes if owned(node.render()))
    if current_metadata != getattr(fom, '_generated_metadata', records(previous_header)):
        fom._metadata_edit_pending = True
        return False
    current, _, _ = decode_text(fom.render_bytes())
    new_header, new_body = split(current)
    filtered = lambda header: ''.join(line for line in header if not owned(line.rstrip('\r\n')))
    for baseline in metadata_baselines(fom):
        text, _, _ = decode_text(baseline)
        old_header, old_body = split(text)
        if new_body != old_body or filtered(new_header) != filtered(old_header):
            continue
        live = iter(node for node in fom.header_nodes if not owned(node.render()))
        restored = []
        for record in old_header:
            line = record.rstrip('\r\n')
            if owned(line):
                node = CommentNode(line)
                node.line_ending = record[len(line):]
            else:
                node = next(live)
            restored.append(node)
        fom.header_nodes[:] = restored
        fom._generated_metadata = records(old_header)
        return True
    return False


def restore_unchanged_list_metadata(fom, keys):
    from rule_framework.text_json import decode_text, split_physical_lines
    previous, _, _ = decode_text(fom._metadata_baseline)
    def records(text, size):
        return tuple((line.rstrip('\r\n'), line[len(line.rstrip('\r\n')):]) for line in split_physical_lines(text)[:size] if metadata_key(line.rstrip('\r\n'), keys))
    current_size = len(list_header_nodes(fom))
    current_records = tuple((node.render(), getattr(node, 'line_ending', fom._newline)) for node in list_header_nodes(fom) if metadata_key(node.render(), keys))
    if current_records != getattr(fom, '_generated_metadata', records(previous, list_baseline_header_size(fom, fom._metadata_baseline))):
        fom._metadata_edit_pending = True
        return False
    current, _, _ = decode_text(fom.render_bytes())
    def business(text, size):
        return ''.join(line for index, line in enumerate(split_physical_lines(text)) if index >= size or not metadata_key(line.rstrip('\r\n'), keys))
    for baseline in metadata_baselines(fom):
        text, _, _ = decode_text(baseline)
        size = list_baseline_header_size(fom, baseline)
        if business(current, current_size) == business(text, size):
            restore_list_metadata(fom, text, keys, baseline_size=size)
            fom._generated_metadata = records(text, size)
            return True
    return False


def ini_metadata_selector(count_keys):
    keys = {key.lower() for key in count_keys} | {"author", "repo", "homepage", "updated", "total",
        "and", "or", "not", "domain", "domain-suffix", "domain-wildcard", "domain-keyword",
        "url-regex", "ip-cidr", "ip-asn", "reject", "redirect", "mitm",
        "http-request-script", "http-response-script", "cron-script", "force-http-engine-hosts"}
    def owned(line):
        match = (re.fullmatch(r"\s*#!([\w-]+)\s*=\s*(.*?)[ \t]*", line)
                 or re.fullmatch(r"\s*#(?:!)?\s+([\w-]+):\s*(.*?)[ \t]*", line))
        return bool(match and (match[1].lower() in keys or
            match[1].lower() == "desc" and re.fullmatch(r"最后更新时间 \d{4}-\d\d-\d\d \d\d:\d\d:\d\d", match[2])))
    return owned


def remember_ini_metadata(fom, count_keys, automatic, *, before=None):
    owned = ini_metadata_selector(count_keys)
    records = tuple((node.render(), getattr(node, "line_ending", fom._newline)) for node in fom.header_nodes if owned(node.render()))
    finish_generated_metadata(fom, automatic, records, before=before)


def resolve_signature(settings=None):
    """Resolve and validate canonical author and repo identity without mutating settings."""
    settings = settings or {}
    raw_author = settings.get('author')
    raw_repo = settings.get('repo')
    author = 'jqyisbest' if raw_author is None or raw_author == '' else raw_author
    repo = 'https://github.com/jqyisbest/ios_rule_script' if raw_repo is None or raw_repo == '' else raw_repo
    for val, name in ((author, 'author'), (repo, 'repo')):
        if (not isinstance(val, str)
                or any(c in val for c in '\r\n\0\v\f\x1c\x1d\x1e\x85\u2028\u2029')
                or not val.strip()):
            raise ValueError(f'{name} must be a non-empty single-line string')
    return author.strip(), repo.strip()

from rule_framework.text_json import split_physical_lines
from rule_framework.ast import (
    parse_line, RuleNode, CommentNode, ASTNode, TypelessRuleNode, 
    AdGuardRuleNode, BlankNode, SectionNode, RewriteNode, ScriptNode, MITMNode
)
import re
import logging
from rule_framework.rule_helpers import UNSET

logger = logging.getLogger('RuleFramework')

def _get_now(fom):
    from datetime import datetime
    from zoneinfo import ZoneInfo
    settings = getattr(fom, 'settings', {})
    timezone_name = settings.get('timezone', 'Asia/Shanghai')
    return datetime.now(ZoneInfo(timezone_name)).strftime('%Y-%m-%d %H:%M:%S')

def _apply_text_replacement(text: str, search: str, replace: str, is_regex: bool = False, count: int = 0) -> tuple:
    from rule_framework.text_json import validate_text_operation
    validate_text_operation(search, replace, is_regex, count)
    if is_regex:
        import re
        return re.subn(search, replace, text, count=count)
    if count == 0:
        c = text.count(search)
        return text.replace(search, replace), c
    c = min(text.count(search), count)
    return text.replace(search, replace, count), c

def is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except (ValueError, AttributeError):
        return False

SEMANTIC_RULE_MAP = {
    'asn': {'IP-ASN', 'ASN', 'GEOIP,ASN'},
    'ip': {'IP-CIDR', 'IP-CIDR6'},
    'domain': {'DOMAIN', 'DOMAIN-SUFFIX', 'HOST', 'HOST-SUFFIX'},
    'keyword': {'DOMAIN-KEYWORD', 'HOST-KEYWORD'},
}

def normalize_rule_type(rule_type: str) -> set:
    if not rule_type:
        return set()
    r_lower = rule_type.lower()
    if r_lower in SEMANTIC_RULE_MAP:
        return set(SEMANTIC_RULE_MAP[r_lower])
    for v in SEMANTIC_RULE_MAP.values():
        if any(r_lower == member.lower() for member in v):
            return set(v)
    return {rule_type.upper()}


def calculate_insert_index(nodes: list, insert: dict, is_section: bool = False, section_name: str = None) -> int:
    from rule_framework.rule_helpers import calculate_insert_index as locate
    return locate(nodes, insert, is_section, section_name)


class FOMBase:
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        from rule_framework.managed_io import guard_managed_save
        # Resolve inherited mixin methods as well as methods defined by adapters.
        for name in ('save', 'save_to'):
            method = getattr(cls, name, None)
            if callable(method):
                setattr(cls, name, guard_managed_save(method))

    # Managed state is independent of parser handles, staged-save callbacks and
    # other adapter infrastructure. New FOMs extend this tuple for their content.
    transaction_fields = (
        'filepath', 'nodes', 'data', 'sections', 'section_order', 'header_nodes',
        'header_comments', 'ends_with_newline', 'is_dirty', 'content', 'settings', '_generated_metadata', '_metadata_origin', '_metadata_edit_pending', '_metadata_origin_header_size', '_metadata_baseline_header_size',
    )
    # Native format adapters declare parsed roots that retain payload and aliases.
    # When an extension field aliases native data, the native copy takes priority.
    # Other adapter fields retain Python's explicit deepcopy/reducer protocols.
    native_transaction_fields = ()

    def snapshot_state(self, *, memo=None):
        """Copy managed content and metadata without copying parser resources."""
        from rule_framework.state_copy import copy_managed_state
        state = {name: self.__dict__[name] for name in self.transaction_fields
                 if name in self.__dict__}
        return copy_managed_state(state, memo=memo, native_values=(
            state[name] for name in self.native_transaction_fields if name in state))

    def restore_state(self, state, *, memo=None):
        from rule_framework.state_copy import copy_managed_state
        restored = copy_managed_state(state, memo=memo, native_values=(
            state[name] for name in self.native_transaction_fields if name in state))
        for name in self.transaction_fields:
            self.__dict__.pop(name, None)
        self.__dict__.update(restored)

    def validate(self):
        """Validate the managed content shape; adapters add their syntax checks."""
        if 'content' in self.__dict__ and not isinstance(self.content, str):
            raise ValueError('Managed text content must be a string')
        if 'settings' in self.__dict__ and not isinstance(self.settings, dict):
            raise ValueError('Managed settings must be a dictionary')
        for field in ('nodes', 'header_nodes', 'header_comments', 'section_order'):
            if field in self.__dict__ and not isinstance(self.__dict__[field], list):
                raise ValueError(f'Managed {field} must be a list')
        for field in ('sections', 'data'):
            if field in self.__dict__ and self.__dict__[field] is not None and not isinstance(self.__dict__[field], dict):
                raise ValueError(f'Managed {field} must be a dictionary')

        from rule_framework.managed_validation import validate_fom_collections
        validate_fom_collections(self)

    def save_to(self, path: str):
        original = self.filepath
        try:
            self.filepath = path
            self.save()
        finally:
            self.filepath = original

    def scaffold(self, base_name: str):
        from rule_framework.ast import CommentNode
        now = _get_now(self)
        
        if hasattr(self, "data"):
            yaml_content = f"""# NAME: {base_name}
# UPDATED: {now}
# TOTAL: 0
payload: []
"""
            self.data = self.yaml.load(yaml_content)
        else:
            comments = [
                CommentNode(f"# NAME: {base_name}"),
                CommentNode(f"# UPDATED: {now}"),
                CommentNode("# TOTAL: 0")
            ]
            if hasattr(self, "nodes"):
                self.nodes = comments + getattr(self, "nodes", [])
            elif hasattr(self, "header_nodes"):
                self.header_nodes = comments + getattr(self, "header_nodes", [])
        self.is_dirty = True

    def export_modules(self):
        from rule_framework.module_conversion import export_modules
        return export_modules(self)

    def merge_modules(self, collections, *, destination=UNSET, insert=None):
        from rule_framework.module_conversion import merge_modules
        return merge_modules(self, collections, destination=destination, insert=insert)

    def export_rules(self, *, policy=UNSET):
        from rule_framework.routing_conversion import export_rules
        return export_rules(self, policy=policy)

    def merge_rules(self, collections, *, destination=UNSET):
        from rule_framework.routing_conversion import merge_rules
        return merge_rules(self, collections, destination=destination)

    def add_rule(self, *args, **kwargs):
        raise ValueError(f"{type(self).__name__} does not support add_rule")
        
    def add_native(self, content, *, kind, insert=None, section=None):
        from rule_framework.native_input import apply_native
        return apply_native(self, content, kind=kind, insert=insert, section=section)

    def remove_rule(self, *args, **kwargs):
        raise ValueError(f"{type(self).__name__} does not support remove_rule")
        
    def add_rewrite(self, *args, **kwargs):
        raise ValueError(f"{type(self).__name__} does not support add_rewrite")
        
    def remove_rewrite(self, *args, **kwargs):
        raise ValueError(f"{type(self).__name__} does not support remove_rewrite")

    def add_mitm(self, *args, **kwargs):
        raise ValueError(f"{type(self).__name__} does not support add_mitm")

    def remove_mitm(self, *args, **kwargs):
        raise ValueError(f"{type(self).__name__} does not support remove_mitm")
        
    def add_script(self, *args, **kwargs):
        raise ValueError(f"{type(self).__name__} does not support add_script")

    def remove_script(self, *args, **kwargs):
        raise ValueError(f"{type(self).__name__} does not support remove_script")

    def modify(self, *args, **kwargs):
        raise ValueError(f"{type(self).__name__} does not support modify")


class ListFileBase(FOMBase):
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.nodes = []
        self.is_dirty = False

    def load(self):
        with open(self.filepath, 'r', encoding='utf-8') as f:
            raw = f.read()
        self.ends_with_newline = raw.endswith('\n')
        self.nodes = []
        for line in raw.splitlines():
            self.nodes.append(parse_line(line))
        self.is_dirty = False

    def save(self):
        content = "\n".join(node.render() for node in self.nodes)
        if getattr(self, 'ends_with_newline', True) and content:
            content += "\n"
        with open(self.filepath, 'w', encoding='utf-8', newline='') as f:
            f.write(content)

    def add_rule(self, rule_type: str, value: str, policy: str = None, insert: dict = None):
        for n in self.nodes:
            if isinstance(n, RuleNode) and n.type == rule_type and n.value == value:
                n.policy = policy
                self.is_dirty = True
                logger.info(f"Updated existing rule in {self.filepath}: {rule_type}, {value} -> {policy}")
                self.update_metadata()
                return
        node = RuleNode(rule_type, value, policy)
        
        if not insert:
            self.nodes.append(node)
        else:
            idx = calculate_insert_index(self.nodes, insert, is_section=False)
            self.nodes.insert(idx, node)
                
        self.is_dirty = True
        self.update_metadata()

    def remove_rule(self, rule_type: str, value: str = None):
        target_types = normalize_rule_type(rule_type)
        old_len = len(self.nodes)
        self.nodes = [
            n for n in self.nodes 
            if not (isinstance(n, RuleNode) and n.type.upper() in target_types and (value is None or n.value == value))
        ]
        if len(self.nodes) != old_len:
            self.is_dirty = True
            self.update_metadata()

    def modify(self, search: str, replace: str, is_regex: bool = False, count: int = 0):
        new_nodes = []
        modified = False
        replacements = 0
        for node in self.nodes:
            if count > 0 and replacements >= count:
                new_nodes.append(node)
                continue
            rendered = node.render()
            matched = bool(re.search(search, rendered)) if is_regex else (search in rendered)
            if matched:
                rem_count = count - replacements if count > 0 else 0
                new_text, reps = _apply_text_replacement(rendered, search, replace, is_regex, rem_count)
                if reps > 0:
                    modified = True
                    replacements += reps
                new_nodes.append(parse_line(new_text))
            else:
                new_nodes.append(node)
        self.nodes = new_nodes
        if modified:
            self.is_dirty = True
            self.update_metadata()

    def _get_rule_count(self) -> int:
        return sum(1 for n in self.nodes if isinstance(n, RuleNode))

    def update_metadata(self):
        now = _get_now(self)
        count = self._get_rule_count()
        prefix = self.get_comment_prefix().strip()
        settings = getattr(self, 'settings', {})
        from rule_framework.metadata import resolve_signature
        author, repo = resolve_signature(settings)
        
        found_total = False
        found_updated = False
        
        new_nodes = []
        found_our_author = False
        found_our_repo = False
        
        for node in self.nodes:
            if isinstance(node, CommentNode):
                rendered = node.render()
                if rendered.startswith(f'{prefix} TOTAL:') or rendered.startswith('# TOTAL:'):
                    p = rendered[0] if rendered[0] in ['!', '#'] else prefix
                    new_nodes.append(CommentNode(f'{p} TOTAL: {count}'))
                    found_total = True
                    continue
                elif rendered.startswith(f'{prefix} UPDATED:') or rendered.startswith('# UPDATED:'):
                    p = rendered[0] if rendered[0] in ['!', '#'] else prefix
                    new_nodes.append(CommentNode(f'{p} UPDATED: {now}'))
                    found_updated = True
                    continue
                elif (rendered.startswith(f'{prefix} AUTHOR:') or rendered.startswith('# AUTHOR:')) and rendered.split(':', 1)[1].strip() == author:
                    found_our_author = True
                elif (rendered.startswith(f'{prefix} REPO:') or rendered.startswith('# REPO:')) and rendered.split(':', 1)[1].strip() == repo:
                    found_our_repo = True
                elif (author and not found_our_author) and (rendered.startswith(f'{prefix} AUTHOR:') or rendered.startswith('# AUTHOR:')):
                    # Insert our author right BEFORE the original author
                    p = rendered[0] if rendered[0] in ['!', '#'] else prefix
                    new_nodes.append(CommentNode(f'{p} AUTHOR: {author}'))
                    found_our_author = True
                elif (repo and not found_our_repo) and (rendered.startswith(f'{prefix} REPO:') or rendered.startswith('# REPO:')):
                    p = rendered[0] if rendered[0] in ['!', '#'] else prefix
                    new_nodes.append(CommentNode(f'{p} REPO: {repo}'))
                    found_our_repo = True
            new_nodes.append(node)
            
        if not found_total:
            new_nodes.insert(0, CommentNode(f'{prefix} TOTAL: {count}'))
            
        if not found_updated:
            for i, node in enumerate(new_nodes):
                if isinstance(node, CommentNode) and 'TOTAL:' in node.render():
                    new_nodes.insert(i + 1, CommentNode(f'{prefix} UPDATED: {now}'))
                    break
                    
        if author and not found_our_author:
            new_nodes.insert(0, CommentNode(f'{prefix} AUTHOR: {author}'))
        if repo and not found_our_repo:
            new_nodes.insert(1 if author else 0, CommentNode(f'{prefix} REPO: {repo}'))
            
        self.nodes = new_nodes

    def get_comment_prefix(self) -> str:
        return "# "



from rule_framework.standard_lists import StandardListMixin


class StandardListFile(StandardListMixin, ListFileBase):
    transaction_fields = ListFileBase.transaction_fields + ("file_role", "client", "_raw_bytes", "_metadata_baseline", "_encoding", "_newline")

from rule_framework.quantumult_lists import QuantumultListMixin


class QuanXListFile(QuantumultListMixin, ListFileBase):
    transaction_fields = ListFileBase.transaction_fields + ("file_role", "client", "_raw_bytes", "_metadata_baseline", "_encoding", "_newline")

class INIFileFOM(FOMBase):
    transaction_fields = FOMBase.transaction_fields + ("_encoding", "_bom", "_newline", "_metadata_baseline")

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.header_nodes = []
        self.sections = {}
        self.section_order = []
        self.is_dirty = False
        self._metadata_baseline = b''
        self._newline = '\n'

    def load(self):
        from pathlib import Path
        from rule_framework.text_json import decode_text
        self._metadata_baseline = Path(self.filepath).read_bytes()
        raw, self._encoding, self._bom = decode_text(self._metadata_baseline)
        self._parse_generic_text(raw)
        self.is_dirty = False

    def _parse_generic_text(self, raw):
        current_section = None
        self._newline = next((match[0] for match in re.finditer(r'\r\n|\n|\r', raw)), '\n')
        self.ends_with_newline = raw.endswith(('\n', '\r'))
        self.header_nodes, self.sections, self.section_order = [], {}, []
        for record in split_physical_lines(raw):
            line = record.rstrip('\r\n')
            node = parse_line(line)
            node.line_ending = record[len(line):]
            if isinstance(node, SectionNode):
                current_section = node.name
                if current_section not in self.sections:
                    self.sections[current_section] = []
                self.section_order.append(current_section)
                self.sections[current_section].append(node)
            else:
                if current_section is None:
                    self.header_nodes.append(node)
                else:
                    self.sections[current_section].append(node)

    @property
    def is_snippet(self):
        return False

    @property
    def is_module(self):
        return False

    def _ordered_generic_nodes(self):
        yield from self.header_nodes
        blocks = {}
        for section, nodes in self.sections.items():
            groups, current = [], []
            for node in nodes:
                if isinstance(node, SectionNode) and current:
                    groups.append(current)
                    current = []
                current.append(node)
            groups.append(current)
            blocks[section] = groups
        from collections import Counter
        remaining = Counter(self.section_order)
        positions = {}
        for section in self.section_order:
            index = positions.get(section, 0)
            groups = blocks[section]
            selected = groups[index:] if remaining[section] == 1 else groups[index:index + 1]
            for group in selected:
                yield from group
            positions[section] = index + 1
            remaining[section] -= 1

    def render_bytes(self):
        nodes = [node for node in self._ordered_generic_nodes()
                 if not (self.is_snippet and isinstance(node, SectionNode))]
        newline = getattr(self, '_newline', '\n')
        records = []
        for index, node in enumerate(nodes):
            ending = getattr(node, 'line_ending', newline)
            if index < len(nodes) - 1 and not ending:
                ending = newline
            if index == len(nodes) - 1 and not getattr(self, 'ends_with_newline', True):
                ending = ''
            records.append(node.render() + ending)
        content = ''.join(records)
        from rule_framework.text_json import encode_text
        return encode_text(content, getattr(self, '_encoding', 'utf-8'), getattr(self, '_bom', b''))

    def validate_complete(self):
        if self.render_bytes() != self._metadata_baseline:
            self.update_metadata(only_if_changed=True)
            self._metadata_baseline = self.render_bytes()

    def save(self):
        from pathlib import Path
        self.validate()
        self.validate_complete()
        Path(self.filepath).write_bytes(self.render_bytes())

    def update_metadata(self, *, only_if_changed=False):
        metadata_before = self.render_bytes() if not only_if_changed else None
        from rule_framework.metadata import restore_unchanged_ini_metadata, remember_ini_metadata, resolve_signature
        if only_if_changed and restore_unchanged_ini_metadata(self, ()):
            return
        now = _get_now(self)
        is_plugin = isinstance(self, (PluginFile, SgmoduleFile))
        prefix = "#!" if is_plugin else "#"
        author_key = f"{prefix}author =" if is_plugin else f"{prefix} AUTHOR:"
        repo_key = f"{prefix}homepage =" if is_plugin else f"{prefix} REPO:"
        
        settings = getattr(self, 'settings', {})
        author, repo = resolve_signature(settings)
        
        count = 0
        for sec in [self.get_rule_section_name(), self.get_rewrite_section_name(), self.get_script_section_name(), self.get_mitm_section_name()]:
            if sec in self.sections:
                count += sum(1 for n in self.sections[sec] if not isinstance(n, CommentNode) and not isinstance(n, SectionNode) and n.render().strip())
            
        new_headers = []
        
        # Phase 1: Clean our existing signatures to avoid duplicates
        cleaned_headers = []
        for node in self.header_nodes:
            if isinstance(node, CommentNode):
                rendered = node.render()
                author_match = re.fullmatch(re.escape(prefix) + r'(?:\s+AUTHOR:\s*|author\s*=\s*)(.*?)\s*', rendered)
                repo_match = re.fullmatch(re.escape(prefix) + r'(?:\s+REPO:\s*|homepage\s*=\s*)(.*?)\s*', rendered)
                if author and author_match and author_match.group(1) == author:
                    continue
                if repo and repo_match and repo_match.group(1) == repo:
                    continue
            cleaned_headers.append(node)
            
        # Phase 2: Find the upstream signature block or NAME block
        insert_idx = 0
        for i, node in enumerate(cleaned_headers):
            if isinstance(node, CommentNode):
                rendered = node.render()
                is_author_line = bool(re.match(r'^' + re.escape(prefix) + r'author\s*=', rendered)) or rendered.startswith(f'{prefix} AUTHOR:')
                if is_author_line:
                    insert_idx = i
                    break
        else:
            for i, node in enumerate(cleaned_headers):
                if isinstance(node, CommentNode) and " NAME:" in node.render():
                    insert_idx = i + 1
                    break
                    
        # Phase 3: Insert our block
        block = []
        if author:
            block.append(CommentNode(f'{author_key} {author}'))
        if repo:
            block.append(CommentNode(f'{repo_key} {repo}'))
            
        new_headers = cleaned_headers[:insert_idx] + block + cleaned_headers[insert_idx:]
        
        # Phase 4: Handle TOTAL and UPDATED
        final_headers = []
        for node in new_headers:
            if isinstance(node, CommentNode):
                rendered = node.render()
                if rendered.startswith(f'{prefix} UPDATED:') or rendered.startswith(f'{prefix}UPDATED:'):
                    final_headers.append(CommentNode(f'{prefix} UPDATED: {now}'))
                    continue
                elif rendered.startswith(f'{prefix} TOTAL:') or rendered.startswith(f'{prefix}TOTAL:') or rendered.startswith(f'{prefix} Total count:'):
                    final_headers.append(CommentNode(f'{prefix} TOTAL: {count}'))
                    continue
            final_headers.append(node)
            
        self.header_nodes = final_headers
        remember_ini_metadata(self, (), only_if_changed, before=metadata_before)

    def _ensure_section(self, name: str):
        if name not in self.sections:
            self.sections[name] = [SectionNode(name)]
            self.section_order.append(name)

    def _append_node(self, section_name: str, node: ASTNode, insert: dict = None):
        self._ensure_section(section_name)
        if not insert:
            self.sections[section_name].append(node)
            return
            
        nodes = self.sections[section_name]
        insert_idx = calculate_insert_index(nodes, insert, is_section=True, section_name=section_name)
        nodes.insert(insert_idx, node)

    def get_rule_section_name(self) -> str:
        return "Rule"
        
    def get_rewrite_section_name(self) -> str:
        return "URL Rewrite"
        
    def get_script_section_name(self) -> str:
        return "Script"
        
    def get_mitm_section_name(self) -> str:
        return "MITM"

    def add_rule(self, rule_type: str, value: str, policy: str = UNSET, insert: dict = None):
        sec = self.get_rule_section_name()
        self._ensure_section(sec)
        if insert is not None:
            calculate_insert_index(self.sections[sec], insert, is_section=True, section_name=sec)
        matched = 0
        for n in self.sections[sec]:
            if isinstance(n, RuleNode) and n.type == rule_type and n.value == value:
                if policy is not UNSET and n.policy != policy:
                    n.policy = policy
                    self.is_dirty = True
                matched += 1
        if matched:
            logger.info(f"Updated {matched} existing rules in {self.filepath} [{sec}]: {rule_type}, {value}; policy={'preserved' if policy is UNSET else policy}")
            return
        node = RuleNode(rule_type, value, None if policy is UNSET else policy)
        self._append_node(sec, node, insert=insert)
        self.is_dirty = True

    def remove_rule(self, rule_type: str, value: str = None):
        target_types = normalize_rule_type(rule_type)
        sec = self.get_rule_section_name()
        if sec in self.sections:
            old_len = len(self.sections[sec])
            self.sections[sec] = [
                n for n in self.sections[sec] 
                if not (isinstance(n, RuleNode) and n.type.upper() in target_types and (value is None or n.value == value))
            ]
            if len(self.sections[sec]) != old_len:
                self.is_dirty = True

    def format_rewrite_rule(self, url_pattern: str, reject_type: str = "reject", redirect_url: str = None, status_code: int = None) -> str:
        # Default: Surge / Shadowrocket
        if redirect_url:
            code = status_code or 302
            return f"{url_pattern} {code} {redirect_url}"
        else:
            return f"{url_pattern} {reject_type}"

    def add_rewrite(self, raw_content: str = None, url_pattern: str = None, reject_type: str = "reject", redirect_url: str = None, status_code: int = None, insert: dict = None):
        if url_pattern:
            line_str = self.format_rewrite_rule(url_pattern, reject_type, redirect_url, status_code)
            node = parse_line(line_str)
        elif raw_content:
            node = parse_line(raw_content)
        else:
            raise ValueError("add_rewrite requires url_pattern or raw_content")
            
        if isinstance(node, MITMNode):
            self.add_mitm(node.hostnames)
            return
            
        sec = self.get_rewrite_section_name()
        self._ensure_section(sec)
        
        if isinstance(node, RewriteNode):
            for i, n in enumerate(self.sections[sec]):
                if isinstance(n, RewriteNode) and getattr(node, 'match_pattern', None) and getattr(n, 'match_pattern', None) == node.match_pattern:
                    self.sections[sec][i] = node
                    self.is_dirty = True
                    logger.info(f"Updated existing rewrite in {self.filepath} [{sec}]: {node.match_pattern}")
                    return
        
        self._append_node(sec, node, insert=insert)
        self.is_dirty = True
    def add_mitm(self, hostnames: list, insert: dict = None):
        sec = self.get_mitm_section_name()
        self._ensure_section(sec)
        
        mitm_node = None
        for n in self.sections[sec]:
            if isinstance(n, MITMNode):
                mitm_node = n
                break
                
        if mitm_node is None:
            clean_hosts = []
            for h in hostnames:
                h_clean = h.replace('%APPEND%', '').strip()
                if h_clean and h_clean not in clean_hosts:
                    clean_hosts.append(h_clean)
            if self.is_module:
                raw = f"hostname = %APPEND% {', '.join(clean_hosts)}"
            else:
                raw = f"hostname = {', '.join(clean_hosts)}"
            new_node = MITMNode(clean_hosts, raw)
            self._append_node(sec, new_node)
            self.is_dirty = True
        else:
            sep = "," if ("," in mitm_node.raw_content and ", " not in mitm_node.raw_content) else ", "
            new_hosts = []
            for h in hostnames:
                h_clean = h.replace('%APPEND%', '').strip()
                if h_clean and h_clean not in mitm_node.hostnames:
                    new_hosts.append(h_clean)
                    mitm_node.hostnames.append(h_clean)
            if new_hosts or self.is_module:
                raw = mitm_node.raw_content
                if self.is_module and '%APPEND%' not in raw:
                    raw = raw.replace('hostname =', 'hostname = %APPEND%', 1)
                if new_hosts:
                    raw = raw.rstrip() + sep + sep.join(new_hosts)
                if raw != mitm_node.raw_content:
                    mitm_node.raw_content = raw
                    self.is_dirty = True

    def remove_mitm(self, hostnames: list | str):
        if isinstance(hostnames, str):
            hostnames = [hostnames]
        sec = self.get_mitm_section_name()
        if sec in self.sections:
            new_nodes = []
            for n in self.sections[sec]:
                if isinstance(n, MITMNode):
                    clean_hosts = [h for h in n.hostnames if h not in hostnames]
                    if len(clean_hosts) != len(n.hostnames):
                        self.is_dirty = True
                        if not clean_hosts:
                            continue # Remove the whole node
                        else:
                            # Reconstruct raw_content roughly
                            prefix = "hostname = %APPEND% " if self.is_module else "hostname = "
                            n.raw_content = prefix + ", ".join(clean_hosts)
                            n.hostnames = clean_hosts
                new_nodes.append(n)
            self.sections[sec] = new_nodes

    def remove_rewrite(self, pattern: str):
        sec = self.get_rewrite_section_name()
        if sec in self.sections:
            old_len = len(self.sections[sec])
            new_nodes = []
            for n in self.sections[sec]:
                if isinstance(n, RewriteNode):
                    if n.match_pattern == pattern or pattern in n.render():
                        continue
                if isinstance(n, TypelessRuleNode) and pattern in n.value:
                    continue
                new_nodes.append(n)
            
            if len(new_nodes) != old_len:
                self.sections[sec] = new_nodes
                self.is_dirty = True

    def add_script(self, raw_content: str, insert: dict = None):
        node = parse_line(raw_content)
        sec = self.get_script_section_name()
        self._ensure_section(sec)
        for i, n in enumerate(self.sections[sec]):
            if isinstance(n, ScriptNode):
                if node.name and n.name == node.name:
                    self.sections[sec][i] = node
                    self.is_dirty = True
                    return
                elif not node.name and n.match_pattern == node.match_pattern:
                    self.sections[sec][i] = node
                    self.is_dirty = True
                    return
        self._append_node(sec, node, insert=insert)
        self.is_dirty = True

    def remove_script(self, name: str = None, pattern: str = None, script_path: str = None):
        sec = self.get_script_section_name()
        if sec in self.sections:
            old_len = len(self.sections[sec])
            new_nodes = []
            for n in self.sections[sec]:
                if isinstance(n, ScriptNode):
                    match_found = False
                    if name:
                        if n.name:
                            match_found = (n.name == name)
                        else:
                            match_found = (pattern and n.match_pattern == pattern) or (script_path and script_path in n.content) or (n.match_pattern == name)
                    else:
                        match_found = (pattern and n.match_pattern == pattern) or (script_path and script_path in n.content)
                    
                    if match_found:
                        continue
                new_nodes.append(n)
            
            if len(new_nodes) != old_len:
                self.sections[sec] = new_nodes
                self.is_dirty = True

    def modify(self, search: str, replace: str, is_regex: bool = False, count: int = 0):
        from rule_framework.text_json import decode_text
        original, _encoding, _bom = decode_text(self.render_bytes())
        updated, _found = _apply_text_replacement(original, search, replace, is_regex, count)
        if updated != original:
            self._parse_generic_text(updated)
            self.is_dirty = True




class SgmoduleFile(INIFileFOM):
    add_url_rewrite = INIFileFOM.add_rewrite

    @property
    def is_module(self):
        return True

class PluginFile(INIFileFOM):
    # Loon plugin
    def get_rewrite_section_name(self) -> str:
        return "Rewrite"
        
    def format_rewrite_rule(self, url_pattern: str, reject_type: str = "reject", redirect_url: str = None, status_code: int = None) -> str:
        if redirect_url:
            code = status_code or 302
            return f"{url_pattern} {code} {redirect_url}"
        else:
            return f"{url_pattern} - {reject_type}"

from rule_framework.quantumult import QuantumultStructuredMixin, QX_FIELDS


class QuanXConfFile(QuantumultStructuredMixin, INIFileFOM):
    transaction_fields = INIFileFOM.transaction_fields + QX_FIELDS
    def get_rule_section_name(self) -> str:
        return "filter_local"
        
    def get_rewrite_section_name(self) -> str:
        return "rewrite_local"
        
    def get_script_section_name(self) -> str:
        return "rewrite_local"
        
    def get_mitm_section_name(self) -> str:
        return "mitm"
        
    def format_rewrite_rule(self, url_pattern: str, reject_type: str = "reject", redirect_url: str = None, status_code: int = None) -> str:
        if redirect_url:
            code = status_code or 302
            return f"{url_pattern} url {code} {redirect_url}"
        else:
            return f"{url_pattern} url {reject_type}"
from ruamel.yaml import YAML
from pathlib import Path

from rule_framework.mihomo_formats import MihomoYamlMixin, MihomoTextMixin, MIHOMO_FIELDS


class ClashYamlFile(MihomoYamlMixin, FOMBase):
    transaction_fields = FOMBase.transaction_fields + MIHOMO_FIELDS
    native_transaction_fields = ('data', '_source_data')


class ClashTextPayloadFile(MihomoTextMixin, ListFileBase):
    transaction_fields = ListFileBase.transaction_fields + MIHOMO_FIELDS


class ClashClassicalListFile(ClashTextPayloadFile):
    """mihomo classical provider content supplied in a .list resource."""


from rule_framework.adguard_filters import AdGuardFilterMixin


class AdGuardFile(AdGuardFilterMixin, ListFileBase):
    transaction_fields = ListFileBase.transaction_fields + (
        "client", "file_role", "_encoding", "_bom", "_newline", "_metadata_baseline", "_native_opaque",
    )


class PlainFileFOM(FOMBase):
    """Managed source/document text with byte-preserving explicit edits."""
    validation_scope = 'declared text operation'
    transaction_fields = FOMBase.transaction_fields + ('text_encoding', 'text_bom')

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.content = ""
        self.text_encoding = 'utf-8'
        self.text_bom = b''

    def load(self):
        from rule_framework.text_json import decode_text
        with open(self.filepath, 'rb') as source:
            self.content, self.text_encoding, self.text_bom = decode_text(source.read())

    def validate(self):
        from rule_framework.text_json import encode_text
        super().validate()
        encode_text(self.content, self.text_encoding, self.text_bom)

    def render_bytes(self):
        """Serialize current working content for managed reads and publication."""
        from rule_framework.text_json import encode_text
        self.validate()
        return encode_text(self.content, self.text_encoding, self.text_bom)

    def save(self):
        raw = self.render_bytes()
        with open(self.filepath, 'wb') as destination:
            destination.write(raw)

    def remove_rule(self, rule_type, value=None):
        if rule_type == 'domain':
            logger.info('Generic text has no structured domain references: %s; use a text Action or Hook for text changes', self.filepath)
            return
        return super().remove_rule(rule_type, value)

    def modify(self, search: str, replace: str, is_regex: bool = False, count: int = 0):
        self.content, replacements = _apply_text_replacement(self.content, search, replace, is_regex, count)
        logger.info(f"Text replacements: {replacements}; validation={self.validation_scope}")
        return replacements

class JSONFileFOM(PlainFileFOM):
    """JSON text with explicit, existing-path field operations."""
    validation_scope = 'JSON syntax'
    transaction_fields = PlainFileFOM.transaction_fields + ('json_value', 'json_baseline', 'json_content_baseline')

    def __init__(self, filepath: str):
        super().__init__(filepath)
        self.content = '{}'
        self.json_value = {}
        self.json_baseline = '{}'
        self.json_content_baseline = '{}'

    def _accept_content(self):
        from rule_framework.text_json import load_json, serialize_json
        self.json_value = load_json(self.content)
        self.json_baseline = serialize_json(self.json_value)
        self.json_content_baseline = self.content

    def load(self):
        super().load()
        self._accept_content()

    def validate(self):
        from rule_framework.text_json import json_spans, serialize_json
        super().validate()
        rendered = serialize_json(self.json_value)
        text_changed = self.content != self.json_content_baseline
        value_changed = rendered != self.json_baseline
        if text_changed and value_changed:
            raise ValueError('JSON content and json_value changed simultaneously; submit one representation per operation')
        if value_changed:
            root = json_spans(self.content)
            self.content = self.content[:root.start] + rendered + self.content[root.end:]
            # Retain public value identity and aliases held by managed Hooks.
            self.json_baseline = rendered
            self.json_content_baseline = self.content
        elif text_changed:
            self._accept_content()
        super().validate()

    def json_get(self, path):
        """Read an existing value; a missing path raises, while JSON null returns None."""
        from copy import deepcopy
        from rule_framework.text_json import json_spans, select_json_span
        self.validate()
        return deepcopy(select_json_span(json_spans(self.content), path).value)

    def _accept_local_edit(self):
        from rule_framework.text_json import load_json, serialize_json
        rendered = serialize_json(self.json_value)
        if serialize_json(load_json(self.content)) != rendered:
            raise ValueError('JSON local edit has additional aliased changes; submit an explicit root-value change')
        self.json_baseline = rendered
        self.json_content_baseline = self.content
        self.validate()

    def json_set(self, path, value):
        from rule_framework.text_json import json_spans, select_json_span, serialize_json, equivalent_json_text
        self.validate()
        span = select_json_span(json_spans(self.content), path)
        replacement = serialize_json(value)
        if not equivalent_json_text(self.content[span.start:span.end], replacement):
            from copy import deepcopy
            if path:
                parent = self.json_value
                for part in path[:-1]:
                    parent = parent[part]
                parent[path[-1]] = deepcopy(value)
            else:
                self.json_value = deepcopy(value)
            self.content = self.content[:span.start] + replacement + self.content[span.end:]
            self._accept_local_edit()
        logger.info(f"JSON field updated: {path!r}; validation=JSON syntax")

    def json_remove(self, path):
        from rule_framework.text_json import remove_json_path
        self.validate()
        content = remove_json_path(self.content, path)
        parent = self.json_value
        for part in path[:-1]:
            parent = parent[part]
        del parent[path[-1]]
        self.content = content
        self._accept_local_edit()
        logger.info(f"JSON field removed: {path!r}; validation=JSON syntax")

from rule_framework.stash_formats import StashMixin, STASH_FIELDS


class StashOverrideFile(StashMixin, FOMBase):
    transaction_fields = FOMBase.transaction_fields + STASH_FIELDS
    native_transaction_fields = ('data', '_source_data')

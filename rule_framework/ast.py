import re

class ASTNode:
    def render(self) -> str:
        raise NotImplementedError

class CommentNode(ASTNode):
    def __init__(self, content: str):
        self.content = content

    def render(self) -> str:
        return self.content

class BlankNode(ASTNode):
    def __init__(self, content: str = ""):
        self.content = content

    def render(self) -> str:
        return self.content

class RuleNode(ASTNode):
    def __init__(self, rule_type: str, value: str, policy: str = None, trailing_whitespace: str = "", raw_value: str = None, raw_fields: list = None):
        self.type = rule_type
        self.value = value
        self.policy = policy
        self.trailing_whitespace = trailing_whitespace
        self.raw_value = raw_value if raw_value is not None else value
        self.raw_fields = raw_fields
        self._parsed_fields = [self.type, self.raw_value, self.policy]

    def render(self) -> str:
        val = self.raw_value
        parts = [self.type, val]
        if self.policy:
            parts.append(self.policy)
        if self.raw_fields:
            for index, raw in enumerate(self.raw_fields[:len(parts)]):
                if parts[index] == self._parsed_fields[index]:
                    parts[index] = raw
                else:
                    leading = raw[:len(raw) - len(raw.lstrip())]
                    trailing = raw[len(raw.rstrip()):]
                    parts[index] = leading + parts[index] + trailing
        return ",".join(parts) + self.trailing_whitespace

class TypelessRuleNode(ASTNode):
    def __init__(self, value: str, trailing_whitespace: str = ""):
        self.value = value
        self.trailing_whitespace = trailing_whitespace

    def render(self) -> str:
        return self.value + self.trailing_whitespace

class AdGuardRuleNode(ASTNode):
    def __init__(self, core_domain: str, options: str, prepended_instruction: str = "", trailing_whitespace: str = "", raw_value: str = ""):
        self.core_domain = core_domain
        self.options = options
        self.prepended_instruction = prepended_instruction
        self.trailing_whitespace = trailing_whitespace
        self.raw_value = raw_value

    def render(self) -> str:
        return self.raw_value + self.trailing_whitespace


class SectionNode(ASTNode):
    def __init__(self, name: str, trailing_whitespace: str = ""):
        self.name = name
        self.trailing_whitespace = trailing_whitespace

    def render(self) -> str:
        return f"[{self.name}]{self.trailing_whitespace}"

class RewriteNode(ASTNode):
    def __init__(self, content: str, match_pattern: str, trailing_whitespace: str = ""):
        self.content = content
        self.match_pattern = match_pattern
        self.trailing_whitespace = trailing_whitespace

    def render(self) -> str:
        return self.content + self.trailing_whitespace

class ScriptNode(ASTNode):
    def __init__(self, content: str, match_pattern: str = None, trailing_whitespace: str = "", name: str = None):
        self.content = content
        self.match_pattern = match_pattern
        self.trailing_whitespace = trailing_whitespace
        self.name = name

    def render(self) -> str:
        return self.content + self.trailing_whitespace

class MITMNode(ASTNode):
    def __init__(self, hostnames: list, raw_content: str, trailing_whitespace: str = ""):
        self.hostnames = hostnames
        self.raw_content = raw_content
        self.trailing_whitespace = trailing_whitespace

    def render(self) -> str:
        return self.raw_content + self.trailing_whitespace

def get_comma_indices_at_depth_0(s: str) -> list:
    comma_indices = []
    depth = 0
    in_quote = None
    escaped = False
    
    for i, char in enumerate(s):
        if escaped:
            escaped = False
            continue
        if char == '\\':
            escaped = True
            continue
            
        if in_quote:
            if char == in_quote:
                in_quote = None
            continue
        elif char in ('"', "'"):
            in_quote = char
            continue
            
        if char == '(':
            depth += 1
        elif char == ')':
            if depth > 0:
                depth -= 1
        elif char == ',':
            if depth == 0:
                comma_indices.append(i)
    return comma_indices

def split_by_comma_at_depth_0(s: str) -> list:
    comma_indices = get_comma_indices_at_depth_0(s)
    parts = []
    last_idx = 0
    for idx in comma_indices:
        parts.append(s[last_idx:idx].strip())
        last_idx = idx + 1
    parts.append(s[last_idx:].strip())
    return parts

def parse_line(line: str) -> ASTNode:
    stripped_line = line.rstrip('\r\n')
    content_only = stripped_line.rstrip(' \t')
    trailing_whitespace = stripped_line[len(content_only):]
    
    if not content_only:
        return BlankNode(stripped_line)
    
    if content_only.startswith('#') or content_only.startswith('//') or content_only.startswith(';'):
        return CommentNode(stripped_line)
        
    # Section
    m_section = re.match(r'^\[(.+)\]$', content_only)
    if m_section:
        return SectionNode(m_section.group(1), trailing_whitespace)

    # MITM
    if content_only.startswith('hostname') and '=' in content_only:
        parts = content_only.split('=', 1)
        raw_hosts = [h.strip() for h in parts[1].split(',')]
        clean_hosts = [h.replace('%APPEND%', '').replace('%INSERT%', '').strip() for h in raw_hosts if h.strip()]
        return MITMNode(clean_hosts, content_only, trailing_whitespace)

    # Loon V2 Rewrite
    m_loon = re.match(r'^(request|response) if (.+?) then (.+)$', content_only)
    if m_loon:
        condition = m_loon.group(2)
        actions = m_loon.group(3)
        node = RewriteNode(content_only, condition, trailing_whitespace)
        node.pipeline = [a.strip() for a in actions.split('|')]
        return node

    # Script Node - typical Surge / Shadowrocket
    if 'script-path=' in content_only or 'type=http-request' in content_only or 'type=http-response' in content_only:
        m_pattern = re.search(r'pattern=([^,]+)', content_only)
        pattern = m_pattern.group(1) if m_pattern else None
        name = None
        if '=' in content_only:
            left = content_only.split('=', 1)[0].strip()
            if ' ' not in left:
                name = left
        return ScriptNode(content_only, pattern, trailing_whitespace, name=name)

    # QX url rewrite or script
    m_qx = re.match(r'^([^\s]+)\s+url\s+(.+)$', content_only)
    if m_qx:
        pattern = m_qx.group(1)
        action = m_qx.group(2)
        if 'script-' in action:
            return ScriptNode(content_only, pattern, trailing_whitespace)
        else:
            node = RewriteNode(content_only, pattern, trailing_whitespace)
            node.action_tokens = action.split(r'\r\n')
            return node

    # Surge / Shadowrocket Rewrite (URL-REGEX or space-separated)
    if ' ' in content_only and not ',' in content_only.split(' ')[0]:
        space_parts = content_only.split(' ')
        if len(space_parts) >= 2 and space_parts[1] in ('redirect', 'header', '302', '307', 'reject', 'reject-200', 'reject-img', 'reject-dict', 'reject-array'):
            return RewriteNode(content_only, space_parts[0], trailing_whitespace)

    # Loon V1 Rewrite
    if ' - ' in content_only:
        dash_parts = content_only.split(' - ', 1)
        if dash_parts[1].strip() in ('reject', 'reject-200', 'reject-img', 'reject-dict', 'reject-array', 'drop'):
            return RewriteNode(content_only, dash_parts[0].strip(), trailing_whitespace)

    upper_content = content_only.upper()
    if upper_content.startswith('URL-REGEX,') or upper_content.startswith('URL-REWRITE,'):
        comma_indices = get_comma_indices_at_depth_0(content_only)
        if len(comma_indices) >= 2:
            idx1 = comma_indices[0]
            idx2 = comma_indices[-1]
            rule_type = content_only[:idx1].strip()
            value = content_only[idx1+1:idx2].strip()
            policy = content_only[idx2+1:].strip()
            if re.search(r'[\=\?\!\*\+\(\)\[\]\^\\\$]', policy):
                # The policy contains regex special characters, meaning this is a 2-part rule where the regex has a comma.
                value = content_only[idx1+1:].strip()
                return RuleNode(rule_type, value, None, trailing_whitespace, raw_value=value,
                                raw_fields=[content_only[:idx1], content_only[idx1+1:]])
            return RuleNode(rule_type, value, policy, trailing_whitespace, raw_value=value,
                            raw_fields=[content_only[:idx1], content_only[idx1+1:idx2], content_only[idx2+1:]])
        elif len(comma_indices) == 1:
            idx1 = comma_indices[0]
            rule_type = content_only[:idx1].strip()
            value = content_only[idx1+1:].strip()
            return RuleNode(rule_type, value, None, trailing_whitespace, raw_value=value,
                                raw_fields=[content_only[:idx1], content_only[idx1+1:]])

    parts = split_by_comma_at_depth_0(content_only)
    
    if len(parts) >= 2:
        rule_type = parts[0].strip()
        upper_type = rule_type.upper()
        
        value = parts[1].strip()
        policy = ",".join(parts[2:]).strip() if len(parts) >= 3 else None
            
        comma_indices = get_comma_indices_at_depth_0(content_only)
        first_comma = comma_indices[0]
        raw_fields = [content_only[:first_comma]]
        if len(comma_indices) > 1:
            second_comma = comma_indices[1]
            raw_fields.extend([content_only[first_comma+1:second_comma], content_only[second_comma+1:]])
        else:
            raw_fields.append(content_only[first_comma+1:])
        return RuleNode(rule_type, value, policy, trailing_whitespace, raw_value=value, raw_fields=raw_fields)
    else:
        return CommentNode(stripped_line)

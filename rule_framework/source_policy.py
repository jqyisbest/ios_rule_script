"""Explicit source-content acceptance, independent of maintenance actions."""
import os
import re
from dataclasses import dataclass


PURPOSES = frozenset({'auto', 'rule_list', 'configuration', 'json', 'text', 'html', 'binary'})
_HTML_TAG = (
    r'html|head|body|title|base|link|meta|style|address|article|aside|footer|header|h[1-6]|'
    r'hgroup|main|nav|section|blockquote|dd|div|dl|dt|figcaption|figure|hr|li|menu|ol|p|'
    r'pre|ul|a|abbr|b|bdi|bdo|br|cite|code|data|dfn|em|i|kbd|mark|q|rp|rt|ruby|s|samp|'
    r'small|span|strong|sub|sup|time|u|var|wbr|area|audio|img|map|track|video|embed|'
    r'iframe|object|picture|portal|source|svg|math|canvas|noscript|script|del|ins|'
    r'caption|col|colgroup|table|tbody|td|tfoot|th|thead|tr|button|datalist|fieldset|'
    r'form|input|label|legend|meter|optgroup|option|output|progress|select|textarea|'
    r'details|dialog|summary|slot|template|center|font|frameset|frame'
)


def parse_content_policy(declaration, context, *, default_purpose='auto', default_allow_empty=False):
    purpose = declaration.get('purpose', default_purpose)
    if not isinstance(purpose, str) or purpose not in PURPOSES:
        raise ValueError(f'{context}: purpose must be one of {sorted(PURPOSES)}')
    allow_empty = declaration.get('allow_empty', default_allow_empty)
    if not isinstance(allow_empty, bool):
        raise ValueError(f'{context}: allow_empty must be a boolean')
    return purpose, allow_empty


def validate_source_content(data, path, *, purpose='auto', allow_empty=False):
    if not isinstance(data, bytes):
        raise ValueError('Source content must be bytes')
    if not data and not allow_empty:
        raise ValueError('Source content rejected: empty content (allow_empty is false)')
    suffix = os.path.splitext(os.fspath(path))[1].lower()
    if purpose == 'binary':
        return
    if purpose == 'auto':
        if suffix in {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.zip', '.gz', '.bin', '.db', '.mmdb', '.dat'}:
            return
        if suffix == '.html' or suffix == '.htm':
            purpose = 'html'
        elif suffix == '.json':
            purpose = 'json'
        elif suffix == '.list':
            purpose = 'rule_list'
        elif suffix in {'.js', '.py', '.sh'}:
            purpose = 'script'
        elif suffix in {'.conf', '.yaml', '.yml', '.sgmodule', '.lnplugin', '.plugin', '.snippet', '.stoverride', '.qxrewrite'}:
            purpose = 'configuration'
        elif suffix == '.txt' and any(p.lower() in {'rule', 'rewrite'} for p in os.fspath(path).replace('\\', '/').split('/')):
            purpose = 'rule_list'
        else:
            # Unclassified assets retain their existing adapter's validation contract.
            return
    from rule_framework.text_json import decode_text
    text, _, _ = decode_text(data)
    if purpose in {'rule_list', 'configuration', 'json', 'script'}:
        leading = text.lstrip('\ufeff \t\r\n')
        if re.match(
                r'(?is)(?:(?:<!--.*?-->|<\?xml\s.*?\?>)\s*)*'
                rf'(?:<!doctype\s+html\b|<(?:{_HTML_TAG})(?=[\s/>]))',
                leading):
            raise ValueError(f'Source content rejected: HTML document does not match purpose {purpose}')
    if purpose == 'rule_list' and text.lstrip('\ufeff \t\r\n').startswith(('{', '[')):
        import json
        try:
            document = json.loads(text)
        except ValueError:
            pass
        else:
            if isinstance(document, (dict, list)):
                raise ValueError('Source content rejected: JSON document does not match purpose rule_list')
    if purpose == 'json':
        # Explicit JSON purpose also applies to targets with generic text adapters.
        from rule_framework.text_json import load_json
        load_json(text)


@dataclass(frozen=True)
class OriginalSourceFile:
    existed: bool
    data: bytes | None = None
    spool_path: str | None = None

    def read_bytes(self):
        if not self.existed:
            return None
        if self.spool_path is not None:
            with open(self.spool_path, 'rb') as stream:
                return stream.read()
        return self.data

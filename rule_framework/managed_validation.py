"""Shared structural validation for publicly editable FOM collections."""


def _validate_nodes(field, nodes):
    if not isinstance(nodes, list):
        raise ValueError(f'Managed {field} must be a list')
    for index, node in enumerate(nodes):
        render = getattr(node, 'render', None)
        if not callable(render):
            raise ValueError(f'Managed {field}[{index}] must be a node with render()')
        try:
            rendered = render()
        except Exception as error:
            raise ValueError(f'Managed {field}[{index}] rendering failed: {error}') from error
        if not isinstance(rendered, str):
            raise ValueError(f'Managed {field}[{index}] must render a string')
        if hasattr(node, '_opaque_native_line') and rendered != node._opaque_native_line:
            raise ValueError(f'Changed opaque native content requires an explicit native input at {field}[{index}]')


def validate_fom_collections(fom):
    for field in ('nodes', 'header_nodes'):
        if field in fom.__dict__:
            _validate_nodes(field, fom.__dict__[field])
    if 'sections' in fom.__dict__:
        if not isinstance(fom.sections, dict):
            raise ValueError('Managed sections must be a dictionary')
        for section, nodes in fom.sections.items():
            _validate_nodes(f'sections[{section!r}]', nodes)
    if 'section_order' in fom.__dict__:
        for section in fom.section_order:
            if not isinstance(section, str) or section not in getattr(fom, 'sections', {}):
                raise ValueError('Managed section_order must refer to existing section names')
    if 'header_comments' in fom.__dict__:
        if any(not isinstance(comment, str) for comment in fom.header_comments):
            raise ValueError('Managed header_comments must contain strings')


def validate_passive_node(node, *, changed=True, comment_prefixes=('#', '//', ';')):
    """A changed comment/blank keeps its identity and one physical line."""
    from rule_framework.ast import CommentNode, BlankNode
    if not changed or not isinstance(node, (CommentNode, BlankNode)):
        return
    rendered = node.render()
    if not isinstance(rendered, str):
        raise ValueError('Managed comment/blank content must be a string')
    if any(char in rendered for char in '\r\n\0\x85\u2028\u2029'):
        raise ValueError('Changed comment/blank syntax must occupy one physical line')
    if isinstance(node, BlankNode):
        valid = not rendered.strip()
    else:
        valid = rendered.lstrip().startswith(comment_prefixes)
    if not valid:
        raise ValueError('Changed comment/blank content has unrecognized structured syntax')

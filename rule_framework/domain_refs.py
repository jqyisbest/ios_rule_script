"""Exact host-reference recognition for isolated URL match fields.

This visitor recognizes a finite authority grammar. It does not execute a client's
regex engine and never selects declarations by searching path or result text.
"""

from dataclasses import dataclass
import re
from urllib.parse import urlsplit


class ReferenceRecognitionError(ValueError):
    """The requested structured host decision exceeds the supported grammar."""


def canonical_domain(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('Domain reference must be a non-empty string')
    return value.rstrip('.').lower()


@dataclass(frozen=True)
class HostReferences:
    hosts: frozenset[str]
    grammar: str

    def contains(self, domain):
        return canonical_domain(domain) in self.hosts


def _finite_hostnames(expression):
    index = 0

    def alternatives(depth):
        nonlocal index
        if depth > 8:
            raise ReferenceRecognitionError('Hostname groups exceed the supported nesting limit')
        choices = set()
        while True:
            sequence = {''}
            while index < len(expression) and expression[index] not in '|)':
                char = expression[index]
                if char == '(':
                    index += 1
                    if expression.startswith('?:', index):
                        index += 2
                    elif index < len(expression) and expression[index] == '?':
                        raise ReferenceRecognitionError('Unsupported hostname group condition')
                    atom = alternatives(depth + 1)
                    if index >= len(expression) or expression[index] != ')':
                        raise ReferenceRecognitionError('Unclosed hostname group')
                    index += 1
                elif char == '\\':
                    index += 1
                    if index >= len(expression) or expression[index] not in '.-':
                        raise ReferenceRecognitionError('Unsupported hostname escape')
                    atom = {expression[index]}
                    index += 1
                elif char.isalnum() or char in '-_':
                    atom = {char}
                    index += 1
                else:
                    raise ReferenceRecognitionError(f'Unsupported hostname expression token {char!r}')
                if index < len(expression) and expression[index] == '?':
                    atom = atom | {''}
                    index += 1
                sequence = {prefix + suffix for prefix in sequence for suffix in atom}
                if len(sequence) > 64:
                    raise ReferenceRecognitionError('Hostname alternatives exceed the supported limit')
            choices.update(sequence)
            if len(choices) > 64:
                raise ReferenceRecognitionError('Hostname alternatives exceed the supported limit')
            if index < len(expression) and expression[index] == '|':
                index += 1
                continue
            return choices

    names = alternatives(0)
    if index != len(expression):
        raise ReferenceRecognitionError('Unbalanced hostname expression')
    if not names or any(not name or len(name) > 253 or
                        any(not label or len(label) > 63 for label in name.removesuffix('.').split('.'))
                        for name in names):
        raise ReferenceRecognitionError('Invalid literal hostname in URL authority')
    return frozenset(canonical_domain(name) for name in names)


def url_host_references(pattern, *, is_regex=True):
    """Recognize literal hosts, finite alternations and optional literal groups.

    Callers pass only the declaration's URL condition. Unsupported authority
    syntax raises a descriptive error so their enclosing Task can roll back.
    """
    if not isinstance(pattern, str) or not pattern.strip():
        raise ReferenceRecognitionError('URL match condition must be a non-empty string')
    pattern = pattern.strip()
    if pattern[0] in ('\"', "'"):
        if len(pattern) < 2 or pattern[-1] != pattern[0]:
            raise ReferenceRecognitionError('Unclosed quoted URL match condition')
        pattern = pattern[1:-1]
    if not is_regex:
        parsed = urlsplit(pattern)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username:
            raise ReferenceRecognitionError('Expected an explicit HTTP URL authority')
        return HostReferences(frozenset({canonical_domain(parsed.hostname)}), 'literal-url')
    normalized = pattern.replace(r'\/', '/')
    scheme = re.match(r'^\^?(?:https\?|https|http|\(\?:http\|https\)|\(\?:https\|http\))://', normalized)
    if not scheme:
        raise ReferenceRecognitionError('Expected an explicit supported HTTP regex authority')
    authority = normalized[scheme.end():].split('/', 1)[0]
    authority = authority.removesuffix('$')
    port = re.search(r':([0-9]{1,5})$', authority)
    if port:
        if not 1 <= int(port.group(1)) <= 65535:
            raise ReferenceRecognitionError('URL port outside valid range 1..65535')
        authority = authority[:port.start()]
    return HostReferences(_finite_hostnames(authority), 'finite-http-regex-authority')


def domain_pattern_references(pattern):
    """Recognize a finite hostname regex payload without interpreting traffic."""
    if not isinstance(pattern, str) or not pattern.strip():
        raise ReferenceRecognitionError('Domain regex condition must be a non-empty string')
    expression = pattern.strip()
    if expression[0] in ('"', "'"):
        if len(expression) < 2 or expression[-1] != expression[0]:
            raise ReferenceRecognitionError('Unclosed quoted domain regex condition')
        expression = expression[1:-1]
    expression = expression.removeprefix('^').removesuffix('$')
    return HostReferences(_finite_hostnames(expression), 'finite-domain-regex')

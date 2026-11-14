"""Explicit, evidence-bounded routing collection conversion.

Adapters own parsing and generation. Collections retain matching conditions and
results; conversion requires a target file role and an explicit result context.
"""

from dataclasses import dataclass
import logging

from rule_framework.ast import RuleNode, CommentNode, BlankNode
from rule_framework.rule_helpers import UNSET, rule_identity

logger = logging.getLogger("RuleFramework")
CLIENT_ALIASES = {"QuantumultX": "Quantumult X"}
DESTINATION_FORMATS = {
    "Surge": {"rule-set", "domain-set", "configuration", "module"},
    "Loon": {"rule-set", "domain-set"},
    "Shadowrocket": {"rule-set", "domain-set"},
    "Quantumult X": {"rule-set"},
    "AdGuard": {"basic-domain-filter-list"},
    "mihomo": {"classical-yaml", "classical-text", "domain-yaml", "domain-text", "ipcidr-yaml", "ipcidr-text", "configuration"},
}

# Cross-client mappings cover only these audited condition families. Regex,
# wildcard, process/platform and database-specific behaviors need their own
# direction evidence. A matching native spelling alone is insufficient.
COMMON_ROUTING_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN", "FINAL",
}
CLIENT_CONTROL_RESULTS = {
    "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL", "REJECT-TINYGIF",
}


def canonical_client(client):
    return CLIENT_ALIASES.get(client, client)


@dataclass(frozen=True)
class RoutingRule:
    type: str
    value: str | None
    conditions: tuple = ()
    policy: object = UNSET
    result_options: tuple = ()
    client: str = "unknown"
    location: str = ""
    source_format: str = "rule-set"

    def __post_init__(self):
        if not isinstance(self.type, str) or not self.type or self.type != self.type.upper():
            raise ValueError("RoutingRule.type must be a canonical non-empty native type")
        if self.type == "FINAL":
            if self.value is not None:
                raise ValueError("RoutingRule terminal value must be None")
        elif not isinstance(self.value, str) or not self.value.strip() or any(c in self.value for c in "\r\n\0"):
            raise ValueError("RoutingRule.value must be a non-empty single-line string")
        for name in ("conditions", "result_options"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or any(not isinstance(item, str) for item in value):
                raise ValueError(f"RoutingRule.{name} must be a tuple of strings")
        if not isinstance(self.client, str) or canonical_client(self.client) not in DESTINATION_FORMATS:
            raise ValueError("RoutingRule.client must identify a supported source client")
        if not isinstance(self.location, str):
            raise ValueError("RoutingRule.location must be a string")
        if (not isinstance(self.source_format, str)
                or self.source_format not in DESTINATION_FORMATS[canonical_client(self.client)]):
            raise ValueError(f"RoutingRule source_format is unsupported for {self.client}: {self.source_format!r}")
        if self.policy is not UNSET:
            _policy(self.policy)

    @property
    def identity(self):
        if canonical_client(self.client) == 'Shadowrocket':
            from rule_framework.shadowrocket import shadowrocket_rule_identity
            return shadowrocket_rule_identity(self.type, self.value, self.conditions)
        return rule_identity(self.type, self.value, self.conditions)


@dataclass(frozen=True)
class RuleCollection:
    rules: tuple[RoutingRule, ...]

    def __post_init__(self):
        if not isinstance(self.rules, tuple) or any(not isinstance(rule, RoutingRule) for rule in self.rules):
            raise ValueError("RuleCollection.rules must be a tuple of RoutingRule records")


def _policy(value):
    from rule_framework.quantumult_lists import validate_quantumult_policy
    validate_quantumult_policy(value)
    return value


def validate_destination(destination):
    if destination is UNSET:
        return
    if not isinstance(destination, dict):
        raise ValueError("merge_rules.destination must be a dictionary declaring supported fields")
    unknown = set(destination) - {"client", "format", "policy"}
    if unknown:
        raise ValueError(f"Unsupported routing destination fields: {sorted(unknown)}")
    if "client" in destination:
        client = destination["client"]
        if not isinstance(client, str) or canonical_client(client) not in DESTINATION_FORMATS:
            raise ValueError(f"Unsupported routing destination client: {client!r}")
    if "format" in destination:
        format_name = destination["format"]
        if not isinstance(format_name, str) or format_name not in set.union(*DESTINATION_FORMATS.values()):
            raise ValueError(f"Unsupported routing destination format: {format_name!r}")
    if "client" in destination and "format" in destination:
        if destination["format"] not in DESTINATION_FORMATS[canonical_client(destination["client"])]:
            raise ValueError("Routing client and destination format disagree")
    if "policy" in destination:
        _policy(destination["policy"])

def validate_merge_declaration(definition):
    unknown = set(definition) - {"action", "type", "sources", "destination", "name", "task", "file", "targets"}
    if unknown:
        raise ValueError(f"Unsupported merge_rules fields: {sorted(unknown)}")
    if not isinstance(definition.get("sources"), list):
        raise ValueError("merge_rules.sources must be an explicit list; [] is an empty collection")
    validate_destination(definition.get("destination", UNSET))
    for source in definition["sources"]:
        if isinstance(source, str):
            if not source.strip() or "\0" in source:
                raise ValueError("Routing source must be a non-empty text path without NUL")
        elif isinstance(source, dict):
            if set(source) - {"file", "policy"}:
                raise ValueError("Routing source fields are file and optional policy")
            if not isinstance(source.get("file"), str) or not source["file"].strip() or "\0" in source["file"]:
                raise ValueError("Routing source.file must be a non-empty text path without NUL")
            if "policy" in source:
                _policy(source["policy"])
        else:
            raise ValueError("Routing sources must be paths or dictionaries")


def _prepare_format(fom, declaration):
    from rule_framework.fom import StandardListFile, ClashYamlFile, ClashTextPayloadFile
    if not isinstance(declaration, dict):
        return
    client = canonical_client(declaration.get("client")) if "client" in declaration else None
    format_name = declaration.get("format")
    if isinstance(fom, StandardListFile) and client in {"Surge", "Loon", "Shadowrocket"}:
        if fom.client == "unknown":
            fom.client = client
        if not any(isinstance(node, RuleNode) or (
                node.render().strip() and not node.render().lstrip().startswith(("#", "//", ";")))
                for node in fom.nodes) and format_name in {"rule-set", "domain-set"}:
            fom.file_role = format_name
    if isinstance(fom, (ClashYamlFile, ClashTextPayloadFile)) and fom.file_role == "rule-provider":
        if (isinstance(format_name, str) and format_name.endswith(("-yaml", "-text"))
                and format_name.rsplit("-", 1)[1] == fom.format):
            has_explicit_behavior = hasattr(fom, "data") and "behavior" in fom.data
            active = any(isinstance(node, RuleNode) or getattr(node, "recognition_error", None) or (
                node.render().strip() and not node.render().lstrip().startswith(("#", "//", ";")))
                         for node in fom.nodes)
            if not active and not has_explicit_behavior:
                fom.behavior = format_name.rsplit("-", 1)[0]


def prepare_declared_target(fom, actions):
    for action in actions:
        if action.type == "merge_rules":
            declaration = action.definition.get("destination", UNSET)
            _prepare_format(fom, declaration)
            destination_for(fom, declaration)


def _validate_record(rule):
    from rule_framework.rule_helpers import validate_standard_value, validate_options
    from rule_framework.quantumult_lists import quantumult_native_type, validate_quantumult_value, validate_quantumult_options
    from rule_framework.mihomo_formats import mihomo_options
    client = canonical_client(rule.client)
    role = rule.source_format
    if role == "domain-set" or role.startswith("domain-"):
        if rule.type not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"} or rule.conditions:
            raise ValueError(f"{client} source role {role} cannot express type/conditions {rule.type}/{rule.conditions}")
    if role.startswith("ipcidr-"):
        if rule.type not in {"IP-CIDR", "IP-CIDR6"} or rule.conditions:
            raise ValueError(f"{client} source role {role} cannot express type/conditions {rule.type}/{rule.conditions}")
    if rule.type == "FINAL" and client != "Quantumult X" and role != "configuration":
        raise ValueError(f"{client} source role {role} cannot express terminal routing results")
    if client == "AdGuard":
        from rule_framework.adguard_filters import validate_filter_value
        if rule.type != "ADGUARD-DOMAIN" or rule.conditions or rule.result_options or rule.policy is not UNSET:
            raise ValueError("AdGuard record cannot represent extra matching fields or routing results")
        validate_filter_value(rule.value)
        return
    if rule.type == "FINAL":
        if rule.conditions or rule.value is not None:
            raise ValueError(f"{client} terminal record cannot express matching conditions/value")
    elif client == "Quantumult X":
        validate_quantumult_value(quantumult_native_type(rule.type, rule.value), rule.value)
    elif client == "mihomo":
        if rule.type != "DOMAIN-REGEX":
            validate_standard_value(rule.type, rule.value)
    else:
        native = "IP-CIDR" if client == "Shadowrocket" and rule.type == "IP-CIDR6" else rule.type
        validate_standard_value(native, rule.value, client=client)
    if client == "Quantumult X":
        if rule.conditions:
            raise ValueError("Quantumult X record matching conditions must be empty")
        validate_quantumult_options(rule.result_options)
        if rule.policy is UNSET:
            raise ValueError("Quantumult X source record requires policy")
    else:
        if rule.result_options:
            raise ValueError(f"{client} record cannot represent QX interface result options")
        if client == "mihomo":
            mihomo_options(rule.conditions, rule.type)
        elif client == 'Shadowrocket':
            from rule_framework.shadowrocket import validate_options as shadowrocket_options
            native = 'IP-CIDR' if rule.type == 'IP-CIDR6' else rule.type
            shadowrocket_options(rule.conditions, native)
        else:
            validate_options(rule.conditions, rule.type, client)


def destination_for(fom, destination=UNSET):
    from rule_framework.fom import StandardListFile, QuanXListFile, ClashYamlFile, ClashTextPayloadFile, AdGuardFile
    from rule_framework.surge import SurgeFile
    validate_destination(destination)
    _prepare_format(fom, destination)
    declared = {} if destination is UNSET else dict(destination)
    if "client" in declared:
        declared["client"] = canonical_client(declared["client"])
    if isinstance(fom, AdGuardFile):
        actual = {"client": "AdGuard", "format": "basic-domain-filter-list"}
    elif isinstance(fom, ClashYamlFile) and fom.file_role == "full-profile":
        if "mode" in fom.data and fom.data["mode"] != "rule":
            raise ValueError(f"mihomo destination mode={fom.data['mode']!r} bypasses or changes routing rules")
        actual = {"client": "mihomo", "format": "configuration"}
    elif isinstance(fom, SurgeFile):
        actual = {"client": "Surge", "format": "module" if fom.is_module else "configuration"}
    elif isinstance(fom, (ClashYamlFile, ClashTextPayloadFile)) and fom.file_role == "rule-provider":
        actual = {"client": "mihomo", "format": f"{fom.behavior}-{fom.format}"}
    elif isinstance(fom, QuanXListFile):
        actual = {"client": "Quantumult X", "format": "rule-set"}
    elif isinstance(fom, StandardListFile):
        client = fom.client
        if client == "unknown" and declared.get("client") in {"Surge", "Loon", "Shadowrocket"}:
            client = fom.client = declared["client"]
        actual = {"client": client, "format": fom.file_role}
    else:
        raise ValueError(f"Routing destination {type(fom).__name__} has no verified collection import")
    validate_destination(actual)
    for key in ("client", "format"):
        if key in declared and declared[key] != actual[key]:
            raise ValueError(f"Routing destination {key} disagrees with existing FOM: {declared[key]!r} versus {actual[key]!r}")
    return dict(actual, **declared)


def task_target_factory(actions, workspace):
    declarations = [action.definition.get("destination", UNSET) for action in actions
                    if action.type == "merge_rules"]
    explicit = [value for value in declarations if value is not UNSET
                and "client" in value and "format" in value]
    purposes = {(canonical_client(value["client"]), value["format"]) for value in explicit}
    if len(purposes) > 1:
        raise ValueError("Task routing destinations declare conflicting client/file purposes")
    return target_factory(explicit[0], workspace) if explicit else None


def target_factory(destination, workspace):
    validate_destination(destination)
    client = canonical_client(destination["client"])

    def create(path):
        from rule_framework.fom import StandardListFile, QuanXListFile, ClashYamlFile, ClashTextPayloadFile
        from rule_framework.client_paths import client_for_path
        namespace = client_for_path(path, base_dir=workspace.base_dir)
        if namespace not in ("unknown", client):
            raise ValueError(f'{destination["client"]} destination conflicts with managed client {namespace}: {path}')
        if client == "AdGuard":
            from rule_framework.fom import AdGuardFile
            return AdGuardFile(path)
        if client == "Surge" and destination["format"] in {"configuration", "module"}:
            from rule_framework.surge import SurgeFile
            return SurgeFile(path)
        if client == "mihomo" and destination["format"] == "configuration":
            return _mihomo_profile(path)
        if client == "mihomo":
            behavior, format_name = destination["format"].rsplit("-", 1)
            target = ClashYamlFile(path) if format_name == "yaml" else ClashTextPayloadFile(path)
            target.behavior = behavior
            return target
        target = QuanXListFile(path) if client == "Quantumult X" else StandardListFile(path)
        target.client = "QuantumultX" if client == "Quantumult X" else client
        target.file_role = destination["format"]
        return target

    return create


def _mihomo_profile(path):
    from rule_framework.fom import ClashYamlFile
    from ruamel.yaml.comments import CommentedSeq

    class RoutingProfileYaml(ClashYamlFile):
        def scaffold(self, base_name):
            super().scaffold(base_name)
            self.data.pop("payload", None)
            self.data["rules"] = CommentedSeq()
            self.nodes = []
            self.file_role, self._sequence_key, self.behavior = "full-profile", "rules", "classical"
            self.add_native_rule("MATCH,DIRECT")

    return RoutingProfileYaml(path)


def _check_terminal_order(rules, client):
    positions = [index for index, rule in enumerate(rules) if rule.type == "FINAL"]
    if positions and positions != [len(rules) - 1]:
        raise ValueError(f"{client} terminal routing rule must occur once at the final collection boundary")


def _merge_terminal(fom, rule, client):
    if rule.conditions:
        raise ValueError(f"{client} terminal routing rule cannot express matching options")
    if client == "Quantumult X":
        fom.add_rule("FINAL", None, policy=rule.policy, conditions={}, options=list(rule.result_options))
        return
    if client == "Surge":
        terminal = "FINAL"
        nodes = [node for section in fom.section_order if section.split("\0")[0] == "Rule"
                 for node in fom.sections[section]]
    else:
        terminal, nodes = "MATCH", fom.nodes
    matches = [node for node in nodes if isinstance(node, RuleNode) and node.type.upper() == terminal]
    if not matches:
        fom.add_native_rule(f"{terminal},{rule.policy}")
        return
    changed = 0
    for node in matches:
        if getattr(node, "options", ()):
            raise ValueError(f"{client} terminal destination has unrepresented matching/result options")
        if node.policy != rule.policy:
            node.policy = rule.policy
            changed += 1
    if changed:
        fom.is_dirty = True
        fom.update_metadata()
    logger.info("Terminal routing update matched=%s modified=%s in %s", len(matches), changed, fom.filepath)


def _validate_source_context(fom):
    from rule_framework.surge import SurgeFile
    from rule_framework.fom import ClashYamlFile
    from rule_framework.ast import SectionNode
    if isinstance(fom, SurgeFile):
        descriptive = ("#!name=", "#!desc=", "#!author=", "#!homepage=", "#!total=")
        for node in fom.header_nodes:
            rendered = node.render().lstrip()
            if rendered.startswith("#!") and not rendered.lower().startswith(descriptive):
                raise ValueError(f"Surge source directive has unrepresented execution context: {rendered!r}")
            if rendered.strip() and not rendered.startswith(("#", ";", "//")):
                raise ValueError(f"Surge source header context is unrecognized: {rendered!r}")
        for section, nodes in fom.sections.items():
            if section.split("\0")[0] == "Rule":
                continue
            for node in nodes:
                if isinstance(node, (BlankNode, SectionNode)):
                    continue
                if node.render().lstrip().startswith(("#", ";", "//")):
                    continue
                raise ValueError(f"Surge source context [{section}] is outside the routing collection model: "
                                 f"{node.render()!r}; matching/result impact is unverified")
    elif isinstance(fom, ClashYamlFile):
        allowed = {"rules", "mode"} if fom.file_role == "full-profile" else {"payload", "behavior", "format"}
        outside = set(fom.data) - allowed
        if outside:
            raise ValueError(f"mihomo source context fields are outside the routing collection model: {sorted(outside)}")
        if "mode" in fom.data and fom.data["mode"] != "rule":
            raise ValueError(f"mihomo source context mode={fom.data['mode']!r} bypasses or changes routing rule execution")
        for line in fom._raw_bytes.decode(fom._encoding).splitlines():
            if line.lstrip().startswith("#!"):
                raise ValueError(f"mihomo source directive has unrepresented execution context: {line!r}")


def _validate_destination_result(fom, rule, client, format_name):
    if client != "Surge" or format_name != "configuration":
        return
    if rule.policy in {"DIRECT", "REJECT", "REJECT-TINYGIF"}:
        return
    declared = set()
    for section, nodes in fom.sections.items():
        if section.split("\0")[0] in {"Proxy", "Proxy Group"}:
            for node in nodes:
                rendered = node.render().strip()
                if rendered and not rendered.startswith(("#", ";", "//", "[")) and "=" in rendered:
                    declared.add(rendered.split("=", 1)[0].strip())
    if rule.policy not in declared:
        raise ValueError(f"Surge policy result {rule.policy!r} is not a declared destination outbound")


def export_rules(fom, *, policy=UNSET):
    _validate_source_context(fom)
    from rule_framework.fom import QuanXListFile, StandardListFile, ClashYamlFile, ClashTextPayloadFile, AdGuardFile
    from rule_framework.adguard_filters import BasicDomainFilterNode, validate_filter_value
    if isinstance(fom, AdGuardFile):
        fom.validate()
        if policy is not UNSET:
            raise ValueError("AdGuard basic collection cannot represent a routing policy context")
        rules = []
        for number, node in enumerate(fom.nodes, 1):
            location = f"{fom.filepath}:{number}"
            if isinstance(node, (CommentNode, BlankNode)):
                if node.render().startswith(("!+", "#!")):
                    raise ValueError(f"AdGuard collection cannot represent executable list directives at {location}")
                continue
            if not isinstance(node, BasicDomainFilterNode):
                raise ValueError(f"AdGuard collection cannot recognize matching/result fields at {location}: {node.render()!r}")
            validate_filter_value(node.value)
            if node.options or node.prepended_instruction:
                raise ValueError(f"AdGuard basic collection cannot represent added modifier/instruction fields at {location}")
            rules.append(RoutingRule("ADGUARD-DOMAIN", node.value, client="AdGuard", location=location, source_format="basic-domain-filter-list"))
        return RuleCollection(tuple(rules))
    from rule_framework.surge import SurgeFile, SurgeRuleNode, SurgeUnknownNode
    from rule_framework.ast import SectionNode
    from rule_framework.rule_helpers import validate_standard_value, validate_options
    if isinstance(fom, SurgeFile):
        fom.validate()
        if policy is not UNSET:
            _policy(policy)
        rules = []
        for section in fom.section_order:
            if section.split("\0")[0] != "Rule":
                continue
            for number, node in enumerate(fom.sections[section], 1):
                location = f"{fom.filepath}:[Rule]:{number}"
                if isinstance(node, (BlankNode, SectionNode)):
                    continue
                if isinstance(node, CommentNode) and not isinstance(node, SurgeUnknownNode):
                    if node.render().lstrip().startswith("#!"):
                        raise ValueError(f"Surge source contains an unrepresented Rule directive at {location}")
                    continue
                if not isinstance(node, SurgeRuleNode):
                    raise ValueError(f"Surge cannot recognize required routing source at {location}")
                try:
                    _policy(node.policy)
                    kind = node.type.upper()
                    if kind == "FINAL":
                        if fom.is_module:
                            raise ValueError("Surge module terminal routing context has no audited collection mapping")
                        if node.options:
                            raise ValueError("FINAL options have no verified matching meaning")
                        value = None
                    else:
                        validate_standard_value(kind, node.value, client="Surge")
                        validate_options(node.options, kind, "Surge")
                        value = node.value
                    if fom.is_module and node.policy not in {"DIRECT", "REJECT", "REJECT-TINYGIF"}:
                        raise ValueError("Surge module routing result must use a supported internal policy")
                    if policy is not UNSET and node.policy != policy:
                        raise ValueError(f"inline policy {node.policy!r} conflicts with source policy {policy!r}")
                except ValueError as error:
                    raise ValueError(f"Surge source {location}: {error}") from error
                rules.append(RoutingRule(kind, value, tuple(node.options), policy=node.policy,
                                         client="Surge", location=location,
                                         source_format="module" if fom.is_module else "configuration"))
        _check_terminal_order(rules, "Surge")
        return RuleCollection(tuple(rules))
    from rule_framework.mihomo_formats import MihomoRuleNode, validate_mihomo_node
    if isinstance(fom, (ClashYamlFile, ClashTextPayloadFile)):
        fom.validate()
        if fom.behavior is None:
            raise ValueError(f"mihomo source provider behavior is unknown: {fom.filepath}")
        if policy is not UNSET:
            _policy(policy)
        rules = []
        for number, node in enumerate(fom.nodes, 1):
            location = f"{fom.filepath}:{number}"
            if isinstance(node, (CommentNode, BlankNode)):
                rendered = node.render().lstrip()
                if getattr(node, "recognition_error", None) or rendered.startswith("#!"):
                    raise ValueError(f"mihomo source contains unrepresented syntax/directives at {location}")
                if rendered.strip() and not rendered.startswith(("#", "//", ";")):
                    raise ValueError(f"mihomo source contains unrecognized routing content at {location}")
                continue
            try:
                validate_mihomo_node(node, fom.behavior)
                if node.profile:
                    fom._validate_policy_target(node)
                result = node.policy if node.profile else policy
                if node.profile and policy is not UNSET and result != policy:
                    raise ValueError(f"inline policy {result!r} conflicts with declared source policy {policy!r}")
            except ValueError as error:
                raise ValueError(f"mihomo source {location}: {error}") from error
            kind = "FINAL" if node.type.upper() == "MATCH" else node.type.upper()
            if kind in {"IP-CIDR", "IP-CIDR6"}:
                import ipaddress
                kind = "IP-CIDR6" if ipaddress.ip_network(node.value, strict=False).version == 6 else "IP-CIDR"
            value = None if kind == "FINAL" else node.value
            rules.append(RoutingRule(kind, value, tuple(node.options), policy=result,
                                     client="mihomo", location=location,
                                     source_format="configuration" if node.profile else f"{fom.behavior}-{fom.format}"))
        _check_terminal_order(rules, "mihomo")
        return RuleCollection(tuple(rules))
    from rule_framework.standard_lists import StandardRuleNode, DomainSetNode
    from rule_framework.rule_helpers import validate_standard_value, validate_options
    if isinstance(fom, StandardListFile):
        if fom.client not in {"Surge", "Loon", "Shadowrocket"}:
            raise ValueError(f"Routing source client is unknown: {fom.filepath}")
        if policy is not UNSET:
            _policy(policy)
        rules = []
        for number, node in enumerate(fom.nodes, 1):
            location = f"{fom.filepath}:{number}"
            if isinstance(node, (CommentNode, BlankNode)):
                if node.render().lstrip().startswith("#!"):
                    raise ValueError(f"{fom.client} source contains an unrepresented executable directive at {location}")
                if node.render().strip() and not node.render().lstrip().startswith(("#", "//", ";")):
                    raise ValueError(f"{fom.client} unrecognized routing source at {location}")
                continue
            if not isinstance(node, (StandardRuleNode, DomainSetNode)):
                raise ValueError(f"{fom.client} cannot recognize required routing source at {location}")
            try:
                validate_standard_value(node.type.upper(), node.value, client=fom.client)
                matching = fom._validate_options(getattr(node, "options", ()), node.type.upper(), fom.client)
                if node.policy not in (None, ""):
                    raise ValueError("external source cannot represent an inline policy")
            except ValueError as error:
                raise ValueError(f"{fom.client} source {location}: {error}") from error
            kind = node.type.upper()
            if fom.client == "Shadowrocket" and kind == "IP-CIDR":
                import ipaddress
                if ipaddress.ip_network(node.value, strict=False).version == 6:
                    kind = "IP-CIDR6"
            rules.append(RoutingRule(kind, node.value, tuple(matching), policy=policy,
                                     client=fom.client, location=location, source_format=fom.file_role))
        return RuleCollection(tuple(rules))
    from rule_framework.quantumult_lists import (
        QuantumultRuleNode, validate_quantumult_value,
        validate_quantumult_policy, validate_quantumult_options,
    )
    if not isinstance(fom, QuanXListFile):
        raise ValueError(f"Routing source {type(fom).__name__} has no verified collection export")
    fom.validate()
    if policy is not UNSET:
        _policy(policy)
    rules = []
    for number, node in enumerate(fom.nodes, 1):
        location = f"{fom.filepath}:{number}"
        if isinstance(node, (CommentNode, BlankNode)):
            rendered = node.render().lstrip()
            if rendered.startswith("#!"):
                raise ValueError(f"Quantumult X source contains an unrepresented executable directive at {location}")
            if rendered.strip() and not rendered.startswith(("#", "//", ";")):
                raise ValueError(f"Quantumult X source contains unrecognized routing content at {location}")
            continue
        if not isinstance(node, QuantumultRuleNode):
            raise ValueError(f"QuantumultX cannot recognize required routing source at {location}")
        try:
            validate_quantumult_value(node.type.upper(), node.value)
            validate_quantumult_policy(node.policy)
            result_options = validate_quantumult_options(node.options)
            if policy is not UNSET and node.policy != policy:
                raise ValueError(f"source policy {node.policy!r} conflicts with declared policy {policy!r}")
        except ValueError as error:
            raise ValueError(f"QuantumultX source {location}: {error}") from error
        kind = node.type.upper().replace("HOST", "DOMAIN", 1)
        kind = "IP-CIDR6" if kind == "IP6-CIDR" else kind
        rules.append(RoutingRule(kind, node.value, policy=node.policy,
                                 result_options=result_options, client="QuantumultX", location=location))
    _check_terminal_order(rules, "Quantumult X")
    return RuleCollection(tuple(rules))


def merge_rules(fom, collections, *, destination=UNSET):
    from dataclasses import replace
    destination = destination_for(fom, destination)
    client = destination["client"]
    inline_result = client == "Quantumult X" or destination["format"] in {"configuration", "module"}
    if isinstance(collections, RuleCollection):
        collections = [collections]
    if not isinstance(collections, (list, tuple)) or any(not isinstance(item, RuleCollection) for item in collections):
        raise ValueError("merge_rules requires public RuleCollection values")
    unique = {}
    for collection in collections:
        for original in collection.rules:
            _validate_record(original)
            source_client = canonical_client(original.client)
            if source_client != client and 'Shadowrocket' in (source_client, client) and original.type in {
                'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'}:
                raise ValueError(f'{client} cannot convert {original.type} from {source_client}: '
                                 'Shadowrocket default extended-matching SNI/HTTP Host range and cross-client '
                                 'default/disable mapping require verified direction evidence')
            if source_client != client and original.type not in COMMON_ROUTING_TYPES | {"ADGUARD-DOMAIN"}:
                raise ValueError(f"{client} cannot convert {original.type} from {source_client}: "
                                 "wildcard/regex, process/platform or database matching has no audited cross-client mapping")
            if (source_client != client and original.policy is not UNSET
                    and original.policy.upper() in CLIENT_CONTROL_RESULTS):
                raise ValueError(f"{client} cannot express {source_client} client-specific control result "
                                 f"{original.policy!r}; its outcome has no audited cross-client mapping")
            if client == "AdGuard" and original.type != "ADGUARD-DOMAIN":
                detail = ("exact-host matching would expand to domain-and-subdomains; "
                          if original.type == "DOMAIN" else "")
                raise ValueError(f"AdGuard cannot convert {original.type} from {original.client}: {detail}"
                                 "routing policy/results and processing context have no basic-filter equivalent")
            if original.type == "ADGUARD-DOMAIN" and client != "AdGuard":
                raise ValueError(f"{client} cannot convert AdGuard basic filter: DNS/HTTP filtering context and "
                                 "implicit domain/subdomain block response cannot be expressed by a routing policy")
            if (original.type == "DOMAIN-WILDCARD" and source_client == client
                    and original.source_format != destination["format"]):
                raise ValueError(f"{client} wildcard grammar across {original.source_format}/"
                                 f"{destination['format']} has no audited role mapping")
            if client == "mihomo" and original.type in {"IP-CIDR", "IP-CIDR6"} and "/" not in original.value:
                import ipaddress
                original = replace(original, value=str(ipaddress.ip_network(original.value, strict=False)))
            policy = original.policy
            context = destination.get("policy", UNSET)
            if policy is UNSET:
                policy = context
            elif context is not UNSET and policy != context:
                raise ValueError(f"{client} source policy {policy!r} conflicts with destination import policy {context!r}: {original.location}")
            rule = replace(original, policy=policy)
            if client == "AdGuard" and policy is not UNSET:
                raise ValueError("AdGuard basic filter cannot represent an explicit routing policy")
            if rule.type == "FINAL" and (not inline_result or destination["format"] == "module"):
                raise ValueError(f"{client} external {destination['format']} cannot represent terminal catch-all routing results")
            if client == "Quantumult X":
                if rule.conditions:
                    raise ValueError(f"Quantumult X cannot express matching options {rule.conditions!r}: {rule.location}")
                if rule.result_options and canonical_client(rule.client) != client:
                    raise ValueError(f"Quantumult X cannot express foreign routing results: {rule.location}")
                if policy is UNSET:
                    raise ValueError("Quantumult X requires an explicit routing policy or external-source policy context")
            else:
                if rule.result_options:
                    raise ValueError(f"{client} cannot express Quantumult X interface result options {rule.result_options!r}: {rule.location}")
                if inline_result and policy is UNSET:
                    raise ValueError(f"{client} configuration requires an explicit routing policy or source import context")
                if not inline_result and policy is not UNSET and context != policy:
                    raise ValueError(f"{client} external rule-set cannot express policy {policy!r}; declare its equal import policy context")
            _validate_destination_result(fom, rule, client, destination["format"])
            old = unique.get(rule.identity)
            if old is not None and (old.policy, old.result_options) != (rule.policy, rule.result_options):
                raise ValueError(f"{client} routing identity has conflicting policy/results: {rule.location}")
            unique.setdefault(rule.identity, rule)
    _check_terminal_order(list(unique.values()), client)
    for rule in unique.values():
        try:
            if rule.type == "FINAL":
                _merge_terminal(fom, rule, client)
                continue
            if client == "AdGuard":
                fom.add_rule("domain", rule.value, conditions={}, options=[])
            elif client == "Quantumult X":
                fom.add_rule(rule.type, rule.value, policy=rule.policy,
                             conditions={}, options=list(rule.result_options))
            elif client == "mihomo":
                fom.add_rule(rule.type, rule.value, policy=rule.policy if inline_result else UNSET, conditions={
                    "no_resolve": "no-resolve" in rule.conditions, "src": "src" in rule.conditions,
                }, options=list(rule.conditions))
            else:
                native_type = "IP-CIDR" if client == "Shadowrocket" and rule.type == "IP-CIDR6" else rule.type
                fields = {"no_resolve": "no-resolve" in rule.conditions}
                if client == 'Shadowrocket':
                    if 'extended-matching' in rule.conditions:
                        fields['extended_matching'] = True
                    if 'pre-matching' in rule.conditions:
                        fields['pre_matching'] = True
                else:
                    fields['extended_matching'] = 'extended-matching' in rule.conditions
                fom.add_rule(native_type, rule.value, policy=rule.policy if inline_result else UNSET,
                             conditions=fields, options=list(rule.conditions))
        except ValueError as error:
            raise ValueError(f"{client} cannot convert {rule.type} from {rule.client} at {rule.location}: {error}") from error
    logger.info("Routing merge: client=%s source_rules=%s unique_rules=%s result_context=%r runtime-validation=not-run",
                client, sum(len(item.rules) for item in collections), len(unique), destination.get("policy", UNSET))

def execute_merge(ctx, definition):
    from rule_framework.workspace import MissingSourceInputError
    validate_merge_declaration(definition)
    if ctx.workspace is None:
        raise ValueError("merge_rules requires a managed workspace")
    collections = []
    for source in definition["sources"]:
        path = source if isinstance(source, str) else source["file"]
        if ctx.workspace.is_missing_source_input(path):
            raise MissingSourceInputError(ctx.workspace.resolve_path(path))
        if not ctx.workspace.exists(path):
            raise ValueError(f"Routing source does not exist: {path}")
        source_fom = ctx.workspace.get_fom(path)
        collections.append(source_fom.export_rules(
            policy=source.get("policy", UNSET) if isinstance(source, dict) else UNSET))
    ctx.fom.merge_rules(collections, destination=definition.get("destination", UNSET))

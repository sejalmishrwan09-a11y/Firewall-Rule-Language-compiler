import ipaddress
from ast_nodes import (
    ASTVisitor, PolicyAST, RuleNode,
    AnyNode, IPNode, CIDRNode, PortNode,
)


class SemanticError(Exception):
    pass

class SemanticAnalyzer(ASTVisitor):
    def __init__(self, rules):
        if isinstance(rules, PolicyAST):
            self.rules = rules.rules
        else:
            self.rules = rules
        self.warnings = []

    def analyze(self):
        for rule in self.rules:
            self.visit(rule)
        self._check_conflicts()
        self._check_shadows()

    def visit_RuleNode(self, node: RuleNode):
        """Protocol/port consistency check."""
        proto = node.protocol_str
        port  = node.port

        if proto in ("TCP", "UDP") and port is None:
            raise SemanticError(
                f"[SemanticError] Line {node.line}: "
                f"{proto} rule requires a PORT clause."
            )
        if proto == "ICMP" and port is not None:
            raise SemanticError(
                f"[SemanticError] Line {node.line}: "
                f"ICMP rule must not have a PORT clause."
            )

        self.visit(node.source)
        self.visit(node.destination)
        if node.port:
            self.visit(node.port)

    def visit_IPNode(self, node: IPNode):
        try:
            ipaddress.ip_address(node.value)
        except ValueError:
            raise SemanticError(
                f"[SemanticError] Line {node.line}, Col {node.col}: "
                f"Invalid IP address '{node.value}'."
            )

    def visit_CIDRNode(self, node: CIDRNode):
        """Validate IP + prefix length."""
        try:
            ipaddress.ip_network(node.value, strict=False)
        except ValueError:
            raise SemanticError(
                f"[SemanticError] Line {node.line}, Col {node.col}: "
                f"Invalid CIDR block '{node.value}'."
            )
        if not (0 <= node.prefix_len <= 32):
            raise SemanticError(
                f"[SemanticError] Line {node.line}: "
                f"CIDR prefix /{node.prefix_len} out of range (0-32)."
            )

    def visit_PortNode(self, node: PortNode):
        """Validate port number is in the valid range."""
        if not (1 <= node.number <= 65535):
            raise SemanticError(
                f"[SemanticError] Line {node.line}: "
                f"Port {node.number} out of range (1-65535)."
            )

    def visit_AnyNode(self, node: AnyNode):
        pass   # ANY is always valid

    def _check_conflicts(self):
        """
        Detect ALLOW/DENY pairs that match identical traffic.
        These are hard errors — one rule will never fire.
        """
        for i, a in enumerate(self.rules):
            for b in self.rules[i+1:]:
                if (a.protocol_str     == b.protocol_str and
                        a.source_str   == b.source_str and
                        a.destination_str == b.destination_str and
                        a.port_number  == b.port_number):
                    actions = {a.action_str, b.action_str}
                    if actions == {"ALLOW", "DENY"}:
                        raise SemanticError(
                            f"[SemanticError] Line {b.line}: "
                            f"Conflict — rule at line {a.line} ({a.action_str}) "
                            f"and rule at line {b.line} ({b.action_str}) "
                            f"match identical traffic "
                            f"({a.protocol_str} FROM {a.source_str} "
                            f"TO {a.destination_str}"
                            f"{' PORT ' + str(a.port_number) if a.port_number else ''})."
                        )

    def _check_shadows(self):
        for i, a in enumerate(self.rules):
            for b in self.rules[i+1:]:
                if a.protocol_str != b.protocol_str:
                    continue
                if (isinstance(a.source, AnyNode) and
                        isinstance(a.destination, AnyNode)):
                    self.warnings.append(
                        f"[Warning] Line {b.line}: Rule "
                        f"({b.action_str} {b.protocol_str} FROM "
                        f"{b.source_str} TO {b.destination_str}) "
                        f"is shadowed by the broader rule at line {a.line} "
                        f"and will never be evaluated."
                    )

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
class ASTNode:
    pass

@dataclass
class ActionNode(ASTNode):
    value: str
    line:  int
    col:   int

@dataclass
class ProtocolNode(ASTNode):
    value: str
    line:  int
    col:   int

@dataclass
class AnyNode(ASTNode):
    line: int
    col:  int

@dataclass
class IPNode(ASTNode):
    value: str
    line:  int
    col:   int

@dataclass
class CIDRNode(ASTNode):
    value:      str
    network:    str
    prefix_len: int
    line:       int
    col:        int

@dataclass
class PortNode(ASTNode):
    number: int
    line:   int
    col:    int

AddressNode = AnyNode | IPNode | CIDRNode

class RuleNode(ASTNode):
    """
    A single firewall rule.  Uses __init__ instead of dataclass
    to avoid field-ordering issues with properties.

    Every field is a typed ASTNode — giving the tree real depth.
    The semantic analyser and both codegen backends walk child nodes.
    """
    def __init__(self, action: ActionNode, protocol: ProtocolNode,
                 source, destination, port: Optional[PortNode],
                 line: int, col: int):
        self.action      = action
        self.protocol    = protocol
        self.source      = source
        self.destination = destination
        self.port        = port
        self.line        = line
        self.col         = col
        self.hit_count   = 0

    @property
    def action_str(self):      return self.action.value
    @property
    def protocol_str(self):    return self.protocol.value
    @property
    def source_str(self):
        return "ANY" if isinstance(self.source, AnyNode) else self.source.value
    @property
    def destination_str(self):
        return "ANY" if isinstance(self.destination, AnyNode) else self.destination.value
    @property
    def port_number(self):
        return self.port.number if self.port else None

    def __repr__(self):
        return (f"Rule(Action={self.action_str}, Protocol={self.protocol_str}, "
                f"Source={self.source_str}, Destination={self.destination_str}, "
                f"Port={self.port_number})")

@dataclass
class PolicyAST(ASTNode):
    """Root of the AST — one per compiled ruleset."""
    rules:  List[RuleNode] = field(default_factory=list)
    source: str = ""

class ASTVisitor:
    def visit(self, node: ASTNode):
        method = f"visit_{type(node).__name__}"
        return getattr(self, method, self.generic_visit)(node)

    def generic_visit(self, node: ASTNode):
        for val in vars(node).values():
            if isinstance(val, ASTNode):
                self.visit(val)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, ASTNode):
                        self.visit(item)

class ASTPrinter(ASTVisitor):
    def __init__(self):
        self._lines = []; self._depth = 0

    def _w(self, t): self._lines.append("  " * self._depth + t)
    def result(self): return "\n".join(self._lines)

    def visit_PolicyAST(self, node):
        self._w(f"PolicyAST  ({len(node.rules)} rules)")
        self._depth += 1
        for r in node.rules: self.visit(r)
        self._depth -= 1

    def visit_RuleNode(self, node):
        self._w(f"RuleNode  line={node.line}")
        self._depth += 1
        self.visit(node.action); self.visit(node.protocol)
        self._w("source:"); self._depth+=1; self.visit(node.source); self._depth-=1
        self._w("destination:"); self._depth+=1; self.visit(node.destination); self._depth-=1
        if node.port: self.visit(node.port)
        self._depth -= 1

    def visit_ActionNode(self, n):   self._w(f"ActionNode    {n.value!r}  L{n.line}:C{n.col}")
    def visit_ProtocolNode(self, n): self._w(f"ProtocolNode  {n.value!r}  L{n.line}:C{n.col}")
    def visit_AnyNode(self, n):      self._w(f"AnyNode  L{n.line}:C{n.col}")
    def visit_IPNode(self, n):       self._w(f"IPNode        {n.value!r}  L{n.line}:C{n.col}")
    def visit_CIDRNode(self, n):     self._w(f"CIDRNode      {n.value!r}  /{n.prefix_len}  L{n.line}:C{n.col}")
    def visit_PortNode(self, n):     self._w(f"PortNode      {n.number}  L{n.line}:C{n.col}")

Rule = RuleNode

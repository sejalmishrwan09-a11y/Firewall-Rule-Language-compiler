from lexer import Lexer
from parser import Parser
from semantic_analyzer import SemanticAnalyzer
from firewall_engine import FirewallEngine, Packet
from ast_nodes import PolicyAST

class FirewallService:

    def __init__(self):
        self.engine = None
        self.last_ast: PolicyAST = None

    def compile_rules(self, rule_text):
        lexer   = Lexer(rule_text)
        tokens  = lexer.tokenize()

        parser  = Parser(tokens)
        ast     = parser.parse()
        self.last_ast = ast

        rules   = ast.rules

        analyzer = SemanticAnalyzer(rules)
        analyzer.analyze()

        self.engine = FirewallEngine(rules)
        return rules

    def get_ast_repr(self):
        """Return pretty-printed AST string for the web UI."""
        if self.last_ast is None:
            return "No AST — compile rules first."
        from ast_nodes import ASTPrinter
        p = ASTPrinter()
        p.visit(self.last_ast)
        return p.result()

    def simulate_packet(self, protocol, source, destination, port=None):
        if self.engine is None:
            raise Exception("No firewall rules compiled")
        packet = Packet(protocol, source, destination, port)
        return self.engine.evaluate(packet)

    def get_rules(self):
        return self.engine.rules if self.engine else []

    def get_logs(self):
        return self.engine.logs if self.engine else []

    def get_stats(self):
        if self.engine is None:
            return {}
        return {str(rule): rule.hit_count for rule in self.engine.rules}

firewall_service = FirewallService()

from datetime import datetime
import ipaddress
from ast_nodes import AnyNode, IPNode, CIDRNode, RuleNode

class Packet:
    def __init__(self, protocol, source, destination, port=None):
        self.protocol    = protocol
        self.source      = source
        self.destination = destination
        self.port        = port

    def __repr__(self):
        return (f"Packet(Protocol={self.protocol}, Source={self.source}, "
                f"Destination={self.destination}, Port={self.port})")

class FirewallEngine:
    def __init__(self, rules):
        self.rules = rules
        self.logs  = []
        for rule in self.rules:
            rule.hit_count = 0

    def evaluate(self, packet):
        for rule in self.rules:
            if self.match(rule, packet):
                rule.hit_count += 1
                decision = rule.action_str
                self.log(packet, decision, rule)
                return decision, rule
        decision = "DENY"
        self.log(packet, decision, None)
        return decision, None

    def match(self, rule: RuleNode, packet: Packet) -> bool:
        if rule.protocol_str != packet.protocol:
            return False

        # Source address
        if not self._match_address(rule.source, packet.source):
            return False

        # Destination address
        if not self._match_address(rule.destination, packet.destination):
            return False

        # Port
        if rule.port_number is not None:
            if packet.port != rule.port_number:
                return False

        return True

    def _match_address(self, rule_addr, packet_ip: str) -> bool:
        """Match an AST address node against a packet IP string."""
        if isinstance(rule_addr, AnyNode):
            return True
        if isinstance(rule_addr, IPNode):
            return rule_addr.value == packet_ip
        if isinstance(rule_addr, CIDRNode):
            try:
                network = ipaddress.ip_network(rule_addr.value, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            except ValueError:
                return False
        return False

    def log(self, packet, decision, rule):
        self.logs.append({
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "time":         datetime.now().strftime("%H:%M:%S"),
            "packet":       packet,
            "decision":     decision,
            "matched_rule": rule,
        })

    def show_logs(self):
        for log in self.logs:
            print(log["timestamp"], "| Packet:", log["packet"],
                  "| Decision:", log["decision"],
                  "| Rule:", log["matched_rule"])

    def show_rule_statistics(self):
        print("\nRule Usage Statistics:")
        for rule in self.rules:
            print(f"  {rule}  →  Hits: {rule.hit_count}")

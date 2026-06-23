from ast_nodes import RuleNode, AnyNode, IPNode, CIDRNode

def convert_to_iptables(rule: RuleNode) -> str:
    target  = "ACCEPT" if rule.action_str == "ALLOW" else "DROP"
    proto   = rule.protocol_str.lower()
    cmd     = f"iptables -A INPUT -p {proto}"
    if rule.source_str != "ANY":
        cmd += f" -s {rule.source_str}"
    if rule.destination_str != "ANY":
        cmd += f" -d {rule.destination_str}"
    if rule.port_number is not None:
        cmd += f" --dport {rule.port_number}"
    cmd += f" -j {target}"
    return cmd

def convert_all_rules(rules) -> list:
    return [convert_to_iptables(r) for r in rules]

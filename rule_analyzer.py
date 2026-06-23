from ast_nodes import AnyNode


def detect_shadow_rules(rules):
    """
    Detect rules that can never be reached because a broader rule
    above them catches all matching traffic first.
    Returns a list of warning strings.
    """
    warnings = []
    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):
            r1, r2 = rules[i], rules[j]
            if r1.protocol_str != r2.protocol_str:
                continue
            if (isinstance(r1.source, AnyNode) and
                    isinstance(r1.destination, AnyNode)):
                warnings.append(
                    f"Warning: Rule {j+1} ({r2.action_str} {r2.protocol_str} "
                    f"FROM {r2.source_str} TO {r2.destination_str}) "
                    f"is shadowed by Rule {i+1} "
                    f"({r1.action_str} {r1.protocol_str} FROM ANY TO ANY) "
                    f"and will never be evaluated."
                )
    return warnings


def detect_conflicts(rules):
    """
    Detect ALLOW+DENY pairs that match identical traffic.
    Returns a list of conflict description strings.
    """
    conflicts = []
    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):
            r1, r2 = rules[i], rules[j]
            if r1.protocol_str     != r2.protocol_str:     continue
            if r1.source_str       != r2.source_str:       continue
            if r1.destination_str  != r2.destination_str:  continue
            if r1.port_number      != r2.port_number:      continue
            actions = {r1.action_str, r2.action_str}
            if actions == {"ALLOW", "DENY"}:
                port_str = f" PORT {r1.port_number}" if r1.port_number else ""
                conflicts.append(
                    f"Conflict: Rule {i+1} ({r1.action_str}) and "
                    f"Rule {j+1} ({r2.action_str}) match identical traffic "
                    f"({r1.protocol_str} FROM {r1.source_str} "
                    f"TO {r1.destination_str}{port_str})."
                )
    return conflicts

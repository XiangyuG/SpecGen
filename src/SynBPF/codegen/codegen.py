import ipaddress
import re

ACTIONS = {"ACCEPT", "DROP", "RETURN", "DNAT", "SNAT", "NODECISION"}

def parse_cidr(cidr):
    if "/" not in cidr:
        ip = int(ipaddress.IPv4Address(cidr))
        return ip, 0xFFFFFFFF

    net = ipaddress.IPv4Network(cidr, strict=False)
    return int(net.network_address), int(net.netmask)


def parse_ctstate(extras: str):
    if extras is None:
        return None
    m = re.search(r'ctstate\s+([A-Z,]+)', extras)    
    if not m:
        return None
    return m.group(1).split(",")


def proto_condition(prot):
    if prot in ("*"):
        return "#t"
    if prot.lower() == "tcp":
        return "(bveq proto (bv 6 8))"
    if prot.lower() == "udp":
        return "(bveq proto (bv 17 8))"
    return "#t"


def ip_condition(var, cidr):
    net, mask = parse_cidr(cidr)
    return f"(bveq (bvand {var} (bv {mask} 32)) (bv {net} 32))"


def ctstate_condition(states):
    conds = [f"(bveq ctstate {s})" for s in states]
    if len(conds) == 1:
        return conds[0]
    return f"(or {' '.join(conds)})"


def gen_rule_condition(rule):
    '''
    Input: an iptable rule
    Output: Rosette condition code for the rule
    '''

    conditions = []

    conditions.append(proto_condition(rule.prot))

    if rule.src != "0.0.0.0/0":
        conditions.append(ip_condition("srcIP", rule.src))
    else:
        conditions.append("#t")

    if rule.dst != "0.0.0.0/0":
        conditions.append(ip_condition("dstIP", rule.dst))
    else:
        conditions.append("#t")

    ct = parse_ctstate(rule.extras)
    if ct:
        conditions.append(ctstate_condition(ct))
    else:
        conditions.append("#t")

    return f"(and {' '.join(conditions)})"

    
'''
Input: a chain of iptable chains
Output: Rosette specification code for the chain
'''
def gen_chain_spec(chains):
    lines = []
    for chain in chains:
        fn = chain.name.lower().replace("-", "_")   # e.g., "INPUT" → chain name
        lines.append(f"(define ({fn} srcPort srcIP dstPort dstIP protocol cstate)")

        indent = "  "

        # build nested ifs
        for rule in chain.rules:
            cond = gen_rule_condition(rule)
            lines.append(indent + f"(if {cond}")

            tgt  = rule.target
            if tgt in ACTIONS:
                tgt = {
                    "ACCEPT": "(bv 0 4)",
                    "DROP":   "(bv 1 4)",
                    "DNAT":   "(bv 2 4)",
                    "SNAT":   "(bv 3 4)",
                    "RETURN": "(bv 4 4)",
                }[tgt]
                lines.append(indent + f"    {tgt}")
            else:
                tgt = tgt.lower().replace("-", "_")
                subcall = f"({tgt.lower()} srcPort srcIP dstPort dstIP protocol cstate)"
    
                lines.append(indent + f"(if {cond}")
                lines.append(indent + f"    (let ([decision {subcall}])")
                lines.append(indent + f"      (if (not (bveq decision (bv 5 4)))")
                lines.append(indent + f"          decision")
                lines.append(indent + f"          (bv 5 4)))")
                # indent deeper
                indent += "  "
            indent += "  "  # deeper nesting
            print(lines)
            exit(0)

        # default policy fallback
        if chain.policy == "ACCEPT":
            default = "(bv 0 4)"  # ACCEPT
        elif chain.policy == "DROP":
            default = "(bv 1 4)"  # DROP
        elif chain.policy == "DNAT":
            default = "(bv 2 4)"  # DNAT
        else:
            default = "(bv 1 4)"  # no policy, default DROP

        lines.append(indent + default)

        # close parentheses
        for _ in chain.rules:
            lines.append(")")

        lines.append(")")
    return "\n".join(lines)

import ipaddress
import re

ACTIONS = {"ACCEPT", "DROP", "RETURN", "DNAT", "SNAT", "NODECISION"}

def parse_cidr(cidr):
    neg = False
    cidr = cidr.strip()

    if cidr.startswith("!"):
        neg = True
        cidr = cidr[1:].strip()

    # no "/" → treat as full host match
    if "/" not in cidr:
        ip = int(ipaddress.IPv4Address(cidr))
        return neg, ip, 0xFFFFFFFF

    net = ipaddress.IPv4Network(cidr, strict=False)
    return neg, int(net.network_address), int(net.netmask)


def parse_ctstate(extras: str):
    if extras is None:
        return False, None
    m = re.search(r'(!\s*)?ctstate\s+([A-Z,]+)', extras)
    if not m:
        return False, None
    negate = (m.group(1) is not None)  # True if "!" exists
    states = m.group(2).split(",")
    
    return negate, states


def proto_condition(prot):
    if prot in ("*"):
        return "#t"
    if prot.lower() == "tcp":
        return "(bveq proto (bv 6 8))"
    if prot.lower() == "udp":
        return "(bveq proto (bv 17 8))"
    return "#t"


def ip_condition(var, cidr):
    neg, net, mask = parse_cidr(cidr)
    cond = f"(bveq (bvand {var} (bv {mask} 32)) (bv {net} 32))"
    if neg:
        return f"(not {cond})"
    return cond


def ctstate_condition(net, states):
    conds = [f"(bveq ctstate {s})" for s in states]
    if net:
        conds = [f"(not {c})" for c in conds]
    if len(conds) == 1:
        return conds[0]
    if net:
        return f"(and {' '.join(conds)})"
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
    neg, ct = parse_ctstate(rule.extras)
    if ct:
        conditions.append(ctstate_condition(neg, ct))
    else:
        conditions.append("#t")

    return f"(and {' '.join(conditions)})"


def gen_rule_call(rule, indent="    "):
    """
    Generate the Rosette code for calling a rule:
    (let ([decision (KUBE_NODEPORTS srcPort srcIP dstPort dstIP protocol ctstate)])
         (if (not (bveq decision (bv 5 4)))
             decision
             NEXT))
    """
    fname = rule.target   # Rosette identifiers cannot have '-'
    if fname in ACTIONS:
        if fname == "ACCEPT":
            call = "(bv 0 4)"  # ACCEPT
        elif fname == "DROP":
            call = "(bv 1 4)"  # DROP
        elif fname == "DNAT":
            call = "(bv 2 4)"  # DNAT
        elif fname == "SNAT":
            call = "(bv 3 4)"  # SNAT
        result = f"({call})\n"
    else:
        fname = fname.lower().replace("-", "_")
        call = f"({fname} srcPort srcIP dstPort dstIP protocol ctstate)"
        result = (
            f"(let ([decision {call}])\n"
            f"{indent}  (if (not (bveq decision (bv 5 4)))\n"
            f"{indent}        decision\n"
            f"{indent}        NEXT))"
        )
    return result

'''
Input: a chain of iptable chains
Output: Rosette specification code for the chain
'''
def gen_chain_spec(chains):
    lines = []
    for chain in chains:
        fn = chain.name.lower().replace("-", "_")   # e.g., "INPUT" → chain name
        lines.append(f"(define ({fn} srcPort srcIP dstPort dstIP protocol ctstate)")

        indent = "  "

        # default policy fallback
        if chain.policy == "ACCEPT":
            default = "(bv 0 4)"  # ACCEPT
        elif chain.policy == "DROP":
            default = "(bv 1 4)"  # DROP
        elif chain.policy == "DNAT":
            default = "(bv 2 4)"  # DNAT
        else:
            default = "(bv 1 4)"  # no policy, default DROP
        
        code_to_print_l = []
        default_code = f"[else {default}]"
        code_to_print_l.append(default_code)
        code_to_replace_l = []
        # Build chain from bottom to top
        for rule in reversed(chain.rules):
            cond = gen_rule_condition(rule)
            call_block = gen_rule_call(rule)
            if len(code_to_replace_l) == 0:
                call_block = call_block.replace("NEXT", default)
            else:
                code = code_to_replace_l[-1]  # previous code
                # Insert previous code as NEXT
                call_block = call_block.replace("NEXT", "(" + code + ")")

            # Wrap inside cond (this is the *new* code)
            code_to_print = f"[{cond} {call_block}]"  # to print the code 
            code_to_print_l.append(code_to_print)
            code_to_replace = f"cond [{cond} {call_block}]"
            code_to_replace_l.append(code_to_replace)
            # code_to_fill = f"(cond [{cond} {call_block}] [else {default}])" # to fill in the previous rule's code

        lines.append(f"{indent}(cond")
        for code in reversed(code_to_print_l):
            lines.append(f"{indent}{code}")        
        lines.append(f"{indent})")  # end of cond
        
        lines.append(")")  # end of function
    
    return "\n".join(lines)

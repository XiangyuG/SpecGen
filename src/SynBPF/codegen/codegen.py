import ipaddress
import re

ACTIONS = {"ACCEPT", "DROP", "REJECT", "RETURN", "SNAT", "NODECISION", "MASQUERADE"}

chain_parameters = "srcPort srcIP dstPort dstIP protocol ctstate mark rand"

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
    # debug the mask and ip address
    # print(neg, net.network_address, net.netmask)
    # print(neg, int(net.network_address), int(net.netmask))
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


def proto_condition(prot, constant_list):
    if prot in ("*"):
        return "#t", constant_list
    if prot.lower() == "tcp":
        constant_list.append("(bv 6 8)")
        return "(bveq protocol (bv 6 8))", constant_list
    if prot.lower() == "udp":
        constant_list.append("(bv 17 8)")
        return "(bveq protocol (bv 17 8))", constant_list
    return "#t", constant_list


def ip_condition(var, cidr, constant_list):
    neg, net, mask = parse_cidr(cidr)
    constant_list.append(f"(bv {mask} 32)")
    constant_list.append(f"(bv {net} 32)")
    cond = f"(bveq (bvand {var} (bv {mask} 32)) (bv {net} 32))"
    if neg:
        return f"(not {cond})", constant_list
    return cond, constant_list


def ctstate_condition(net, states):
    conds = [f"(bveq ctstate {s})" for s in states]
    if net:
        conds = [f"(not {c})" for c in conds]
    if len(conds) == 1:
        return conds[0]
    if net:
        return f"(and {' '.join(conds)})"
    return f"(or {' '.join(conds)})"


def parse_mark(extras: str):
    """
      mark setting:
      MARK or 0x4000
    """
    if extras is None:
        return None

    # Case 1: MARK target (setting mark)
    m = re.search(r'MARK\s+(or|and|xor)\s+0x([0-9a-fA-F]+)', extras)
    if m:
        op = m.group(1)
        val = int(m.group(2), 16)
        return op, val

    return None, None

def parse_dnat(extras: str):
    """
      DNAT rule extras, example:
        tcp to:10.244.0.4:53
        udp to:10.244.0.4:53
    """

    if extras is None:
        return None, None, None

    # Match:  tcp to:10.244.0.4:53
    #         udp to:10.244.0.4:53
    m = re.search(r'\b(tcp|udp)\b\s+to:(\d+\.\d+\.\d+\.\d+):(\d+)', extras)
    if not m:
        return None, None, None

    proto = m.group(1)              # tcp / udp
    ip = m.group(2)                 # 10.244.0.4
    ip_int = int(ipaddress.IPv4Address(ip))
    port = int(m.group(3))          # 53

    return proto, ip_int, port

def parse_probability(extras: str):
    """
    Parse statistic mode random probability from extras.
    Example:
      "statistic mode random probability 0.50000000000"
    """

    if extras is None:
        return None

    m = re.search(r'probability\s+([0-9.]+)', extras)
    if not m:
        return None
    # Scale by 100 and then rounding
    return int(float(m.group(1)) * 100)

def gen_rule_condition(rule, constant_list, prob = None):
    '''
    Input: an iptable rule
    Output: Rosette condition code for the rule
    '''

    conditions = []

    proto_cond, constant_list = proto_condition(rule.prot, constant_list)
    if proto_cond != "#t":
        conditions.append(proto_cond)

    if rule.src != "0.0.0.0/0":
        ip_cond, constant_list = ip_condition("srcIP", rule.src, constant_list)
        conditions.append(ip_cond)
    else:
        constant_list.append("(bv 0 32)")

    if rule.dst != "0.0.0.0/0":
        ip_cond, constant_list = ip_condition("dstIP", rule.dst, constant_list)
        conditions.append(ip_cond)
    else:
        constant_list.append("(bv 0 32)")
    neg, ct = parse_ctstate(rule.extras)
    if ct:
        conditions.append(ctstate_condition(neg, ct))
    
    # set the prob to be between 0 and 99. set the threshold to be 8-bit
    if prob != None:
        conditions.append(f"(bvslt rand (bv {prob} 8))")

    if len(conditions) == 0:
        return "#t", constant_list
    return f"(and {' '.join(conditions)})", constant_list


def gen_rule_call(rule, constant_list, indent="    "):
    """
    Generate the Rosette code for calling a rule:
    (let ([decision (FUNCNAME srcPort srcIP dstPort dstIP protocol ctstate mark)])
         (if (not (bveq decision (bv 5 4)))
             decision
             NEXT))
    """
    fname = rule.target   # Rosette identifiers cannot have '-'
    if fname in ACTIONS:
        if fname == "ACCEPT":
            call = "(bv 0 4) ;;; ACCEPT"  # ACCEPT
        elif fname == "DROP":
            call = "(bv 1 4) ;;; DROP"  # DROP
        elif fname == "SNAT":
            call = "(bv 3 4) ;;; SNAT"  # SNAT
        elif fname == "REJECT":
            call = "(bv 4 4) ;;; REJECT"  # REJECT
        elif fname == "RETURN":
            call = "RETURN ;;; RETURN"  # RETURN
        elif fname == "MASQUERADE":
            call = "(bv 7 4) ;;; MASQUERADE"  # MASQUERADE
        result = f"(list {call} {chain_parameters})\n"
    elif fname == "DNAT":
        proto, ip, port = parse_dnat(rule.extras)
        constant_list.append(f"(bv {ip} 32)")
        constant_list.append(f"(bv {port} 16)")
        call = "(bv 2 4)"  # DNAT
        result = (
            f"(set! dstIP (bv {ip} 32))\n"
            f"(set! dstPort (bv {port} 16))\n"
            f"(list {call} {chain_parameters})\n"
        )
    elif fname == "MARK":
        op, val = parse_mark(rule.extras)
        if op == "or":
            op = "bvor"
        elif op == "xor":
            op = "bvxor"
        else:
            assert False, "unsupported operation for MARK at this point"
        call = "MARK"  # MARK
        constant_list.append(f"(bv {val} 16)")
        result = (
            f"(set! mark ({op} mark (bv {val} 16)))\n"
            f"(list {call} {chain_parameters})\n"
        )
    else:
        fname = fname.lower().replace("-", "_")
        call = f"({fname} {chain_parameters})"
        ret_list_name = "ret_list"
        result = (
            f"(let* ([{ret_list_name} {call}]\n"
            f"      [decision (list-ref {ret_list_name} 0)]\n"
            f"      [mark (list-ref {ret_list_name} 7)])\n"
            f"{indent}  (if (and (not (bveq decision NOHIT)) (not (bveq decision RETURN)) (not (bveq decision MARK)))\n"
            f"{indent}        {ret_list_name}\n"
            f"{indent}        NEXT))"
        )
    return result, constant_list


def unique_list(lst):
    seen = set()
    result = []
    for x in lst:
        if x not in seen:
            result.append(x)
            seen.add(x)
    return result

'''
Input: a chain of iptable chains
Output: Rosette specification code for the chain
'''
def gen_chain_spec(chains):
    constant_list = []
    lines = []
    lines.append("(define NEW (bv 0 4))")
    lines.append("(define RELATED (bv 1 4))")
    lines.append("(define ESTABLISHED (bv 2 4))")
    lines.append("(define INVALID (bv 3 4))")
    lines.append("(define DNAT (bv 4 4))")

    lines.append("(define NOHIT (bv 5 4))")
    lines.append("(define RETURN (bv 6 4))")
    lines.append("(define MARK (bv 8 4))")
    for chain in chains:
        fn = chain.name.lower().replace("-", "_")   # e.g., "INPUT" → chain name
        # TODO: Preprocess the load-balancing chain starting from KUBE-SVC
        rand_l = []
        if fn[0:8] == "kube_svc":
            for rule in chain.rules:
                rand_l.append(parse_probability(rule.extras))
            val = 0
            for i in range(len(rand_l)):
                rv = rand_l[i]
                if rv != None:
                    val += rv
                    rand_l[i] = val
                    constant_list.append(f"(bv {val} 8)")

        lines.append(f"(define ({fn} {chain_parameters})")

        indent = "  "

        # default policy fallback
        if chain.policy == "ACCEPT":
            default = "(bv 0 4)"  # ACCEPT
        elif chain.policy == "DROP":
            default = "(bv 1 4)"  # DROP
        elif chain.policy == "DNAT":
            default = "(bv 2 4)"  # DNAT
        else:
            default = "NOHIT"  # no policy

        code_to_print_l = []
        default_code = f"[else (list {default} {chain_parameters})]"
        code_to_print_l.append(default_code)

        # Build chain from bottom to top
        for i in range(len(chain.rules) - 1, -1, -1):
            rule = chain.rules[i]
            if len(rand_l) == 0:
                cond, constant_list = gen_rule_condition(rule, constant_list)
            else:
                cond, constant_list = gen_rule_condition(rule, constant_list, rand_l[i])
            call_block, constant_list = gen_rule_call(rule, constant_list)
            if len(code_to_print_l) == 1:
                call_block = call_block.replace("NEXT", f"(list {default} {chain_parameters})")
                # print(f"code_to_replace_l is empty {call_block}")
            else:
                code = ""
                # Concatenate all previous code pieces
                for code_piece in reversed(code_to_print_l):
                    code += code_piece
                # Insert previous code as NEXT
                call_block = call_block.replace("NEXT", "(cond\n" + code + ")")
                # print(f"code_to_replace_l is not empty {call_block}")

            # Wrap inside cond (this is the *new* code)
            code_to_print = f"[{cond} {call_block}]\n"  # to print the code 
            code_to_print_l.append(code_to_print)
            
        lines.append(f"{indent}(cond")
        for code in reversed(code_to_print_l):
            lines.append(f"{indent}{code}")        
        lines.append(f"{indent})")  # end of cond
        
        lines.append(")")  # end of function
    constant_list = unique_list(constant_list)    
    return "\n".join(lines), constant_list

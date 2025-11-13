import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Rule:
    num: int
    pkts: str
    bytes: str
    target: str
    prot: str
    opt: str
    inp: str
    out: str
    src: str
    dst: str
    extras: Optional[str] = None

@dataclass
class Chain:
    name: str
    policy: str = None
    packets: str = None
    bytes: str = None
    rules: list = field(default_factory=list)

def parse_iptables(text: str):
    chains = []
    current_chain = None

    # Regex patterns
    chain_header = re.compile(r'^Chain (\S+) \(policy (\S+) (\d+) packets, (\d+) bytes\)')
    rule_line = re.compile(
        r'^\s*'           # Beginning empty
        r'(\d+)\s+'       # num
        r'(\S+)\s+'       # pkts
        r'(\S+)\s+'       # bytes
        r'(\S+)\s+'       # target
        r'(\S+)\s+'       # prot
        r'(\S+)\s+'       # opt
        r'(\S+)\s+'       # in
        r'(\S+)\s+'       # out
        r'(\S+)'          # src
        r'\s+'            # >=1 space
        r'(\S+)'          # dst
        r'(?:\s+(.*))?$'  # optional extras (e.g., ctstate / comment）
    )

    chain_no_policy = re.compile(r'^Chain (\S+) \((\d+) references\)')

    for line in text.splitlines():
        line = line.rstrip()

        # Chain with policy
        m = chain_header.match(line)
        if m:
            name, policy, pkts, bytes_ = m.groups()
            current_chain = Chain(name=name, policy=policy, packets=pkts, bytes=bytes_)
            chains.append(current_chain)
            continue
        
        # Chain without policy
        m = chain_no_policy.match(line)
        if m:
            name, refs = m.groups()
            current_chain = Chain(name=name)
            chains.append(current_chain)
            continue

        # Rule line
        m = rule_line.match(line)
        if m and current_chain:
            r = Rule(*m.groups())
            current_chain.rules.append(r)

    return chains

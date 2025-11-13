import argparse
from SynBPF.frontends.parser import parse_iptables
from SynBPF.codegen.codegen import gen_chain_spec

def parse_file(filename: str):
    """Parse one iptables dump file."""
    with open(filename, "r") as f:
        text = f.read()
    return parse_iptables(text)


def print_chains(chains):
    """Pretty-print chain + rule info."""
    for chain in chains:
        print(f"Chain: {chain.name}, Default Policy: {chain.policy}, "
              f"Packets: {chain.packets}, Bytes: {chain.bytes}")

        for rule in chain.rules:
            print(
                f"  Rule {rule.num}: {rule.pkts} pkts, {rule.bytes} bytes, "
                f"Target: {rule.target}, Prot: {rule.prot}, "
                f"In: {rule.inp}, Out: {rule.out}, "
                f"Src: {rule.src}, Dst: {rule.dst}, "
                f"Extras: {rule.extras}"
            )
        print()  # blank line between chains


def main():
    parser = argparse.ArgumentParser(
        description="Parse iptables text dump into structured SynBPF IR"
    )

    parser.add_argument(
        "file",
        type=str,
        help="Path to iptables dump text file (e.g., /tmp/iptables_dump.txt)"
    )

    args = parser.parse_args()

    # Step 1: Parse the input iptable file
    chains = parse_file(args.file)
    print_chains(chains) # print for debugging

    # Step 2: Generate code to Rosette's specification format
    codegen_output = gen_chain_spec(chains)
    print("Generated Rosette Specification Code:")
    print(codegen_output)
    
if __name__ == "__main__":
    main()

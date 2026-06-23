from firewall_service import FirewallService

def get_rules_from_user():
    print("Enter Firewall Rules (type DONE to finish):")
    lines = []

    while True:
        line = input("> ")
        if line.strip().upper() == "DONE":
            break
        lines.append(line)

    return "\n".join(lines)


def main():
    try:
        service = FirewallService()

        rule_text = get_rules_from_user()

        rules = service.compile_rules(rule_text)

        print("\nRules Compiled Successfully ✅\n")

        print("Now enter packets to simulate.")
        print("Format: PROTOCOL SOURCE DESTINATION PORT")
        print("Type EXIT to stop.\n")

        while True:
            user_input = input("Packet> ")

            if user_input.strip().upper() == "EXIT":
                break

            parts = user_input.split()

            if len(parts) not in [3, 4]:
                print("Invalid packet format.")
                continue

            protocol = parts[0]
            source = parts[1]
            destination = parts[2]
            port = int(parts[3]) if len(parts) == 4 else None

            decision, matched_rule = service.simulate_packet(
                protocol, source, destination, port
            )

            print("Decision:", decision)
            print("Matched Rule:", matched_rule)
            print("-----")

        print("\nRule Statistics:")
        stats = service.get_stats()

        for rule, count in stats.items():
            print(f"{rule} → Hits: {count}")

    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    main()
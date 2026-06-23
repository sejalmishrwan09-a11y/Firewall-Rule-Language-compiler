import random
import time
from firewall_service import firewall_service
from database import SessionLocal, PacketLog

DEFAULT_RULES = """
ALLOW TCP FROM 192.168.1.0/24 TO ANY PORT 80
ALLOW UDP FROM 192.168.1.0/24 TO ANY PORT 53
DENY ICMP FROM ANY TO ANY
"""

firewall_service.compile_rules(DEFAULT_RULES)

PACKET_TEMPLATES = [
    ("TCP",  lambda: random.choice([80, 443, 22, 8080])),
    ("TCP",  lambda: random.choice([80, 443, 22, 8080])),
    ("UDP",  lambda: random.choice([53, 123, 161])),
    ("ICMP", lambda: None),
]

def generate_packet():
    proto, port_fn = random.choice(PACKET_TEMPLATES)
    source      = f"192.168.1.{random.randint(1, 254)}"
    destination = f"10.0.0.{random.randint(1, 254)}"
    port        = port_fn()
    return proto, source, destination, port


def start_traffic(interval: float = 2.0):
    print("Starting Auto Traffic Generator...\n")

    while True:
        protocol, src, dst, port = generate_packet()

        try:
            decision, matched = firewall_service.simulate_packet(
                protocol, src, dst, port
            )

            rule_str = str(matched) if matched else "default-deny"
            print(f"{src} → {dst} | {protocol}:{port or '-'} | {decision} | {rule_str}")

            db = SessionLocal()
            db.add(PacketLog(
                protocol=protocol,
                source=src,
                destination=dst,
                port=port,
                decision=decision
            ))
            db.commit()
            db.close()

        except Exception as e:
            print(f"ERROR: {e}")

        time.sleep(interval)


if __name__ == "__main__":
    start_traffic()

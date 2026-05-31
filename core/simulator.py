import random
import time
import threading
from datetime import datetime
from core.analyzer import PacketInfo, PacketAnalyzer

FAKE_IPS = [
    "192.168.1.1", "192.168.1.105", "10.0.0.1", "8.8.8.8",
    "1.1.1.1", "172.16.0.5", "203.0.113.42", "198.51.100.7",
    "93.184.216.34", "142.250.80.46", "151.101.1.140",
]

FAKE_PORTS = [80, 443, 53, 22, 8080, 3306, 5432, 3389, 6379, 8443, 25, 110]
PROTOCOLS = ["TCP"] * 6 + ["UDP"] * 3 + ["ICMP"] * 1
TCP_FLAG_COMBOS = ["SYN", "ACK", "SYN+ACK", "PSH+ACK", "FIN+ACK", "RST"]


def make_fake_packet() -> PacketInfo:
    proto = random.choice(PROTOCOLS)
    src_ip = random.choice(FAKE_IPS)
    dst_ip = random.choice([ip for ip in FAKE_IPS if ip != src_ip])
    src_port = random.choice(FAKE_PORTS) if proto in ("TCP","UDP") else None
    dst_port = random.choice(FAKE_PORTS) if proto in ("TCP","UDP") else None
    flags = random.choice(TCP_FLAG_COMBOS) if proto == "TCP" else ""
    return PacketInfo(
        timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
        src_ip=src_ip, dst_ip=dst_ip,
        protocol=proto,
        src_port=src_port, dst_port=dst_port,
        length=random.randint(40, 1500),
        flags=flags,
        ttl=random.choice([64, 128, 255]),
        raw_hex="".join(random.choices("0123456789abcdef", k=32)),
    )


class SimulatedCapture:
    def __init__(self, analyzer: PacketAnalyzer, pps: float = 5.0):
        self.analyzer = analyzer
        self.pps = pps
        self._thread = None

    def start(self):
        self.analyzer.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print(f"[SIM] Simulated capture started @ {self.pps} pps")

    def _loop(self):
        interval = 1.0 / self.pps
        while self.analyzer.running:
            pkt = make_fake_packet()
            self.analyzer.packets.append(pkt)
            self.analyzer._update_stats(pkt)
            self.analyzer._notify(pkt)
            time.sleep(max(0.01, interval + random.uniform(-0.05, 0.05)))

    def stop(self):
        self.analyzer.stop()
        print("[SIM] Simulation stopped.")
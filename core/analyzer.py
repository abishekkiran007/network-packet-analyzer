import socket
import struct
import time
import threading
import json
from datetime import datetime
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class PacketInfo:
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    flags: str = ""
    ttl: int = 0
    raw_hex: str = ""
    def to_dict(self): return asdict(self)


@dataclass
class Stats:
    total_packets: int = 0
    total_bytes: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    other_count: int = 0
    top_src_ips: dict = field(default_factory=dict)
    top_dst_ips: dict = field(default_factory=dict)
    top_ports: dict = field(default_factory=dict)
    packets_per_second: float = 0.0
    start_time: float = field(default_factory=time.time)


PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}
TCP_FLAGS = {0x01:"FIN",0x02:"SYN",0x04:"RST",0x08:"PSH",0x10:"ACK",0x20:"URG"}
WELL_KNOWN_PORTS = {
    20:"FTP-DATA",21:"FTP",22:"SSH",23:"TELNET",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",6379:"Redis",
    8080:"HTTP-ALT",8443:"HTTPS-ALT",
}


def parse_ip_header(raw):
    if len(raw) < 20: return None
    try:
        iph = struct.unpack("!BBHHHBBH4s4s", raw[:20])
        return {"ihl":(iph[0]&0xF)*4,"protocol":iph[6],
                "src_ip":socket.inet_ntoa(iph[8]),"dst_ip":socket.inet_ntoa(iph[9]),
                "ttl":iph[5],"length":iph[2]}
    except struct.error: return None


def parse_tcp_header(raw):
    if len(raw) < 20: return None
    try:
        t = struct.unpack("!HHLLBBHHH", raw[:20])
        flags = "+".join(n for b,n in TCP_FLAGS.items() if t[5]&b)
        return {"src_port":t[0],"dst_port":t[1],"flags":flags}
    except struct.error: return None


def parse_udp_header(raw):
    if len(raw) < 8: return None
    try:
        u = struct.unpack("!HHHH", raw[:8])
        return {"src_port":u[0],"dst_port":u[1]}
    except struct.error: return None


def get_service(port):
    return WELL_KNOWN_PORTS.get(port, str(port)) if port else ""


class PacketAnalyzer:
    def __init__(self, max_packets=1000):
        self.packets = deque(maxlen=max_packets)
        self.stats = Stats()
        self.running = False
        self._lock = threading.Lock()
        self._callbacks = []
        self._pps_window = deque(maxlen=60)

    def add_callback(self, fn): self._callbacks.append(fn)

    def _notify(self, pkt):
        for cb in self._callbacks:
            try: cb(pkt)
            except: pass

    def _update_stats(self, pkt):
        with self._lock:
            self.stats.total_packets += 1
            self.stats.total_bytes += pkt.length
            if pkt.protocol == "TCP": self.stats.tcp_count += 1
            elif pkt.protocol == "UDP": self.stats.udp_count += 1
            elif pkt.protocol == "ICMP": self.stats.icmp_count += 1
            else: self.stats.other_count += 1
            self.stats.top_src_ips[pkt.src_ip] = self.stats.top_src_ips.get(pkt.src_ip,0)+1
            self.stats.top_dst_ips[pkt.dst_ip] = self.stats.top_dst_ips.get(pkt.dst_ip,0)+1
            for p in [pkt.src_port, pkt.dst_port]:
                if p:
                    k = get_service(p)
                    self.stats.top_ports[k] = self.stats.top_ports.get(k,0)+1
            now = time.time()
            self._pps_window.append(now)
            self.stats.packets_per_second = round(len(self._pps_window)/max(now-self.stats.start_time,1),2)

    def _process_raw(self, raw):
        ip = parse_ip_header(raw)
        if not ip: return None
        proto = ip["protocol"]
        payload = raw[ip["ihl"]:]
        src_port = dst_port = None
        flags = ""
        if proto == 6:
            t = parse_tcp_header(payload)
            if t: src_port,dst_port,flags = t["src_port"],t["dst_port"],t["flags"]
        elif proto == 17:
            u = parse_udp_header(payload)
            if u: src_port,dst_port = u["src_port"],u["dst_port"]
        return PacketInfo(
            timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
            src_ip=ip["src_ip"], dst_ip=ip["dst_ip"],
            protocol=PROTO_MAP.get(proto,f"PROTO-{proto}"),
            src_port=src_port, dst_port=dst_port,
            length=ip["length"], flags=flags, ttl=ip["ttl"],
            raw_hex=raw[:16].hex()
        )

    def capture(self, filter_proto=None, filter_ip=None, count=0):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        except PermissionError:
            raise PermissionError("Admin privileges required. Run as Administrator.")
        self.running = True
        captured = 0
        try:
            while self.running:
                raw, _ = sock.recvfrom(65535)
                pkt = self._process_raw(raw)
                if not pkt: continue
                if filter_proto and pkt.protocol != filter_proto.upper(): continue
                if filter_ip and filter_ip not in (pkt.src_ip, pkt.dst_ip): continue
                self.packets.append(pkt)
                self._update_stats(pkt)
                self._notify(pkt)
                captured += 1
                if count and captured >= count: break
        finally:
            sock.close()
            self.running = False

    def stop(self): self.running = False

    def get_stats_snapshot(self):
        with self._lock:
            total = max(self.stats.total_packets, 1)
            return {
                "total_packets": self.stats.total_packets,
                "total_bytes": self.stats.total_bytes,
                "elapsed_seconds": round(time.time()-self.stats.start_time,1),
                "pps": self.stats.packets_per_second,
                "protocol_breakdown": {
                    "TCP":   round(self.stats.tcp_count/total*100,1),
                    "UDP":   round(self.stats.udp_count/total*100,1),
                    "ICMP":  round(self.stats.icmp_count/total*100,1),
                    "Other": round(self.stats.other_count/total*100,1),
                },
                "top_src_ips":  dict(sorted(self.stats.top_src_ips.items(),key=lambda x:x[1],reverse=True)[:5]),
                "top_dst_ips":  dict(sorted(self.stats.top_dst_ips.items(),key=lambda x:x[1],reverse=True)[:5]),
                "top_ports":    dict(sorted(self.stats.top_ports.items(),  key=lambda x:x[1],reverse=True)[:5]),
            }

    def get_recent_packets(self, n=20):
        with self._lock:
            return [p.to_dict() for p in list(self.packets)[-n:]]

    def save_to_json(self, path):
        data = {"stats": self.get_stats_snapshot(), "packets": [p.to_dict() for p in self.packets]}
        with open(path,"w") as f: json.dump(data,f,indent=2)
        print(f"[+] Saved {len(self.packets)} packets to {path}")
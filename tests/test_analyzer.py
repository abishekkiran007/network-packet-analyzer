import struct
import socket
import time
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.analyzer import (
    PacketAnalyzer, PacketInfo,
    parse_ip_header, parse_tcp_header, parse_udp_header, get_service
)
from core.simulator import make_fake_packet, SimulatedCapture


def make_raw_ip(src="192.168.1.1", dst="8.8.8.8", proto=6, payload=b""):
    version_ihl = (4 << 4) | 5
    total_length = 20 + len(payload)
    raw = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_length, 0, 0,
        64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst)
    ) + payload
    return raw


def make_raw_tcp(src_port=12345, dst_port=80, flags=0x02):
    return struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, 0, 0,
        (5 << 4), flags, 65535, 0, 0
    )


def make_raw_udp(src_port=54321, dst_port=53):
    return struct.pack("!HHHH", src_port, dst_port, 8, 0)


class TestIPParser:
    def test_valid_ip_header(self):
        raw = make_raw_ip("10.0.0.1", "10.0.0.2", proto=6)
        result = parse_ip_header(raw)
        assert result is not None
        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "10.0.0.2"
        assert result["protocol"] == 6
        assert result["ihl"] == 20
        assert result["ttl"] == 64

    def test_too_short(self):
        assert parse_ip_header(b"\x00" * 10) is None

    def test_empty(self):
        assert parse_ip_header(b"") is None


class TestTCPParser:
    def test_syn_packet(self):
        raw = make_raw_tcp(src_port=54321, dst_port=443, flags=0x02)
        result = parse_tcp_header(raw)
        assert result is not None
        assert result["src_port"] == 54321
        assert result["dst_port"] == 443
        assert "SYN" in result["flags"]

    def test_ack_packet(self):
        raw = make_raw_tcp(flags=0x10)
        result = parse_tcp_header(raw)
        assert "ACK" in result["flags"]

    def test_syn_ack(self):
        raw = make_raw_tcp(flags=0x12)
        result = parse_tcp_header(raw)
        assert "SYN" in result["flags"]
        assert "ACK" in result["flags"]

    def test_too_short(self):
        assert parse_tcp_header(b"\x00" * 5) is None


class TestUDPParser:
    def test_dns_packet(self):
        raw = make_raw_udp(src_port=12345, dst_port=53)
        result = parse_udp_header(raw)
        assert result["src_port"] == 12345
        assert result["dst_port"] == 53

    def test_too_short(self):
        assert parse_udp_header(b"\x00" * 4) is None


class TestGetService:
    def test_known_ports(self):
        assert get_service(80)  == "HTTP"
        assert get_service(443) == "HTTPS"
        assert get_service(22)  == "SSH"
        assert get_service(53)  == "DNS"

    def test_unknown_port(self):
        assert get_service(9999) == "9999"

    def test_none_port(self):
        assert get_service(None) == ""


class TestPacketAnalyzer:
    def setup_method(self):
        self.analyzer = PacketAnalyzer(max_packets=100)

    def _feed(self, proto="TCP", src_ip="1.2.3.4", dst_ip="5.6.7.8",
              src_port=1234, dst_port=80, length=100):
        pkt = PacketInfo(
            timestamp="12:00:00.000",
            src_ip=src_ip, dst_ip=dst_ip,
            protocol=proto,
            src_port=src_port, dst_port=dst_port,
            length=length, flags="SYN", ttl=64, raw_hex="deadbeef"
        )
        self.analyzer.packets.append(pkt)
        self.analyzer._update_stats(pkt)
        return pkt

    def test_stats_count(self):
        self._feed("TCP")
        self._feed("UDP")
        self._feed("ICMP", src_port=None, dst_port=None)
        s = self.analyzer.get_stats_snapshot()
        assert s["total_packets"] == 3

    def test_protocol_breakdown(self):
        for _ in range(3): self._feed("TCP")
        for _ in range(1): self._feed("UDP")
        s = self.analyzer.get_stats_snapshot()
        assert s["protocol_breakdown"]["TCP"] == 75.0
        assert s["protocol_breakdown"]["UDP"] == 25.0

    def test_total_bytes(self):
        self._feed(length=500)
        self._feed(length=300)
        s = self.analyzer.get_stats_snapshot()
        assert s["total_bytes"] == 800

    def test_top_src_ips(self):
        self._feed(src_ip="1.1.1.1")
        self._feed(src_ip="1.1.1.1")
        self._feed(src_ip="2.2.2.2")
        s = self.analyzer.get_stats_snapshot()
        assert s["top_src_ips"]["1.1.1.1"] == 2

    def test_callback_fired(self):
        received = []
        self.analyzer.add_callback(lambda p: received.append(p.protocol))
        pkt = self._feed("TCP")
        self.analyzer._notify(pkt)
        assert "TCP" in received

    def test_get_recent_packets(self):
        for i in range(10):
            self._feed(src_ip=f"10.0.0.{i}")
        pkts = self.analyzer.get_recent_packets(5)
        assert len(pkts) == 5

    def test_save_to_json(self, tmp_path):
        self._feed()
        path = str(tmp_path / "test_output.json")
        self.analyzer.save_to_json(path)
        import json
        with open(path) as f:
            data = json.load(f)
        assert "packets" in data
        assert "stats" in data
        assert len(data["packets"]) == 1


class TestSimulator:
    def test_fake_packet_fields(self):
        pkt = make_fake_packet()
        assert pkt.src_ip != pkt.dst_ip
        assert pkt.protocol in ("TCP", "UDP", "ICMP")
        assert pkt.length > 0
        assert pkt.timestamp != ""

    def test_simulated_capture_feeds_analyzer(self):
        analyzer = PacketAnalyzer()
        sim = SimulatedCapture(analyzer, pps=50)
        sim.start()
        time.sleep(0.3)
        sim.stop()
        assert analyzer.stats.total_packets > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
import sys
import time
import argparse
import threading

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from core.analyzer import PacketAnalyzer
from core.simulator import SimulatedCapture


def plain_print_packet(pkt):
    sport = f":{pkt['src_port']}" if pkt['src_port'] else ""
    dport = f":{pkt['dst_port']}" if pkt['dst_port'] else ""
    flags = f" [{pkt['flags']}]" if pkt['flags'] else ""
    print(f"[{pkt['timestamp']}] {pkt['protocol']}{flags}  "
          f"{pkt['src_ip']}{sport} -> {pkt['dst_ip']}{dport}  "
          f"len={pkt['length']}  ttl={pkt['ttl']}")


def run_plain(analyzer):
    analyzer.add_callback(plain_print_packet)
    print("=" * 70)
    print("  NETWORK PACKET ANALYZER  |  Ctrl+C to stop")
    print("=" * 70)
    try:
        while analyzer.running:
            time.sleep(1)
    except KeyboardInterrupt:
        analyzer.stop()


def build_rich_display(analyzer):
    console = Console()
    s = analyzer.get_stats_snapshot()
    pkts = analyzer.get_recent_packets(15)
    pb = s["protocol_breakdown"]

    stats_text = Text()
    stats_text.append("  Packets : ", style="bold cyan")
    stats_text.append(f"{s['total_packets']:,}\n", style="white")
    stats_text.append("  Bytes   : ", style="bold cyan")
    stats_text.append(f"{s['total_bytes']:,}\n", style="white")
    stats_text.append("  PPS     : ", style="bold cyan")
    stats_text.append(f"{s['pps']}\n", style="green")
    stats_text.append("  Elapsed : ", style="bold cyan")
    stats_text.append(f"{s['elapsed_seconds']}s\n", style="white")
    stats_text.append(
        f"\n  TCP {pb['TCP']}%  UDP {pb['UDP']}%  "
        f"ICMP {pb['ICMP']}%  Other {pb['Other']}%",
        style="dim"
    )
    stats_panel = Panel(stats_text, title="[bold green]LIVE STATS",
                        border_style="green", padding=(0,1))

    ip_text = Text()
    ip_text.append("  TOP SOURCES\n", style="bold yellow")
    for ip, cnt in s["top_src_ips"].items():
        ip_text.append(f"  {ip:<18} {cnt}\n", style="white")
    ip_text.append("\n  TOP DESTINATIONS\n", style="bold yellow")
    for ip, cnt in s["top_dst_ips"].items():
        ip_text.append(f"  {ip:<18} {cnt}\n", style="white")
    ip_panel = Panel(ip_text, title="[bold yellow]TOP IPs",
                     border_style="yellow", padding=(0,1))

    port_text = Text()
    for svc, cnt in s["top_ports"].items():
        bar = "█" * min(cnt, 20)
        port_text.append(f"  {svc:<12} {bar} {cnt}\n", style="magenta")
    port_panel = Panel(port_text, title="[bold magenta]TOP PORTS",
                       border_style="magenta", padding=(0,1))

    table = Table(box=box.SIMPLE_HEAVY, show_header=True,
                  header_style="bold cyan", expand=True)
    table.add_column("Time",    style="dim",    width=14)
    table.add_column("Proto",   style="bold",   width=7)
    table.add_column("Flags",   style="yellow", width=12)
    table.add_column("Source",  style="cyan",   width=22)
    table.add_column("Dest",    style="green",  width=22)
    table.add_column("Len",     justify="right",width=6)
    table.add_column("TTL",     justify="right",width=5)

    COLORS = {"TCP":"bold blue","UDP":"bold green",
              "ICMP":"bold red","default":"white"}

    for p in reversed(pkts):
        color = COLORS.get(p["protocol"], COLORS["default"])
        sp = f":{p['src_port']}" if p["src_port"] else ""
        dp = f":{p['dst_port']}" if p["dst_port"] else ""
        table.add_row(
            p["timestamp"],
            f"[{color}]{p['protocol']}[/]",
            p["flags"] or "—",
            f"{p['src_ip']}{sp}",
            f"{p['dst_ip']}{dp}",
            str(p["length"]),
            str(p["ttl"]),
        )

    pkt_panel = Panel(table, title="[bold white]LIVE PACKETS",
                      border_style="white", padding=(0,0))

    return Columns([
        Panel(Columns([stats_panel, ip_panel, port_panel]),
              title="[bold] NETWORK PACKET ANALYZER  |  Ctrl+C to stop",
              border_style="bright_black"),
    ]), pkt_panel


def run_rich(analyzer):
    console = Console()
    console.print("\n[bold green]  NETWORK PACKET ANALYZER[/]  starting...\n")
    time.sleep(0.5)
    try:
        with Live(console=console, refresh_per_second=2, screen=True) as live:
            while analyzer.running:
                from rich.console import Group
                top, table = build_rich_display(analyzer)
                live.update(Group(top, table))
                time.sleep(0.5)
    except KeyboardInterrupt:
        analyzer.stop()
        console.print("\n[yellow]Stopped.[/]")


def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer by Abishek D"
    )
    parser.add_argument("--sim",   action="store_true",
                        help="Use simulated traffic (no admin needed)")
    parser.add_argument("--proto", default=None,
                        help="Filter: TCP / UDP / ICMP")
    parser.add_argument("--ip",    default=None,
                        help="Filter by IP address")
    parser.add_argument("--count", type=int, default=0,
                        help="Stop after N packets")
    parser.add_argument("--pps",   type=float, default=8.0,
                        help="Simulated packets per second")
    parser.add_argument("--save",  default=None,
                        help="Save packets to JSON file")
    parser.add_argument("--plain", action="store_true",
                        help="Plain text output")
    args = parser.parse_args()

    analyzer = PacketAnalyzer(max_packets=500)

    if args.sim:
        sim = SimulatedCapture(analyzer, pps=args.pps)
        sim.start()
        try:
            if args.plain or not HAS_RICH:
                run_plain(analyzer)
            else:
                run_rich(analyzer)
        finally:
            sim.stop()
    else:
        t = threading.Thread(
            target=analyzer.capture,
            kwargs={"filter_proto":args.proto,
                    "filter_ip":args.ip,
                    "count":args.count},
            daemon=True
        )
        t.start()
        try:
            if args.plain or not HAS_RICH:
                run_plain(analyzer)
            else:
                run_rich(analyzer)
        finally:
            analyzer.stop()

    if args.save:
        analyzer.save_to_json(args.save)


if __name__ == "__main__":
    main()
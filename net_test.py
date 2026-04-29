#!/usr/bin/env python3
"""
Host-side checks for the FPGA Ethernet bring-up: ICMP ping and UDP echo probe.

Examples:
  python net_test.py ping
  python net_test.py ping 192.168.1.10 --count 5
  python net_test.py udp
  python net_test.py udp --ip 192.168.1.10 --port 4000

UDP path matches a stack that echoes payload on the same flow (see project docs).
If ARP for the FPGA never completes, you may need a static ARP entry (admin):
  arp -s 192.168.1.10 02-12-34-56-78-9A
"""

from __future__ import annotations

import argparse
import platform
import socket
import subprocess
import sys
import time

DEFAULT_FPGA_IP = "192.168.1.10"
DEFAULT_UDP_PORT = 4000
DEFAULT_PAYLOAD = b"HELLO_FPGA"


def run_ping(host: str, count: int) -> int:
    """Run system ICMP ping (no extra Python deps). Returns ping process exit code."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), host]
    print(" ".join(cmd), "\n", flush=True)
    proc = subprocess.run(cmd)
    return int(proc.returncode)


def run_udp_probe(
    ip: str,
    port: int,
    payload: bytes,
    interval: float,
) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    sock.settimeout(0.0)
    local = sock.getsockname()
    print(f"Local UDP {local[0] or '*'}:{local[1]} -> {ip}:{port}")
    print(f"Payload ({len(payload)} B): {payload!r}")
    print("TX / RX lines below. Ctrl+C to stop.\n")

    sent = 0
    replies = 0
    try:
        while True:
            sock.sendto(payload, (ip, port))
            sent += 1
            print(f"TX {sent:6d}  -> {ip}:{port}  {len(payload):4d} B  {payload!r}")

            while True:
                try:
                    data, addr = sock.recvfrom(2048)
                    replies += 1
                    print(f"RX {replies:6d}  <- {addr[0]}:{addr[1]}  {len(data):4d} B  {data!r}")
                except BlockingIOError:
                    break
                except InterruptedError:
                    break
                except OSError:
                    break

            if interval > 0:
                time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\nStopped. TX={sent}  RX={replies}")
    finally:
        sock.close()
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="Ping the FPGA (ICMP) or send UDP probes and print replies.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("ping", help="ICMP echo using the OS ping command")
    pp.add_argument("host", nargs="?", default=DEFAULT_FPGA_IP, help=f"IPv4 (default {DEFAULT_FPGA_IP})")
    pp.add_argument("-n", "--count", type=int, default=4, metavar="N", help="Number of pings (default 4)")

    up = sub.add_parser("udp", help="Send UDP payloads and print any replies (echo test)")
    up.add_argument("--ip", default=DEFAULT_FPGA_IP, help=f"Destination IPv4 (default {DEFAULT_FPGA_IP})")
    up.add_argument("--port", type=int, default=DEFAULT_UDP_PORT, help=f"UDP port (default {DEFAULT_UDP_PORT})")
    up.add_argument("--payload", default=DEFAULT_PAYLOAD.decode("ascii"), help="ASCII payload")
    up.add_argument(
        "--interval",
        type=float,
        default=0.1,
        metavar="SEC",
        help="Seconds between sends (default 0.1; 0 = send as fast as possible)",
    )

    args = p.parse_args()

    if args.cmd == "ping":
        return run_ping(args.host, args.count)

    if args.cmd == "udp":
        raw = args.payload.encode("utf-8", errors="replace")
        if len(raw) > 900:
            print("Payload too long for safe test (keep under ~900 bytes).", file=sys.stderr)
            return 1
        return run_udp_probe(args.ip, args.port, raw, args.interval)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
Send UDP probes to the FPGA (192.168.1.10, port 4000) continuously until Ctrl+C.
The FPGA echoes the same payload (UDP ports swapped; checksum cleared).

Wireshark: udp.port == 4000  or  ip.addr == 192.168.1.10

If ARP for .10 never completes (admin cmd):
  arp -s 192.168.1.10 02-12-34-56-78-9A
"""

from __future__ import annotations

import argparse
import socket
import sys
import time

FPGA_IP = "192.168.1.10"
PROBE_PORT = 4000
DEFAULT_PAYLOAD = b"HELLO_FPGA"


def main() -> int:
    p = argparse.ArgumentParser(description="UDP probe: send forever until Ctrl+C.")
    p.add_argument("--ip", default=FPGA_IP, help=f"FPGA IPv4 (default {FPGA_IP})")
    p.add_argument("--port", type=int, default=PROBE_PORT, help=f"UDP dest port (default {PROBE_PORT})")
    p.add_argument("--payload", default=DEFAULT_PAYLOAD.decode("ascii"), help="ASCII payload")
    p.add_argument(
        "--interval",
        type=float,
        default=0.1,
        metavar="SEC",
        help="Seconds between packets (default 0.1; use 0 to send as fast as possible)",
    )
    args = p.parse_args()

    payload = args.payload.encode("utf-8", errors="replace")
    if len(payload) > 900:
        print("Payload too long for safe test (keep under ~900 bytes).", file=sys.stderr)
        return 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    sock.settimeout(0.0)
    local = sock.getsockname()
    print(f"Local UDP {local[0] or '*'}:{local[1]} -> {args.ip}:{args.port}")
    print(f"Fixed payload ({len(payload)} B): {payload!r}")
    print("Each line is one TX or RX. Ctrl+C to stop.\n")

    sent = 0
    replies = 0
    try:
        while True:
            sock.sendto(payload, (args.ip, args.port))
            sent += 1
            print(f"TX {sent:6d}  -> {args.ip}:{args.port}  {len(payload):4d} B  {payload!r}")

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

            if args.interval > 0:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nStopped. TX={sent}  RX={replies}")
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

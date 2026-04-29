#!/usr/bin/env python3
"""Read PHY link status from the FPGA UART (MRPI: hex lines from phy_uart_regdump)."""

from __future__ import annotations

import argparse
import json
import sys
import time

import serial
import serial.tools.list_ports

# Must match phy_uart_regdump.vhd header: M R P I :
MARKER = b"MRPI:"
DUMP_LEN = 9
HEX_DUMP_LEN = DUMP_LEN * 2


def list_ports() -> list[str]:
    return [port.device for port in serial.tools.list_ports.comports()]


def decode_mrpi_line(hex_payload: bytes) -> bytes | None:
    if len(hex_payload) != HEX_DUMP_LEN:
        return None
    try:
        return bytes.fromhex(hex_payload.decode("ascii"))
    except ValueError:
        return None


def phy_status(dump: bytes) -> dict:
    """Decode 9-byte MRPI payload (phyad, reg0..3 each 16-bit big-endian)."""
    if len(dump) != DUMP_LEN:
        return {"error": f"bad length {len(dump)}"}

    phyad = dump[0]
    bmcr = int.from_bytes(dump[1:3], "big")
    bmsr = int.from_bytes(dump[3:5], "big")
    r18 = int.from_bytes(dump[5:7], "big")
    r31 = int.from_bytes(dump[7:9], "big")

    no_phy = phyad == 0xFF and bmcr == 0xFFFF and bmsr == 0xFFFF and r18 == 0xFFFF and r31 == 0xFFFF

    out: dict = {
        "phyad": phyad,
        "bmcr": bmcr,
        "bmsr": bmsr,
        "reg18": r18,
        "reg31": r31,
        "no_phy": no_phy,
    }
    if no_phy:
        out["link_up"] = None
        out["autoneg_complete"] = None
        return out

    link_up = bool((bmsr >> 2) & 1)
    an_complete = bool((bmsr >> 5) & 1)
    out["link_up"] = link_up
    out["autoneg_complete"] = an_complete
    out["bmcr_autoneg"] = bool((bmcr >> 12) & 1)
    out["bmcr_duplex"] = bool((bmcr >> 8) & 1)
    out["bmcr_speed100"] = bool((bmcr >> 13) & 1)
    return out


def drain_until_mrpi(ser: serial.Serial, deadline: float) -> bytes | None:
    buffer = bytearray()
    while time.monotonic() < deadline:
        chunk = ser.read(4096)
        if chunk:
            buffer.extend(chunk)
        while True:
            marker_at = buffer.find(MARKER)
            if marker_at < 0:
                if len(buffer) > 64:
                    del buffer[:- (len(MARKER) - 1)]
                break
            if marker_at > 0:
                del buffer[:marker_at]
            dump_start = len(MARKER)
            dump_end = dump_start + HEX_DUMP_LEN
            if len(buffer) < dump_end:
                break
            hex_payload = bytes(buffer[dump_start:dump_end])
            dump = decode_mrpi_line(hex_payload)
            del buffer[:dump_end]
            while buffer[:1] in (b"\r", b"\n"):
                del buffer[:1]
            if dump is not None:
                return dump
    return None


def format_human(st: dict) -> str:
    if st.get("error"):
        return f"error: {st['error']}"
    if st.get("no_phy"):
        return "no MDIO PHY found (scan failed)"
    parts = [
        f"link={'up' if st['link_up'] else 'down'}",
        f"autoneg_done={st['autoneg_complete']}",
        f"bmcr=0x{st['bmcr']:04x}",
        f"bmsr=0x{st['bmsr']:04x}",
        f"phyad={st['phyad']}",
    ]
    return "  ".join(parts)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Query Ethernet PHY link status from FPGA UART (MRPI: register dump)."
    )
    p.add_argument("--port", help="Serial port, e.g. COM5")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument(
        "--once",
        action="store_true",
        help="Print one reading (or timeout) and exit",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=12.0,
        help="Seconds to wait for first MRPI line when using --once",
    )
    p.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    p.add_argument(
        "--exit-code",
        action="store_true",
        help="With --once: exit 0 if link up, 1 if link down, 2 if no PHY/timeout",
    )
    p.add_argument(
        "--raw",
        action="store_true",
        help="Dump every byte received (hex + ASCII). Useful when no MRPI line ever arrives.",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not args.port:
        ports = list_ports()
        if not ports:
            print("No serial ports found.", file=sys.stderr)
            return 2
        print("Available serial ports:")
        for port in ports:
            print(f"  {port}")
        print("\nRe-run with --port COMx", file=sys.stderr)
        return 2

    ser = serial.Serial(args.port, args.baud, timeout=0.25)

    if args.raw:
        print(
            f"Raw mode on {args.port} @ {args.baud} baud. "
            "Every byte received is printed. Ctrl+C to stop."
        )
        print("If you see NOTHING here for 10+ seconds, nothing is reaching the PC at all.")
        total = 0
        last_report = time.monotonic()
        try:
            while True:
                chunk = ser.read(4096)
                if chunk:
                    total += len(chunk)
                    ascii_view = "".join(
                        chr(b) if 32 <= b < 127 else "." for b in chunk
                    )
                    hex_view = " ".join(f"{b:02x}" for b in chunk)
                    ts = time.strftime("%H:%M:%S")
                    print(f"[{ts}] ({len(chunk):3d} B) {hex_view}")
                    print(f"                {ascii_view}")
                now = time.monotonic()
                if now - last_report >= 5.0:
                    print(f"[status] total bytes so far: {total}")
                    last_report = now
        except KeyboardInterrupt:
            print(f"\nStopped. Total bytes received: {total}")
            return 0
        finally:
            ser.close()

    if args.once:
        deadline = time.monotonic() + args.timeout
        dump = drain_until_mrpi(ser, deadline)
        ser.close()
        if dump is None:
            print("Timeout: no valid MRPI line.", file=sys.stderr)
            return 2 if args.exit_code else 1
        st = phy_status(dump)
        if args.json:
            print(json.dumps(st))
        else:
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] {format_human(st)}")
        if args.exit_code:
            if st.get("no_phy"):
                return 2
            if st.get("link_up"):
                return 0
            return 1
        return 0

    print(f"Opening {args.port} at {args.baud} baud — streaming MRPI link status (Ctrl+C to stop)\n")
    buffer = bytearray()
    try:
        while True:
            chunk = ser.read(4096)
            if chunk:
                buffer.extend(chunk)
            while True:
                marker_at = buffer.find(MARKER)
                if marker_at < 0:
                    emit_len = max(0, len(buffer) - (len(MARKER) - 1))
                    if emit_len:
                        del buffer[:emit_len]
                    break
                if marker_at > 0:
                    del buffer[:marker_at]
                dump_start = len(MARKER)
                dump_end = dump_start + HEX_DUMP_LEN
                if len(buffer) < dump_end:
                    break
                hex_payload = bytes(buffer[dump_start:dump_end])
                dump = decode_mrpi_line(hex_payload)
                del buffer[:dump_end]
                while buffer[:1] in (b"\r", b"\n"):
                    del buffer[:1]
                if dump is None:
                    continue
                st = phy_status(dump)
                ts = time.strftime("%H:%M:%S")
                if args.json:
                    print(json.dumps({"ts": ts, **st}))
                else:
                    print(f"[{ts}] {format_human(st)}")
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0
    finally:
        ser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

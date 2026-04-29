import argparse
import sys
import time

import serial
import serial.tools.list_ports


# Must match phy_uart_regdump.vhd: M R P I :
MARKER = b"MRPI:"
DUMP_LEN = 9
HEX_DUMP_LEN = DUMP_LEN * 2


def list_ports() -> list[str]:
    return [port.device for port in serial.tools.list_ports.comports()]


def print_raw(data: bytes) -> None:
    if not data:
        return
    ts = time.strftime("%H:%M:%S")
    ascii_view = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
    hex_view = " ".join(f"{b:02x}" for b in data)
    print(f"[{ts}] RAW {len(data)}B ascii='{ascii_view}' hex={hex_view}")


def speed_desc(code: int) -> str:
    return {
        0b001: "10BASE-T half-duplex",
        0b101: "10BASE-T full-duplex",
        0b010: "100BASE-TX half-duplex",
        0b110: "100BASE-TX full-duplex",
    }.get(code, f"unknown({code:03b})")


def print_dump(data: bytes) -> None:
    ts = time.strftime("%H:%M:%S")
    if len(data) != DUMP_LEN:
        print(f"[{ts}] Bad MDIO dump length: {len(data)}")
        print()
        return

    phyad = data[0]
    bmcr = int.from_bytes(data[1:3], "big")
    bmsr = int.from_bytes(data[3:5], "big")
    smode = int.from_bytes(data[5:7], "big")
    pscsr = int.from_bytes(data[7:9], "big")

    print(f"[{ts}] PHY dump (MRPI)")
    print("  " + " ".join(f"{b:02x}" for b in data))
    if phyad == 0xFF and bmcr == 0xFFFF and bmsr == 0xFFFF and smode == 0xFFFF and pscsr == 0xFFFF:
        print("  no MDIO responder found on PHY addresses 0..31")
        print()
        return
    print(f"  phyad      = {phyad}")
    print(
        f"  reg00 BMCR  = 0x{bmcr:04x}"
        f" reset={(bmcr >> 15) & 1}"
        f" loopback={(bmcr >> 14) & 1}"
        f" speed100={(bmcr >> 13) & 1}"
        f" autoneg={(bmcr >> 12) & 1}"
        f" restart_an={(bmcr >> 9) & 1}"
        f" duplex={(bmcr >> 8) & 1}"
    )
    print(f"  reg01 BMSR  = 0x{bmsr:04x} link_up={(bmsr >> 2) & 1} autoneg_complete={(bmsr >> 5) & 1}")
    print(f"  reg18 SMODE = 0x{smode:04x} mode={(smode >> 5) & 0x7} phyad={smode & 0x1f}")
    print(
        f"  reg31 PSCSR = 0x{pscsr:04x}"
        f" autodone={(pscsr >> 12) & 1}"
        f" speed={speed_desc((pscsr >> 2) & 0x7)}"
    )
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read LAN8720A MDIO dumps from Tang Primer UART.")
    parser.add_argument("--port", help="Serial port name, for example COM5")
    parser.add_argument("--baud", type=int, default=115200, help="UART baud rate")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.port:
        ports = list_ports()
        if not ports:
            print("No serial ports found. Plug in the board and try again.", file=sys.stderr)
            return 1
        print("Available serial ports:")
        for port in ports:
            print(f"  {port}")
        print("\nRun again with --port COMx for the UART port from the board.", file=sys.stderr)
        return 1

    print(f"Opening {args.port} at {args.baud} baud")
    print("Waiting for MRPI: PHY register dumps. Press Ctrl+C to stop.\n")

    buffer = bytearray()
    with serial.Serial(args.port, args.baud, timeout=0.25) as ser:
        while True:
            chunk = ser.read(4096)
            if chunk:
                buffer.extend(chunk)

            while True:
                marker_at = buffer.find(MARKER)
                if marker_at < 0:
                    emit_len = max(0, len(buffer) - (len(MARKER) - 1))
                    if emit_len:
                        print_raw(bytes(buffer[:emit_len]))
                        del buffer[:emit_len]
                    break

                if marker_at > 0:
                    print_raw(bytes(buffer[:marker_at]))
                    del buffer[:marker_at]
                    marker_at = 0

                dump_start = marker_at + len(MARKER)
                dump_end = dump_start + HEX_DUMP_LEN
                if len(buffer) < dump_end:
                    break

                hex_payload = bytes(buffer[dump_start:dump_end])
                try:
                    dump = bytes.fromhex(hex_payload.decode("ascii"))
                except ValueError:
                    print_raw(bytes(buffer[:dump_end]))
                    del buffer[:dump_end]
                    break

                print_dump(dump)
                del buffer[:dump_end]
                while buffer[:1] in (b"\r", b"\n"):
                    del buffer[:1]


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nStopped.")

#!/usr/bin/env python3
"""
EDID viewer / decoder.

Two ways to use it:

  1. As a standalone GUI:
        python edid_viewer.py
     - Paste a raw EDID dump (hex bytes, any common format) into the
       top text area, OR click "Load from File...".
     - Click "Decode" to see a human-readable breakdown.

  2. As a library (e.g. inside an issues-tracker that wants to embed an
     "Attach EDID" widget):
        from edid_viewer import parse_hex_dump, decode_edid, EdidWidget

     - parse_hex_dump(text) -> bytes        forgiving hex parser
     - decode_edid(data: bytes) -> dict     structured decode
     - format_decoded(decoded) -> str       pretty text
     - EdidWidget(parent=None) -> QWidget   reusable UI block

Dependencies: pyside6 (only for the GUI; the decoder itself is stdlib).
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# 1. Forgiving hex parser
# ---------------------------------------------------------------------------

_HEX_PAIR_RE = re.compile(r"[0-9a-fA-F]{2}")


def parse_hex_dump(text: str) -> bytes:
    """Accept basically any common EDID dump format and return raw bytes.

    Recognises:
      * "00 FF FF FF ..." (space separated)
      * "00FFFFFF..."     (no separators)
      * "0x00, 0xFF, ..." (C array)
      * Output of `xxd` / `hexdump -C` (offset + ascii sidebar are stripped)
      * Mixed case, blank lines, line numbering prefixes "1| ..."
    """
    if not text or not text.strip():
        raise ValueError("empty input")

    cleaned_lines: list[str] = []
    for line in text.splitlines():
        # Drop line-number prefixes like "  12| 00 FF ..." or "12: 00 FF ...".
        stripped = re.sub(r"^\s*\d+\s*[\|:]\s*", "", line)
        # Drop the trailing "|ascii sidebar|" from hexdump -C / xxd output.
        stripped = re.sub(r"\|.*\|\s*$", "", stripped)
        # Drop a leading hex offset followed by a colon ("0010: 00 FF ...").
        stripped = re.sub(r"^[0-9a-fA-F]{4,8}\s*[:\-]\s*", "", stripped)
        cleaned_lines.append(stripped)

    blob = " ".join(cleaned_lines)
    blob = blob.replace("0x", " ").replace("0X", " ")
    blob = re.sub(r"[,;]+", " ", blob)
    pairs = _HEX_PAIR_RE.findall(blob)

    if not pairs:
        # Could be one long unbroken hex string with no spaces at all.
        compact = re.sub(r"[^0-9a-fA-F]", "", blob)
        if len(compact) % 2 != 0:
            raise ValueError("hex string has odd length")
        pairs = [compact[i:i + 2] for i in range(0, len(compact), 2)]

    if not pairs:
        raise ValueError("no hex bytes found")

    return bytes(int(p, 16) for p in pairs)


# ---------------------------------------------------------------------------
# 2. EDID decoder
# ---------------------------------------------------------------------------

EDID_HEADER = bytes.fromhex("00FFFFFFFFFFFF00")
ESTABLISHED_TIMING_I = [
    (0x80, "720x400 @ 70 Hz (VGA)"),
    (0x40, "720x400 @ 88 Hz (XGA)"),
    (0x20, "640x480 @ 60 Hz (VGA)"),
    (0x10, "640x480 @ 67 Hz (Apple)"),
    (0x08, "640x480 @ 72 Hz"),
    (0x04, "640x480 @ 75 Hz"),
    (0x02, "800x600 @ 56 Hz"),
    (0x01, "800x600 @ 60 Hz"),
]
ESTABLISHED_TIMING_II = [
    (0x80, "800x600 @ 72 Hz"),
    (0x40, "800x600 @ 75 Hz"),
    (0x20, "832x624 @ 75 Hz (Apple)"),
    (0x10, "1024x768 @ 87 Hz interlaced"),
    (0x08, "1024x768 @ 60 Hz"),
    (0x04, "1024x768 @ 70 Hz"),
    (0x02, "1024x768 @ 75 Hz"),
    (0x01, "1280x1024 @ 75 Hz"),
]
ESTABLISHED_TIMING_III = [
    (0x80, "1152x870 @ 75 Hz (Apple)"),
]
DIGITAL_INTERFACES = {
    0x0: "Undefined",
    0x1: "DVI",
    0x2: "HDMI-a",
    0x3: "HDMI-b",
    0x4: "MDDI",
    0x5: "DisplayPort",
}
COLOR_DEPTH = {
    0b000: "undefined",
    0b001: "6 bpc",
    0b010: "8 bpc",
    0b011: "10 bpc",
    0b100: "12 bpc",
    0b101: "14 bpc",
    0b110: "16 bpc",
    0b111: "reserved",
}
ASPECT_RATIO = {
    0b00: "16:10",
    0b01: "4:3",
    0b10: "5:4",
    0b11: "16:9",
}


@dataclass
class DetailedTiming:
    pixel_clock_khz: int
    h_active: int
    h_blank: int
    v_active: int
    v_blank: int
    h_front_porch: int
    h_sync_width: int
    v_front_porch: int
    v_sync_width: int
    h_size_mm: int
    v_size_mm: int
    h_border: int
    v_border: int
    interlaced: bool
    flags_raw: int

    @property
    def refresh_hz(self) -> float:
        if self.pixel_clock_khz <= 0:
            return 0.0
        h_total = self.h_active + self.h_blank
        v_total = self.v_active + self.v_blank
        if h_total == 0 or v_total == 0:
            return 0.0
        rate = (self.pixel_clock_khz * 1000) / (h_total * v_total)
        if self.interlaced:
            rate *= 2
        return rate

    def short(self) -> str:
        return (
            f"{self.h_active}x{self.v_active}"
            f"{'i' if self.interlaced else ''} "
            f"@ {self.refresh_hz:.2f} Hz "
            f"({self.pixel_clock_khz / 1000:.2f} MHz)"
        )


@dataclass
class DescriptorBlock:
    kind: str  # "detailed_timing", "monitor_name", "monitor_serial", "range_limits", "ascii_text", "unknown"
    raw: bytes
    payload: dict = field(default_factory=dict)
    text: str = ""


@dataclass
class DecodedEdid:
    raw: bytes
    valid_header: bool
    checksum_ok: bool
    manufacturer: str
    product_code: int
    serial_number: int
    week: int
    year: int
    edid_version: tuple[int, int]
    is_digital: bool
    digital_color_depth: str
    digital_interface: str
    h_size_cm: int
    v_size_cm: int
    gamma: float | None
    features: dict
    chromaticity: dict
    established_timings: list[str]
    standard_timings: list[str]
    descriptors: list[DescriptorBlock]
    extension_blocks: int
    cea_blocks: list[dict] = field(default_factory=list)


def _decode_manufacturer(b0: int, b1: int) -> str:
    raw = (b0 << 8) | b1
    c1 = (raw >> 10) & 0x1F
    c2 = (raw >> 5) & 0x1F
    c3 = raw & 0x1F

    def to_letter(x: int) -> str:
        if 1 <= x <= 26:
            return chr(ord("A") + x - 1)
        return "?"

    return to_letter(c1) + to_letter(c2) + to_letter(c3)


def _trim_descriptor_text(buf: bytes) -> str:
    text = buf.split(b"\n")[0]
    return text.decode("ascii", errors="replace").rstrip()


def _parse_detailed_timing(block: bytes) -> DetailedTiming:
    pixel_clock_khz = ((block[1] << 8) | block[0]) * 10
    h_active = block[2] | ((block[4] & 0xF0) << 4)
    h_blank = block[3] | ((block[4] & 0x0F) << 8)
    v_active = block[5] | ((block[7] & 0xF0) << 4)
    v_blank = block[6] | ((block[7] & 0x0F) << 8)
    h_front_porch = block[8] | ((block[11] & 0xC0) << 2)
    h_sync_width = block[9] | ((block[11] & 0x30) << 4)
    v_front_porch = (block[10] >> 4) | ((block[11] & 0x0C) << 2)
    v_sync_width = (block[10] & 0x0F) | ((block[11] & 0x03) << 4)
    h_size_mm = block[12] | ((block[14] & 0xF0) << 4)
    v_size_mm = block[13] | ((block[14] & 0x0F) << 8)
    h_border = block[15]
    v_border = block[16]
    flags = block[17]
    return DetailedTiming(
        pixel_clock_khz=pixel_clock_khz,
        h_active=h_active,
        h_blank=h_blank,
        v_active=v_active,
        v_blank=v_blank,
        h_front_porch=h_front_porch,
        h_sync_width=h_sync_width,
        v_front_porch=v_front_porch,
        v_sync_width=v_sync_width,
        h_size_mm=h_size_mm,
        v_size_mm=v_size_mm,
        h_border=h_border,
        v_border=v_border,
        interlaced=bool(flags & 0x80),
        flags_raw=flags,
    )


def _parse_descriptor(block: bytes) -> DescriptorBlock:
    if len(block) != 18:
        return DescriptorBlock(kind="unknown", raw=bytes(block))

    if block[0] != 0 or block[1] != 0:
        timing = _parse_detailed_timing(block)
        return DescriptorBlock(
            kind="detailed_timing",
            raw=bytes(block),
            payload={"timing": timing},
            text=timing.short(),
        )

    tag = block[3]
    payload_bytes = bytes(block[5:18])

    if tag == 0xFF:
        return DescriptorBlock(
            kind="monitor_serial",
            raw=bytes(block),
            text=_trim_descriptor_text(payload_bytes),
        )
    if tag == 0xFE:
        return DescriptorBlock(
            kind="ascii_text",
            raw=bytes(block),
            text=_trim_descriptor_text(payload_bytes),
        )
    if tag == 0xFC:
        return DescriptorBlock(
            kind="monitor_name",
            raw=bytes(block),
            text=_trim_descriptor_text(payload_bytes),
        )
    if tag == 0xFD:
        # Range limits descriptor.
        return DescriptorBlock(
            kind="range_limits",
            raw=bytes(block),
            payload={
                "min_v_hz": payload_bytes[0],
                "max_v_hz": payload_bytes[1],
                "min_h_khz": payload_bytes[2],
                "max_h_khz": payload_bytes[3],
                "max_pixel_clock_mhz": payload_bytes[4] * 10,
            },
            text=(
                f"Range: V {payload_bytes[0]}-{payload_bytes[1]} Hz, "
                f"H {payload_bytes[2]}-{payload_bytes[3]} kHz, "
                f"Pixel clk <= {payload_bytes[4] * 10} MHz"
            ),
        )

    return DescriptorBlock(
        kind="unknown",
        raw=bytes(block),
        text=f"unknown descriptor tag 0x{tag:02X}",
    )


def _parse_chromaticity(data: bytes) -> dict:
    rg_lsb = data[25]
    bw_lsb = data[26]
    red_x = ((data[27] << 2) | ((rg_lsb >> 6) & 0x3)) / 1024.0
    red_y = ((data[28] << 2) | ((rg_lsb >> 4) & 0x3)) / 1024.0
    green_x = ((data[29] << 2) | ((rg_lsb >> 2) & 0x3)) / 1024.0
    green_y = ((data[30] << 2) | (rg_lsb & 0x3)) / 1024.0
    blue_x = ((data[31] << 2) | ((bw_lsb >> 6) & 0x3)) / 1024.0
    blue_y = ((data[32] << 2) | ((bw_lsb >> 4) & 0x3)) / 1024.0
    white_x = ((data[33] << 2) | ((bw_lsb >> 2) & 0x3)) / 1024.0
    white_y = ((data[34] << 2) | (bw_lsb & 0x3)) / 1024.0
    return {
        "red": (red_x, red_y),
        "green": (green_x, green_y),
        "blue": (blue_x, blue_y),
        "white": (white_x, white_y),
    }


def _parse_standard_timings(data: bytes) -> list[str]:
    timings: list[str] = []
    for offset in range(38, 54, 2):
        b0 = data[offset]
        b1 = data[offset + 1]
        if b0 == 0x01 and b1 == 0x01:
            continue
        h_active = (b0 + 31) * 8
        ratio_bits = (b1 >> 6) & 0x3
        refresh = (b1 & 0x3F) + 60
        ratio = ASPECT_RATIO[ratio_bits]
        if ratio == "16:10":
            v_active = h_active * 10 // 16
        elif ratio == "4:3":
            v_active = h_active * 3 // 4
        elif ratio == "5:4":
            v_active = h_active * 4 // 5
        else:
            v_active = h_active * 9 // 16
        timings.append(f"{h_active}x{v_active} @ {refresh} Hz ({ratio})")
    return timings


def _parse_cea_extension(block: bytes) -> dict:
    if len(block) != 128 or block[0] != 0x02:
        return {"present": False}
    revision = block[1]
    dtd_offset = block[2]
    flags = block[3]
    info = {
        "present": True,
        "revision": revision,
        "dtd_offset": dtd_offset,
        "underscan_supported": bool(flags & 0x80),
        "basic_audio_supported": bool(flags & 0x40),
        "ycbcr_444": bool(flags & 0x20),
        "ycbcr_422": bool(flags & 0x10),
        "native_dtd_count": flags & 0x0F,
        "data_blocks": [],
    }

    # Walk the data block collection, 4 <= offset < dtd_offset.
    i = 4
    while dtd_offset >= 4 and i < dtd_offset:
        if i >= len(block):
            break
        header = block[i]
        length = header & 0x1F
        tag = (header >> 5) & 0x07
        payload = bytes(block[i + 1:i + 1 + length])
        info["data_blocks"].append({
            "tag": tag,
            "tag_name": {
                1: "Audio",
                2: "Video",
                3: "Vendor-Specific",
                4: "Speaker",
                5: "VESA Display Transfer",
                7: "Extended",
            }.get(tag, f"Reserved-{tag}"),
            "length": length,
            "payload_hex": payload.hex(),
        })
        i += 1 + length

    # Detailed timings in extension start at dtd_offset, 18 bytes each, until 0x00.
    extension_dtds: list[str] = []
    if 4 <= dtd_offset < 127:
        j = dtd_offset
        while j + 18 <= 127:
            chunk = bytes(block[j:j + 18])
            if chunk[0] == 0 and chunk[1] == 0:
                break
            d = _parse_descriptor(chunk)
            if d.kind == "detailed_timing":
                extension_dtds.append(d.payload["timing"].short())
            else:
                extension_dtds.append(d.text)
            j += 18
    info["detailed_timings"] = extension_dtds
    return info


def decode_edid(data: bytes) -> DecodedEdid:
    if len(data) < 128:
        raise ValueError(f"EDID must be at least 128 bytes, got {len(data)}")

    base = data[:128]
    valid_header = base[:8] == EDID_HEADER
    checksum_ok = (sum(base) & 0xFF) == 0

    manufacturer = _decode_manufacturer(base[8], base[9])
    product_code = base[10] | (base[11] << 8)
    serial_number = base[12] | (base[13] << 8) | (base[14] << 16) | (base[15] << 24)
    week = base[16]
    year = 1990 + base[17]
    edid_version = (base[18], base[19])

    video_input = base[20]
    is_digital = bool(video_input & 0x80)
    if is_digital:
        depth_bits = (video_input >> 4) & 0x07
        iface_bits = video_input & 0x0F
        digital_color_depth = COLOR_DEPTH.get(depth_bits, "?")
        digital_interface = DIGITAL_INTERFACES.get(iface_bits, f"Reserved-{iface_bits}")
    else:
        digital_color_depth = "n/a (analog)"
        digital_interface = "n/a (analog)"

    h_size_cm = base[21]
    v_size_cm = base[22]
    gamma_raw = base[23]
    gamma = (gamma_raw + 100) / 100.0 if gamma_raw != 0xFF else None

    feat = base[24]
    features = {
        "standby_supported": bool(feat & 0x80),
        "suspend_supported": bool(feat & 0x40),
        "active_off_supported": bool(feat & 0x20),
        "color_format_or_type_bits": (feat >> 3) & 0x03,
        "srgb_default": bool(feat & 0x04),
        "preferred_timing_includes_refresh": bool(feat & 0x02),
        "continuous_frequency": bool(feat & 0x01),
    }

    chromaticity = _parse_chromaticity(base)

    et1 = base[35]
    et2 = base[36]
    et3 = base[37]
    established: list[str] = []
    for mask, label in ESTABLISHED_TIMING_I:
        if et1 & mask:
            established.append(label)
    for mask, label in ESTABLISHED_TIMING_II:
        if et2 & mask:
            established.append(label)
    for mask, label in ESTABLISHED_TIMING_III:
        if et3 & mask:
            established.append(label)

    standard_timings = _parse_standard_timings(base)

    descriptors = [
        _parse_descriptor(bytes(base[54:72])),
        _parse_descriptor(bytes(base[72:90])),
        _parse_descriptor(bytes(base[90:108])),
        _parse_descriptor(bytes(base[108:126])),
    ]

    extension_blocks = base[126]

    cea_blocks: list[dict] = []
    for ext_idx in range(extension_blocks):
        start = 128 * (ext_idx + 1)
        if start + 128 > len(data):
            break
        ext = bytes(data[start:start + 128])
        if ext[0] == 0x02:
            cea_blocks.append(_parse_cea_extension(ext))

    return DecodedEdid(
        raw=bytes(data),
        valid_header=valid_header,
        checksum_ok=checksum_ok,
        manufacturer=manufacturer,
        product_code=product_code,
        serial_number=serial_number,
        week=week,
        year=year,
        edid_version=edid_version,
        is_digital=is_digital,
        digital_color_depth=digital_color_depth,
        digital_interface=digital_interface,
        h_size_cm=h_size_cm,
        v_size_cm=v_size_cm,
        gamma=gamma,
        features=features,
        chromaticity=chromaticity,
        established_timings=established,
        standard_timings=standard_timings,
        descriptors=descriptors,
        extension_blocks=extension_blocks,
        cea_blocks=cea_blocks,
    )


def format_decoded(d: DecodedEdid) -> str:
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("EDID summary")
    lines.append("=" * 60)
    lines.append(f"Header valid:     {d.valid_header}")
    lines.append(f"Checksum OK:      {d.checksum_ok}")
    lines.append(f"Manufacturer:     {d.manufacturer}")
    lines.append(f"Product code:     0x{d.product_code:04X}")
    lines.append(f"Serial number:    {d.serial_number}")
    lines.append(f"Manufacture date: week {d.week} of {d.year}")
    lines.append(f"EDID version:     {d.edid_version[0]}.{d.edid_version[1]}")
    lines.append("")

    monitor_name = next(
        (b.text for b in d.descriptors if b.kind == "monitor_name"),
        "",
    )
    if not monitor_name:
        # Some panels skip the 0xFC tag and dump the model name in a 0xFE
        # "ASCII text" descriptor instead. Use the first one as a fallback.
        ascii_text = next(
            (b.text for b in d.descriptors if b.kind == "ascii_text" and b.text),
            "",
        )
        monitor_name = ascii_text or "(not provided)"
    monitor_serial = next(
        (b.text for b in d.descriptors if b.kind == "monitor_serial"),
        "(not provided)",
    )
    lines.append(f"Monitor name:     {monitor_name}")
    lines.append(f"Monitor serial:   {monitor_serial}")
    lines.append("")

    lines.append("Video input")
    lines.append("-" * 60)
    lines.append(f"  Type:           {'Digital' if d.is_digital else 'Analog'}")
    if d.is_digital:
        lines.append(f"  Color depth:    {d.digital_color_depth}")
        lines.append(f"  Interface:      {d.digital_interface}")
    if d.h_size_cm or d.v_size_cm:
        diag_in = ((d.h_size_cm ** 2 + d.v_size_cm ** 2) ** 0.5) / 2.54
        lines.append(
            f"  Screen size:    {d.h_size_cm} x {d.v_size_cm} cm "
            f"(~{diag_in:.1f} in)"
        )
    if d.gamma is not None:
        lines.append(f"  Gamma:          {d.gamma:.2f}")
    lines.append("")

    lines.append("Features")
    lines.append("-" * 60)
    for k, v in d.features.items():
        lines.append(f"  {k:36s} {v}")
    lines.append("")

    lines.append("Chromaticity (CIE 1931)")
    lines.append("-" * 60)
    for k, (x, y) in d.chromaticity.items():
        lines.append(f"  {k:6s} x={x:.4f} y={y:.4f}")
    lines.append("")

    lines.append("Established timings")
    lines.append("-" * 60)
    if d.established_timings:
        for t in d.established_timings:
            lines.append(f"  - {t}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("Standard timings")
    lines.append("-" * 60)
    if d.standard_timings:
        for t in d.standard_timings:
            lines.append(f"  - {t}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("Descriptor blocks")
    lines.append("-" * 60)
    for i, desc in enumerate(d.descriptors):
        prefix = f"  [{i}] {desc.kind}"
        if desc.kind == "detailed_timing" and "timing" in desc.payload:
            t: DetailedTiming = desc.payload["timing"]
            lines.append(prefix + f": {t.short()}")
            lines.append(
                f"        H: active={t.h_active} blank={t.h_blank} "
                f"front={t.h_front_porch} sync={t.h_sync_width}"
            )
            lines.append(
                f"        V: active={t.v_active} blank={t.v_blank} "
                f"front={t.v_front_porch} sync={t.v_sync_width}"
            )
            if t.h_size_mm or t.v_size_mm:
                lines.append(
                    f"        Image size: {t.h_size_mm} x {t.v_size_mm} mm"
                )
        else:
            lines.append(prefix + (f": {desc.text}" if desc.text else ""))
    lines.append("")

    lines.append("Extensions")
    lines.append("-" * 60)
    lines.append(f"  Extension blocks: {d.extension_blocks}")
    for i, cea in enumerate(d.cea_blocks):
        lines.append("")
        lines.append(f"  CEA-861 block #{i}")
        lines.append(f"    revision:               {cea.get('revision')}")
        lines.append(f"    dtd offset:             {cea.get('dtd_offset')}")
        lines.append(f"    native DTDs:            {cea.get('native_dtd_count')}")
        lines.append(f"    underscan supported:    {cea.get('underscan_supported')}")
        lines.append(f"    basic audio supported:  {cea.get('basic_audio_supported')}")
        lines.append(f"    YCbCr 4:4:4 supported:  {cea.get('ycbcr_444')}")
        lines.append(f"    YCbCr 4:2:2 supported:  {cea.get('ycbcr_422')}")
        for blk in cea.get("data_blocks", []):
            lines.append(
                f"    data block tag={blk['tag']} ({blk['tag_name']}) "
                f"len={blk['length']} payload={blk['payload_hex']}"
            )
        for t in cea.get("detailed_timings", []):
            lines.append(f"    detailed timing: {t}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 3. Reusable Qt widget (works embedded in a larger app, e.g. issues-tracker)
# ---------------------------------------------------------------------------

try:
    from PySide6 import QtCore, QtGui, QtWidgets  # noqa: E402
    _HAS_QT = True
except Exception:  # pragma: no cover - pyside6 optional for the lib path
    _HAS_QT = False


if _HAS_QT:

    class EdidWidget(QtWidgets.QWidget):
        """Self-contained "paste OR load file" EDID input + decoder view.

        Signals:
            decoded(DecodedEdid): emitted on a successful decode.
            errored(str):         emitted with a human-readable error string.
        """

        decoded = QtCore.Signal(object)
        errored = QtCore.Signal(str)

        def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
            super().__init__(parent)

            outer = QtWidgets.QVBoxLayout(self)

            help_lbl = QtWidgets.QLabel(
                "Paste raw EDID bytes below (any common hex format), "
                "or load from a file. Then click Decode."
            )
            help_lbl.setWordWrap(True)
            outer.addWidget(help_lbl)

            self.input_edit = QtWidgets.QPlainTextEdit()
            self.input_edit.setPlaceholderText(
                "Examples accepted:\n"
                "  00 FF FF FF FF FF FF 00 ...\n"
                "  00FFFFFFFFFFFF00...\n"
                "  0x00, 0xFF, 0xFF, ...\n"
                "  output of `xxd file.bin` or `hexdump -C file.bin`"
            )
            self.input_edit.setMinimumHeight(140)
            outer.addWidget(self.input_edit)

            btn_row = QtWidgets.QHBoxLayout()
            self.load_btn = QtWidgets.QPushButton("Load from File...")
            self.decode_btn = QtWidgets.QPushButton("Decode")
            self.decode_btn.setDefault(True)
            self.copy_btn = QtWidgets.QPushButton("Copy Decoded")
            self.clear_btn = QtWidgets.QPushButton("Clear")
            btn_row.addWidget(self.load_btn)
            btn_row.addWidget(self.decode_btn)
            btn_row.addWidget(self.copy_btn)
            btn_row.addWidget(self.clear_btn)
            btn_row.addStretch(1)
            outer.addLayout(btn_row)

            self.status_lbl = QtWidgets.QLabel("")
            self.status_lbl.setStyleSheet("color: #b00;")
            outer.addWidget(self.status_lbl)

            self.output_edit = QtWidgets.QPlainTextEdit()
            self.output_edit.setReadOnly(True)
            mono = QtGui.QFont("Consolas")
            mono.setStyleHint(QtGui.QFont.Monospace)
            self.output_edit.setFont(mono)
            outer.addWidget(self.output_edit, 1)

            self.load_btn.clicked.connect(self.on_load_file)
            self.decode_btn.clicked.connect(self.on_decode)
            self.copy_btn.clicked.connect(self.on_copy)
            self.clear_btn.clicked.connect(self.on_clear)

        @QtCore.Slot()
        def on_load_file(self) -> None:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self,
                "Open EDID file",
                "",
                "EDID files (*.edid *.bin *.txt);;All files (*)",
            )
            if not path:
                return
            try:
                raw = Path(path).read_bytes()
                # If the file looks like text (mostly printable ASCII), treat
                # as a hex dump; otherwise show as hex for the user to confirm.
                if all(b in b"\r\n\t " or 32 <= b < 127 for b in raw[:256]):
                    self.input_edit.setPlainText(raw.decode("ascii", "replace"))
                else:
                    self.input_edit.setPlainText(
                        " ".join(f"{b:02X}" for b in raw)
                    )
                self.status_lbl.setText(f"Loaded {len(raw)} byte(s) from {path}")
                self.status_lbl.setStyleSheet("color: #060;")
            except Exception as exc:  # pylint: disable=broad-except
                self.status_lbl.setStyleSheet("color: #b00;")
                self.status_lbl.setText(f"Failed to load file: {exc}")
                self.errored.emit(str(exc))

        @QtCore.Slot()
        def on_decode(self) -> None:
            text = self.input_edit.toPlainText()
            try:
                # Either pure hex paste, or a path the user typed/dragged in.
                stripped = text.strip()
                if (
                    "\n" not in stripped
                    and len(stripped) < 260
                    and Path(stripped).expanduser().is_file()
                ):
                    raw = Path(stripped).expanduser().read_bytes()
                    if all(b in b"\r\n\t " or 32 <= b < 127 for b in raw[:256]):
                        data = parse_hex_dump(raw.decode("ascii", "replace"))
                    else:
                        data = raw
                else:
                    data = parse_hex_dump(text)

                decoded = decode_edid(data)
                self.output_edit.setPlainText(format_decoded(decoded))
                msgs: list[str] = [f"Decoded {len(data)} bytes."]
                if not decoded.valid_header:
                    msgs.append("WARNING: header magic mismatch")
                if not decoded.checksum_ok:
                    msgs.append("WARNING: base block checksum mismatch")
                color = "#060" if decoded.valid_header and decoded.checksum_ok else "#b80"
                self.status_lbl.setStyleSheet(f"color: {color};")
                self.status_lbl.setText("  ".join(msgs))
                self.decoded.emit(decoded)
            except Exception as exc:  # pylint: disable=broad-except
                self.output_edit.setPlainText("")
                self.status_lbl.setStyleSheet("color: #b00;")
                self.status_lbl.setText(f"Decode failed: {exc}")
                self.errored.emit(str(exc))

        @QtCore.Slot()
        def on_copy(self) -> None:
            QtWidgets.QApplication.clipboard().setText(self.output_edit.toPlainText())
            self.status_lbl.setStyleSheet("color: #060;")
            self.status_lbl.setText("Decoded output copied to clipboard.")

        @QtCore.Slot()
        def on_clear(self) -> None:
            self.input_edit.clear()
            self.output_edit.clear()
            self.status_lbl.clear()


    class _StandaloneWindow(QtWidgets.QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("EDID Viewer")
            self.resize(900, 700)
            self.widget = EdidWidget(self)
            self.setCentralWidget(self.widget)


def main() -> int:
    if not _HAS_QT:
        print(
            "PySide6 is required to run the GUI. Install with: pip install pyside6",
            file=sys.stderr,
        )
        return 2
    app = QtWidgets.QApplication(sys.argv)
    win = _StandaloneWindow()

    # Pre-load the project's edid file as a convenience if it exists.
    project_edid = Path(__file__).with_name("edid")
    if project_edid.is_file():
        try:
            text = project_edid.read_text(encoding="ascii", errors="replace")
            win.widget.input_edit.setPlainText(text)
            win.widget.status_lbl.setText(
                f"Pre-loaded {project_edid.name}. Click Decode."
            )
            win.widget.status_lbl.setStyleSheet("color: #060;")
        except Exception:
            pass

    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

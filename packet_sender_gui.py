#!/usr/bin/env python3
"""
LAN8720 packet sender GUI (PySide6 + Scapy).

Install dependencies:
  pip install pyside6 scapy

Notes:
  - Windows packet send/sniff usually requires Npcap.
  - Run as Administrator if your interface blocks raw access.
"""

from __future__ import annotations

import binascii
import re
import sys
import threading
import time
from dataclasses import dataclass

from PySide6 import QtCore
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)
from scapy.all import AsyncSniffer, Ether, Raw, get_if_hwaddr, get_if_list, sendp
from scapy.arch.windows import get_windows_if_list


MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def normalize_mac(text: str) -> str:
    value = text.strip().replace("-", ":").lower()
    parts = value.split(":")
    if len(parts) != 6:
        raise ValueError("MAC must have 6 bytes")
    for part in parts:
        if len(part) != 2:
            raise ValueError("Each MAC byte must be 2 hex chars")
        int(part, 16)
    return ":".join(parts)


def is_valid_mac(text: str) -> bool:
    return bool(MAC_RE.fullmatch(text.strip().lower()))


def extract_guid(text: str) -> str:
    match = re.search(r"\{([0-9a-fA-F\-]+)\}", text)
    if not match:
        return ""
    return match.group(1).lower()


def parse_payload(text: str, mode: str) -> bytes:
    if mode == "ASCII":
        return text.encode("utf-8", errors="replace")
    clean = text.replace(" ", "").replace("\n", "").replace("\r", "")
    if clean == "":
        return b""
    if len(clean) % 2 != 0:
        raise ValueError("HEX payload must have even length")
    try:
        return binascii.unhexlify(clean)
    except binascii.Error as exc:
        raise ValueError(f"Invalid HEX payload: {exc}") from exc


@dataclass
class SendConfig:
    iface: str
    src_mac: str
    dst_mac: str
    ethertype: int
    payload: bytes
    count: int
    interval_s: float
    sniff_seconds: float
    receive_only: bool = False
    hide_self_tx: bool = True


class SenderWorker(QtCore.QObject):
    log = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(self, cfg: SendConfig) -> None:
        super().__init__()
        self.cfg = cfg
        self._stop = False

    @QtCore.Slot()
    def run(self) -> None:
        sniffer: AsyncSniffer | None = None
        active_bpf = ""
        self_mac = self.cfg.src_mac.lower()
        peer_count = 0
        self_count = 0
        try:
            self.log.emit(f"[INFO] Interface: {self.cfg.iface}")
            if self.cfg.receive_only:
                self.log.emit(
                    f"[INFO] Receive-only mode: listening for ethertype=0x{self.cfg.ethertype:04x} "
                    f"(no TX). Anything NOT from {self_mac} is a real peer frame."
                )
            else:
                self.log.emit(
                    f"[INFO] Sending {self.cfg.count} frame(s), ethertype=0x{self.cfg.ethertype:04x}, "
                    f"payload={len(self.cfg.payload)} B"
                )
                if self.cfg.hide_self_tx:
                    self.log.emit(
                        "[INFO] Self-TX frames will be suppressed (your own outbound copies "
                        "are hidden). Only frames from OTHER MACs will be logged as [RX]."
                    )

            def on_packet(pkt) -> None:
                nonlocal peer_count, self_count
                if Ether not in pkt:
                    return
                eth = pkt[Ether]
                src_l = str(eth.src).lower()
                is_self = (src_l == self_mac)
                if is_self:
                    self_count += 1
                    if self.cfg.hide_self_tx:
                        return
                    tag = "[RX-self]"
                else:
                    peer_count += 1
                    tag = "[RX-peer]"
                line = (
                    f"{tag} src={eth.src} dst={eth.dst} type=0x{eth.type:04x} "
                    f"len={len(bytes(pkt))}"
                )
                self.log.emit(line)

            if self.cfg.sniff_seconds > 0 or self.cfg.receive_only:
                base_bpf = f"ether proto 0x{self.cfg.ethertype:04x}"
                # Some Windows/Npcap adapters accept inbound/outbound qualifiers
                # inconsistently; prefer generic filter first for reliability.
                bpf_candidates = [base_bpf, f"inbound and {base_bpf}"]
                started = False
                last_exc: Exception | None = None
                for bpf in bpf_candidates:
                    try:
                        sniffer = AsyncSniffer(iface=self.cfg.iface, filter=bpf, prn=on_packet, store=False)
                        sniffer.start()
                        active_bpf = bpf
                        self.log.emit(f"[INFO] Sniffer started (filter: {bpf})")
                        if bpf.startswith("inbound and "):
                            self.log.emit("[INFO] Inbound-only capture enabled (TX self-capture reduced).")
                        else:
                            self.log.emit("[INFO] Using generic capture filter (driver-compatible mode).")
                        started = True
                        break
                    except Exception as exc:  # pylint: disable=broad-except
                        last_exc = exc
                        sniffer = None
                if not started:
                    raise RuntimeError(f"Failed to start sniffer: {last_exc}")

            if self.cfg.receive_only:
                deadline = time.monotonic() + self.cfg.sniff_seconds if self.cfg.sniff_seconds > 0 else None
                while not self._stop:
                    if deadline is not None and time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
            else:
                frame = Ether(src=self.cfg.src_mac, dst=self.cfg.dst_mac, type=self.cfg.ethertype) / Raw(self.cfg.payload)
                for index in range(self.cfg.count):
                    if self._stop:
                        self.log.emit("[INFO] Send stopped by user.")
                        break
                    sendp(frame, iface=self.cfg.iface, verbose=False)
                    self.log.emit(f"[TX] #{index + 1} src={self.cfg.src_mac} dst={self.cfg.dst_mac}")
                    if self.cfg.interval_s > 0 and index + 1 < self.cfg.count:
                        time.sleep(self.cfg.interval_s)

                if sniffer is not None:
                    self.log.emit(f"[INFO] Waiting {self.cfg.sniff_seconds:.2f}s for replies...")
                    end = time.monotonic() + self.cfg.sniff_seconds
                    while time.monotonic() < end and not self._stop:
                        time.sleep(0.05)
        except Exception as exc:  # pylint: disable=broad-except
            self.log.emit(f"[ERROR] {exc}")
        finally:
            if sniffer is not None:
                try:
                    sniffer.stop()
                    self.log.emit("[INFO] Sniffer stopped.")
                except Exception as exc:  # pylint: disable=broad-except
                    msg = str(exc)
                    if "inbound/outbound not supported on Ethernet" in msg and active_bpf.startswith("inbound and "):
                        self.log.emit(
                            "[INFO] Sniffer stop quirk: adapter does not fully support inbound/outbound qualifiers."
                        )
                        self.log.emit("[INFO] Capture finished anyway; results before stop remain valid.")
                    else:
                        self.log.emit(f"[WARN] Failed to stop sniffer cleanly: {exc}")
            self.log.emit(
                f"[INFO] Capture summary: peer frames = {peer_count}, self-TX echoes = {self_count}"
            )
            if peer_count == 0 and self_count > 0 and not self.cfg.receive_only:
                self.log.emit(
                    "[HINT] Zero peer frames. The FPGA did NOT send anything back. "
                    "Everything you saw was your own TX looped by Npcap. "
                    "Check: RMII REF_CLK, PHY NRST, link LEDs on the LAN8720 module."
                )
            self.finished.emit()

    def stop(self) -> None:
        self._stop = True


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("LAN8720 Packet Sender")
        self.resize(860, 640)
        self.settings = QtCore.QSettings("fpga_project", "lan8720_packet_sender")

        self._thread: QtCore.QThread | None = None
        self._worker: SenderWorker | None = None

        central = QWidget(self)
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        form = QFormLayout()
        layout.addLayout(form)

        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumContentsLength(48)
        self.refresh_btn = QPushButton("Refresh Interfaces")
        iface_row = QHBoxLayout()
        iface_row.addWidget(self.iface_combo, 1)
        iface_row.addWidget(self.refresh_btn)
        form.addRow("Interface", iface_row)

        self.preset_combo = QComboBox()
        self.preset_combo.addItems(
            [
                "Broadcast Echo Test (Recommended)",
                "Custom",
            ]
        )
        self.apply_preset_btn = QPushButton("Apply Preset")
        preset_row = QHBoxLayout()
        preset_row.addWidget(self.preset_combo, 1)
        preset_row.addWidget(self.apply_preset_btn)
        form.addRow("Preset", preset_row)

        self.src_mac_edit = QLineEdit()
        self.src_mac_auto_btn = QPushButton("Use Interface MAC")
        src_row = QHBoxLayout()
        src_row.addWidget(self.src_mac_edit, 1)
        src_row.addWidget(self.src_mac_auto_btn)
        form.addRow("Source MAC", src_row)

        self.dst_mac_edit = QLineEdit("ff:ff:ff:ff:ff:ff")
        form.addRow("Destination MAC", self.dst_mac_edit)

        self.ethertype_edit = QLineEdit("88B5")
        form.addRow("Ethertype (hex)", self.ethertype_edit)

        self.payload_mode = QComboBox()
        self.payload_mode.addItems(["ASCII", "HEX"])
        form.addRow("Payload Mode", self.payload_mode)

        self.payload_edit = QPlainTextEdit("HELLO_LAN8720")
        self.payload_edit.setFixedHeight(90)
        form.addRow("Payload", self.payload_edit)

        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, 100000)
        self.count_spin.setValue(10)
        form.addRow("Packet Count", self.count_spin)

        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setRange(0.0, 5.0)
        self.interval_spin.setDecimals(3)
        self.interval_spin.setSingleStep(0.01)
        self.interval_spin.setValue(0.05)
        form.addRow("Interval (s)", self.interval_spin)

        self.sniff_spin = QDoubleSpinBox()
        self.sniff_spin.setRange(0.0, 30.0)
        self.sniff_spin.setDecimals(2)
        self.sniff_spin.setSingleStep(0.25)
        self.sniff_spin.setValue(2.0)
        form.addRow("Sniff Window (s)", self.sniff_spin)

        self.recv_only_chk = QCheckBox("Receive-only (don't transmit; just listen)")
        self.recv_only_chk.setChecked(False)
        form.addRow("", self.recv_only_chk)

        self.hide_self_chk = QCheckBox(
            "Hide self-TX echoes (recommended: only shows frames that did NOT come from this PC)"
        )
        self.hide_self_chk.setChecked(True)
        form.addRow("", self.hide_self_chk)

        button_row = QHBoxLayout()
        layout.addLayout(button_row)
        self.send_btn = QPushButton("Send")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("Clear Log")
        button_row.addWidget(self.send_btn)
        button_row.addWidget(self.stop_btn)
        button_row.addWidget(self.clear_btn)
        button_row.addStretch(1)

        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box, 1)

        self.refresh_btn.clicked.connect(self.refresh_interfaces)
        self.apply_preset_btn.clicked.connect(self.apply_selected_preset)
        self.src_mac_auto_btn.clicked.connect(lambda: self.auto_fill_source_mac(force=True))
        self.send_btn.clicked.connect(self.on_send)
        self.stop_btn.clicked.connect(self.on_stop)
        self.clear_btn.clicked.connect(self.log_box.clear)

        self.refresh_interfaces()
        if not self.load_settings():
            self.apply_selected_preset()

    def append_log(self, line: str) -> None:
        self.log_box.appendPlainText(line)

    def refresh_interfaces(self) -> None:
        current_data = self.iface_combo.currentData()
        current_iface = current_data["iface"] if isinstance(current_data, dict) else ""
        self.iface_combo.clear()
        entries = self.build_iface_entries()
        for entry in entries:
            self.iface_combo.addItem(entry["label"], entry)

        if current_iface:
            for idx in range(self.iface_combo.count()):
                data = self.iface_combo.itemData(idx)
                if isinstance(data, dict) and data.get("iface") == current_iface:
                    self.iface_combo.setCurrentIndex(idx)
                    break
        elif self.iface_combo.count() > 0:
            # Prefer non-loopback interface for typical LAN8720 cable setup.
            selected = 0
            for idx in range(self.iface_combo.count()):
                data = self.iface_combo.itemData(idx)
                iface = data.get("iface", "").lower() if isinstance(data, dict) else ""
                label = data.get("label", "").lower() if isinstance(data, dict) else ""
                if "loopback" not in iface and "loopback" not in label:
                    selected = idx
                    break
            self.iface_combo.setCurrentIndex(selected)

        self.auto_fill_source_mac(force=False)

    def build_iface_entries(self) -> list[dict]:
        raw_ifaces = get_if_list()
        win_info: dict[str, dict] = {}
        try:
            for item in get_windows_if_list():
                guid = str(item.get("guid", "")).strip("{}").lower()
                if guid:
                    win_info[guid] = item
        except Exception:
            pass

        entries: list[dict] = []
        for iface in raw_ifaces:
            guid = extract_guid(iface)
            info = win_info.get(guid, {})
            desc = str(info.get("description", "")).strip()
            mac = str(info.get("mac", "")).strip().lower()
            ips = info.get("ips", [])
            ip_txt = ""
            if isinstance(ips, list) and ips:
                ip_txt = str(ips[0])
            label_parts = [desc if desc else iface]
            if ip_txt:
                label_parts.append(ip_txt)
            label = " | ".join(label_parts)
            entries.append({"label": label, "iface": iface, "mac": mac})
        return entries

    def set_interface_by_name(self, iface_name: str) -> bool:
        if iface_name == "":
            return False
        for idx in range(self.iface_combo.count()):
            data = self.iface_combo.itemData(idx)
            if isinstance(data, dict) and data.get("iface") == iface_name:
                self.iface_combo.setCurrentIndex(idx)
                return True
        return False

    def load_settings(self) -> bool:
        iface = str(self.settings.value("iface", "", str))
        preset = str(self.settings.value("preset", "", str))
        src_mac = str(self.settings.value("src_mac", "", str))
        dst_mac = str(self.settings.value("dst_mac", "", str))
        ethertype = str(self.settings.value("ethertype", "", str))
        payload_mode = str(self.settings.value("payload_mode", "", str))
        payload_text = str(self.settings.value("payload", "", str))
        count = int(self.settings.value("count", 10))
        interval = float(self.settings.value("interval", 0.05))
        sniff = float(self.settings.value("sniff_window", 2.0))

        restored_any = False
        if iface and self.set_interface_by_name(iface):
            restored_any = True
        if preset and self.preset_combo.findText(preset) >= 0:
            self.preset_combo.setCurrentText(preset)
            restored_any = True
        if src_mac:
            self.src_mac_edit.setText(src_mac)
            restored_any = True
        if dst_mac:
            self.dst_mac_edit.setText(dst_mac)
            restored_any = True
        if ethertype:
            self.ethertype_edit.setText(ethertype)
            restored_any = True
        if payload_mode and self.payload_mode.findText(payload_mode) >= 0:
            self.payload_mode.setCurrentText(payload_mode)
            restored_any = True
        if payload_text:
            self.payload_edit.setPlainText(payload_text)
            restored_any = True
        self.count_spin.setValue(max(1, min(count, self.count_spin.maximum())))
        self.interval_spin.setValue(max(0.0, min(interval, self.interval_spin.maximum())))
        self.sniff_spin.setValue(max(0.0, min(sniff, self.sniff_spin.maximum())))

        recv_only = self.settings.value("receive_only", False)
        hide_self = self.settings.value("hide_self_tx", True)
        if isinstance(recv_only, str):
            recv_only = recv_only.lower() in ("true", "1", "yes")
        if isinstance(hide_self, str):
            hide_self = hide_self.lower() in ("true", "1", "yes")
        self.recv_only_chk.setChecked(bool(recv_only))
        self.hide_self_chk.setChecked(bool(hide_self))
        return restored_any

    def save_settings(self) -> None:
        data = self.iface_combo.currentData()
        iface = data.get("iface", "") if isinstance(data, dict) else self.iface_combo.currentText().strip()
        self.settings.setValue("iface", iface)
        self.settings.setValue("preset", self.preset_combo.currentText())
        self.settings.setValue("src_mac", self.src_mac_edit.text().strip())
        self.settings.setValue("dst_mac", self.dst_mac_edit.text().strip())
        self.settings.setValue("ethertype", self.ethertype_edit.text().strip())
        self.settings.setValue("payload_mode", self.payload_mode.currentText())
        self.settings.setValue("payload", self.payload_edit.toPlainText())
        self.settings.setValue("count", self.count_spin.value())
        self.settings.setValue("interval", self.interval_spin.value())
        self.settings.setValue("sniff_window", self.sniff_spin.value())
        self.settings.setValue("receive_only", self.recv_only_chk.isChecked())
        self.settings.setValue("hide_self_tx", self.hide_self_chk.isChecked())
        self.settings.sync()

    def auto_fill_source_mac(self, force: bool) -> None:
        current = self.src_mac_edit.text().strip()
        if current and not force:
            return

        data = self.iface_combo.currentData()
        iface = data.get("iface", "") if isinstance(data, dict) else self.iface_combo.currentText().strip()
        mac_guess = data.get("mac", "") if isinstance(data, dict) else ""
        if is_valid_mac(mac_guess):
            self.src_mac_edit.setText(mac_guess)
            return
        try:
            maybe_mac = get_if_hwaddr(iface).strip().lower()
            if is_valid_mac(maybe_mac):
                self.src_mac_edit.setText(maybe_mac)
                return
        except Exception:
            pass
        self.src_mac_edit.setText("02:12:34:56:78:9a")

    def apply_selected_preset(self) -> None:
        preset = self.preset_combo.currentText()
        if preset != "Broadcast Echo Test (Recommended)":
            return
        self.dst_mac_edit.setText("ff:ff:ff:ff:ff:ff")
        self.ethertype_edit.setText("88B5")
        self.payload_mode.setCurrentText("ASCII")
        self.payload_edit.setPlainText("HELLO_LAN8720")
        self.count_spin.setValue(10)
        self.interval_spin.setValue(0.05)
        self.sniff_spin.setValue(2.0)
        self.auto_fill_source_mac(force=False)

    def build_config(self) -> SendConfig:
        data = self.iface_combo.currentData()
        if isinstance(data, dict):
            iface = str(data.get("iface", "")).strip()
        else:
            iface = self.iface_combo.currentText().strip()
        if iface == "":
            raise ValueError("Choose a network interface")

        src_mac = normalize_mac(self.src_mac_edit.text())
        dst_mac = normalize_mac(self.dst_mac_edit.text())

        ethertype_txt = self.ethertype_edit.text().strip().lower().replace("0x", "")
        if ethertype_txt == "":
            raise ValueError("Ethertype cannot be empty")
        ethertype = int(ethertype_txt, 16)
        if not (0 <= ethertype <= 0xFFFF):
            raise ValueError("Ethertype must be 0..FFFF")

        payload = parse_payload(self.payload_edit.toPlainText(), self.payload_mode.currentText())
        return SendConfig(
            iface=iface,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ethertype=ethertype,
            payload=payload,
            count=self.count_spin.value(),
            interval_s=self.interval_spin.value(),
            sniff_seconds=self.sniff_spin.value(),
            receive_only=self.recv_only_chk.isChecked(),
            hide_self_tx=self.hide_self_chk.isChecked(),
        )

    def set_running(self, running: bool) -> None:
        self.send_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running)
        self.refresh_btn.setEnabled(not running)

    def on_send(self) -> None:
        try:
            cfg = self.build_config()
        except Exception as exc:  # pylint: disable=broad-except
            QMessageBox.critical(self, "Invalid Input", str(exc))
            return

        self.append_log("=" * 72)
        self.append_log("[INFO] Starting packet send job...")

        self._thread = QtCore.QThread(self)
        self._worker = SenderWorker(cfg)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(self.append_log)
        self._worker.finished.connect(self.on_worker_finished)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()
        self.set_running(True)

    def on_stop(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self.append_log("[INFO] Stop requested.")

    def on_worker_finished(self) -> None:
        self.append_log("[INFO] Job finished.")
        self.set_running(False)
        self._worker = None
        self._thread = None

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self.save_settings()
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    # Ensure Scapy does not fight with Qt over the same interpreter shutdown path.
    threading.current_thread().name = "main"
    raise SystemExit(main())

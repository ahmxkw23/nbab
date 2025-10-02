# nbab_ready_buttons.py
import sys
import re
import shutil
import shlex
import threading
import urllib.parse
from datetime import datetime
import json
from pathlib import Path

import nmap
from PyQt6 import QtCore
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QUrl, QTimer, QRectF
from PyQt6.QtGui import (
    QPalette, QColor, QDesktopServices, QIcon,
    QPainter, QPen, QBrush, QFontMetrics, QPixmap
)
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox,
    QFileDialog, QMessageBox, QTabWidget, QTreeWidget, QTreeWidgetItem, QSpinBox,
    QSizePolicy, QProgressBar, QAbstractSpinBox, QScrollArea
)

PORTS_RE = re.compile(r"^(\d+(-\d+)?)(,(\d+(-\d+)?))*$")

def nmap_available() -> bool:
    return shutil.which("nmap") is not None

class ScanSignals(QObject):
    log = pyqtSignal(str)
    done = pyqtSignal()
    error = pyqtSignal(str)
    results = pyqtSignal(object)

class NmapWorker(threading.Thread):
    def __init__(self, target: str, ports: str, args: str, signals: ScanSignals):
        super().__init__(daemon=True)
        self.target = target.strip()
        self.ports = ports.strip()
        self.args = args
        self.signals = signals

    def run(self):
        try:
            nm = nmap.PortScanner()
            start_ts = datetime.now()
            self.signals.log.emit(f"[+] Scan started {start_ts:%Y-%m-%d %H:%M:%S}\n")
            self.signals.log.emit(f"[+] Target: {self.target}\n[+] Ports: {self.ports or 'Default (Top 1000)'}\n[+] Options: {self.args or '(None)'}\n\n")

            nm.scan(self.target, self.ports if self.ports else None, arguments=self.args)

            out_lines = []
            rows = []
            for host in nm.all_hosts():
                out_lines.append(f"Host: {host} | State: {nm[host].state()}")
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        svc = nm[host][proto][port]
                        state = svc.get('state', '')
                        name = svc.get('name', '')
                        product = svc.get('product', '')
                        version = svc.get('version', '')
                        extr = ' '.join(x for x in [name, product, version] if x)
                        line = f"  - {proto.upper()} {port:>5}: {state}"
                        if extr:
                            line += f" | {extr}"
                        out_lines.append(line)
                        rows.append({
                            'host': host,
                            'proto': proto,
                            'port': port,
                            'state': state,
                            'service': name,
                            'product': product,
                            'version': version,
                        })
                out_lines.append("")

            if not out_lines:
                out_lines.append("No results. Check target or permissions.")

            end_ts = datetime.now()
            dur = (end_ts - start_ts).total_seconds()
            out = "\n".join(out_lines)
            self.signals.results.emit(rows)
            self.signals.log.emit(out + f"\n[✓] Scan finished in {dur:.1f} seconds\n")
            self.signals.done.emit()

        except nmap.PortScannerError as e:
            self.signals.error.emit("Could not run nmap. Make sure it is installed and in PATH.\n" f"Details: {e}")
        except Exception as e:
            self.signals.error.emit(f"Unexpected error: {e}")

class Switch(QCheckBox):
    """
    iOS-style toggle switch replacing QCheckBox visuals.
    - ON: blue track with white knob (right)
    - OFF: dark track with white knob (left)
    - DISABLED: gray variants
    """
    def __init__(self, text='', parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._w = 46
        self._h = 26
        self._pad = 3
        self.setMinimumHeight(max(self._h, 24))

    def sizeHint(self):
        fm = QFontMetrics(self.font())
        text_w = fm.horizontalAdvance(self.text()) if self.text() else 0
        return super().sizeHint().expandedTo(
            QtCore.QSize(self._w + (8 if text_w else 0) + text_w, self._h)
        )

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        x0, y0 = 0, (self.height() - self._h) // 2
        track_rect = QRectF(x0, y0, self._w, self._h)
        r = self._h / 2.0

        is_on = self.isChecked()
        is_en = self.isEnabled()

        if is_on and is_en:
            track_color = QColor("#3b82f6")
            border_color = QColor("#2563eb")
            knob_x = x0 + self._w - self._h + self._pad
        elif is_on and not is_en:
            track_color = QColor("#6b7280")
            border_color = QColor("#4b5563")
            knob_x = x0 + self._w - self._h + self._pad
        elif not is_en:
            track_color = QColor("#4b5563")
            border_color = QColor("#374151")
            knob_x = x0 + self._pad
        else:
            track_color = QColor("#2a2f45")
            border_color = QColor("#20263a")
            knob_x = x0 + self._pad

        painter.setPen(QPen(border_color, 1))
        painter.setBrush(QBrush(track_color))
        painter.drawRoundedRect(track_rect, r, r)

        knob_d = self._h - 2 * self._pad
        knob_rect = QRectF(knob_x, y0 + self._pad, knob_d, knob_d)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(Qt.GlobalColor.white if is_en else QColor("#e5e7eb")))
        painter.drawEllipse(knob_rect)

        if self.text():
            fm = QFontMetrics(self.font())
            text_x = x0 + self._w + 8
            text_y = (self.height() + fm.ascent() - fm.descent()) // 2
            painter.setPen(QColor("#cfd3e1") if is_en else QColor("#6b7280"))
            painter.drawText(text_x, text_y, self.text())

        painter.end()

# Make every QCheckBox render as a Switch in this module
QCheckBox = Switch

class NmapGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("N-Bab")
        self.setGeometry(200, 200, 980, 720)
        self.setWindowIcon(QIcon("assets/icon.png"))

        self.apply_dark_theme()

        self.worker: NmapWorker | None = None
        self.signals = ScanSignals()
        self.signals.log.connect(self.append_log)
        self.signals.done.connect(self.on_done)
        self.signals.error.connect(self.on_error)
        self.signals.results.connect(self.load_results_table)

        # Track scanning state
        self.scanning = False

        # --- Wrap entire UI in a scroll area so results/logs remain reachable even
        # when Advanced Options are expanded ---
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        root = QVBoxLayout(container)
        root.setSpacing(14)
        root.setContentsMargins(16, 16, 16, 16)

                # Title row with icon + text
        title_row = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(QPixmap("assets/icon.png").scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        title_row.addWidget(icon_label)

        title = QLabel("N-Bab Addon")
        title.setAlignment(Qt.AlignmentFlag.AlignLeft)
        title.setStyleSheet("QLabel { font-size: 22px; font-weight: 700; letter-spacing: .5px; }")

        title_row.addWidget(title)
        title_row.addStretch()
        root.addLayout(title_row)


        # Row: Target & Ports
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Target (IP/Domain):"))
        self.in_target = QLineEdit()
        self.in_target.setPlaceholderText("e.g. 192.168.1.1 or scanme.nmap.org")
        row1.addWidget(self.in_target, 2)
        row1.addWidget(QLabel("Ports:"))
        self.in_ports = QLineEdit()
        self.in_ports.setPlaceholderText("e.g. 1-1024 or 22,80,443")
        row1.addWidget(self.in_ports, 1)
        root.addLayout(row1)

        # Row: Scan type & basics
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Scan Types:"))
        self.chk_sS = QCheckBox("-sS (TCP SYN)")
        self.chk_sT = QCheckBox("-sT (TCP Connect)")
        self.chk_sU = QCheckBox("-sU (UDP)")
        self.chk_sS.setChecked(True)
        row2.addWidget(self.chk_sS)
        row2.addWidget(self.chk_sT)
        row2.addWidget(self.chk_sU)

        self.chk_sv = QCheckBox("-sV Version Detection")
        self.chk_os = QCheckBox("-O OS Detection")
        self.chk_A = QCheckBox("-A Aggressive Scan")
        row2.addWidget(self.chk_sv)
        row2.addWidget(self.chk_os)
        row2.addWidget(self.chk_A)
        root.addLayout(row2)

        # Profile selector
        row_profile = QHBoxLayout()
        row_profile.addWidget(QLabel("Preset:"))
        self.cb_profile = QComboBox()
        self.cb_profile.addItems(["(None)", "Quick Scan", "Full Scan", "Vuln Scan", "Custom…"])
        row_profile.addWidget(self.cb_profile)

        self.btn_save_profile = QPushButton("Save Preset")
        self.btn_save_profile.setToolTip("Save current GUI settings as a custom preset")
        row_profile.addWidget(self.btn_save_profile)
        root.addLayout(row_profile)

        self.cb_profile.currentIndexChanged.connect(self.on_profile_change)
        self.btn_save_profile.clicked.connect(self.save_current_profile)

        # Timing & Script
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Timing:"))
        self.cb_timing = QComboBox()
        self.cb_timing.addItems(["(Default)", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5"])
        row3.addWidget(self.cb_timing)
        row3.addWidget(QLabel("NSE Script (optional):"))
        self.in_script = QLineEdit()
        self.in_script.setPlaceholderText("e.g. vuln or default,safe")
        row3.addWidget(self.in_script, 2)
        root.addLayout(row3)

        # Advanced (collapsible)
        self._adv_show_text = "Show Advanced Options"
        self._adv_hide_text = "Hide Advanced Options"
        self.adv_toggle = QPushButton(self._adv_show_text)
        self.adv_toggle.setCheckable(True)
        self.adv_toggle.setChecked(False)
        self.adv_toggle.toggled.connect(self.toggle_advanced)
        fm = self.adv_toggle.fontMetrics()
        widest = max(fm.horizontalAdvance(self._adv_show_text), fm.horizontalAdvance(self._adv_hide_text))
        self.adv_toggle.setMinimumWidth(widest + 24)
        root.addWidget(self.adv_toggle)

        self.adv_box = QWidget()
        adv = QVBoxLayout(self.adv_box)
        adv.setSpacing(10)

        # Group A
        rowA = QHBoxLayout()
        self.lbl_vi = QLabel("--version-intensity:")
        rowA.addWidget(self.lbl_vi)
        self.spn_vi = QSpinBox(); self.spn_vi.setRange(0, 9); self.spn_vi.setValue(7); self.spn_vi.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        rowA.addWidget(self.spn_vi)
        self.chk_vall = QCheckBox("--version-all")
        rowA.addWidget(self.chk_vall)
        self.chk_oslimit = QCheckBox("--osscan-limit")
        rowA.addWidget(self.chk_oslimit)
        self.chk_osguess = QCheckBox("--osscan-guess")
        rowA.addWidget(self.chk_osguess)
        adv.addLayout(rowA)

        # Group B
        rowB = QHBoxLayout()
        self.chk_top = QCheckBox("--top-ports")
        rowB.addWidget(self.chk_top)
        self.spn_top = QSpinBox(); self.spn_top.setRange(1, 65535); self.spn_top.setValue(0); self.spn_top.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons); self.spn_top.setMaximumWidth(120)
        rowB.addWidget(self.spn_top)
        self.chk_open = QCheckBox("--open (only open)")
        rowB.addWidget(self.chk_open)
        self.chk_reason = QCheckBox("--reason"); self.chk_reason.setChecked(True)
        rowB.addWidget(self.chk_reason)
        self.chk_trace = QCheckBox("--traceroute")
        rowB.addWidget(self.chk_trace)
        adv.addLayout(rowB)

        # Group C
        rowC = QHBoxLayout()
        rowC.addWidget(QLabel("Output:"))
        self.cb_out = QComboBox(); self.cb_out.addItems(["(None)", "-oN", "-oX", "-oG", "-oA"])
        rowC.addWidget(self.cb_out)
        self.in_out = QLineEdit(); self.in_out.setPlaceholderText("filename or basename for -oA")
        rowC.addWidget(self.in_out, 2)
        adv.addLayout(rowC)

        # Group D
        rowD1 = QHBoxLayout()
        rowD1.setSpacing(8)
        rowD1.setContentsMargins(0, 0, 0, 0)
        self.chk_frag = QCheckBox("-f Fragment"); rowD1.addWidget(self.chk_frag)
        self.chk_mtu = QCheckBox("--mtu"); rowD1.addWidget(self.chk_mtu)
        self.spn_mtu = QSpinBox(); self.spn_mtu.setRange(8, 1500); self.spn_mtu.setSingleStep(8); self.spn_mtu.setValue(0); self.spn_mtu.setMaximumWidth(120); self.spn_mtu.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons); rowD1.addWidget(self.spn_mtu)
        self.lbl_dlen = QLabel("--data-length:"); rowD1.addWidget(self.lbl_dlen)
        self.spn_dlen = QSpinBox(); self.spn_dlen.setRange(0, 1500); self.spn_dlen.setValue(0); self.spn_dlen.setMaximumWidth(120); self.spn_dlen.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons); rowD1.addWidget(self.spn_dlen)
        adv.addLayout(rowD1)

        rowD2 = QHBoxLayout()
        rowD2.addWidget(QLabel("-D Decoys (comma):"))
        self.in_decoy = QLineEdit(); self.in_decoy.setPlaceholderText("RND:5 or 10.0.0.1,ME,10.0.0.3"); rowD2.addWidget(self.in_decoy, 2)
        rowD2.addWidget(QLabel("-S Spoof IP:")); self.in_spoofip = QLineEdit(); rowD2.addWidget(self.in_spoofip)
        rowD2.addWidget(QLabel("-g Src Port:")); self.spn_sport = QSpinBox(); self.spn_sport.setRange(0,65535); self.spn_sport.setValue(0); self.spn_sport.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons); rowD2.addWidget(self.spn_sport)
        adv.addLayout(rowD2)

        self.adv_box.setVisible(False)
        root.addWidget(self.adv_box)

        # Buttons
        row_btn = QHBoxLayout()
        self.btn_scan = QPushButton("Start Scan"); self.btn_scan.clicked.connect(self.start_scan)
        row_btn.addWidget(self.btn_scan)
        self.btn_stop = QPushButton("Stop"); self.btn_stop.clicked.connect(self.stop_scan)
        row_btn.addWidget(self.btn_stop)
        self.btn_save = QPushButton("Save Results…"); self.btn_save.clicked.connect(self.save_results)
        row_btn.addWidget(self.btn_save)
        root.addLayout(row_btn)

        # Progress & Elapsed
        row_prog = QHBoxLayout()
        row_prog.addWidget(QLabel("Progress:"))
        self.progress = QProgressBar(); self.progress.setMinimum(0); self.progress.setMaximum(100); self.progress.setValue(0); self.progress.setTextVisible(False)
        row_prog.addWidget(self.progress, 4)
        self.lbl_elapsed = QLabel("Elapsed: 0.0s"); row_prog.addWidget(self.lbl_elapsed)
        root.addLayout(row_prog)

        self._elapsed_timer = QTimer(self); self._elapsed_timer.setInterval(500); self._elapsed_timer.timeout.connect(self._update_elapsed_label)
        self._scan_start_dt = None

        # Command preview
        row_preview = QHBoxLayout()
        row_preview.addWidget(QLabel("Command Preview:"))
        self.in_preview = QLineEdit(); self.in_preview.setReadOnly(False); self.in_preview.setPlaceholderText("You can edit the nmap command here; leave it blank to update automatically")
        row_preview.addWidget(self.in_preview, 4)
        self.btn_reset_preview = QPushButton("Reset Preview"); self.btn_reset_preview.setToolTip("Reset the preview to the automatically generated one"); self.btn_reset_preview.clicked.connect(self._reset_preview_flag_and_update)
        row_preview.addWidget(self.btn_reset_preview)
        root.addLayout(row_preview)

        self.preview_edited = False
        self.in_preview.textEdited.connect(lambda _: setattr(self, "preview_edited", True))

        # Output tabs
        self.tabs = QTabWidget()
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Host", "Protocol", "Port", "State", "Service", "Product", "Version"])
        self.tree.setSortingEnabled(True)
        self.tree.itemDoubleClicked.connect(self.open_exploitdb)
        self.tabs.addTab(self.tree, "Results")

        self.out = QTextEdit()
        self.out.setReadOnly(True)
        self.tabs.addTab(self.out, "Log")

        # Give results/log tabs layout priority
        root.addWidget(self.tabs, stretch=5)

        # Host the scroll area in the main widget
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        scroll.setWidget(container)

        # Styles
        self.apply_styles()

        # Update readiness visuals as user types
        self.in_target.textChanged.connect(self.update_button_states)
        self.in_ports.textChanged.connect(self.update_button_states)

        # Keep preview updated
        self.in_target.textChanged.connect(self.update_preview)
        self.in_ports.textChanged.connect(self.update_preview)
        self.chk_sv.stateChanged.connect(self.update_preview)
        self.chk_os.stateChanged.connect(self.update_preview)
        self.chk_A.stateChanged.connect(self.update_preview)
        self.cb_timing.currentIndexChanged.connect(self.update_preview)
        self.in_script.textChanged.connect(self.update_preview)
        self.chk_sS.stateChanged.connect(self.update_preview)
        self.chk_sT.stateChanged.connect(self.update_preview)
        self.chk_sU.stateChanged.connect(self.update_preview)
        self.adv_toggle.toggled.connect(self.update_preview)
        self.spn_vi.valueChanged.connect(self.update_preview)
        self.chk_vall.stateChanged.connect(self.update_preview)
        self.chk_oslimit.stateChanged.connect(self.update_preview)
        self.chk_osguess.stateChanged.connect(self.update_preview)
        self.chk_top.stateChanged.connect(self.update_preview)
        self.spn_top.valueChanged.connect(self.update_preview)
        self.chk_open.stateChanged.connect(self.update_preview)
        self.chk_reason.stateChanged.connect(self.update_preview)
        self.chk_trace.stateChanged.connect(self.update_preview)
        self.cb_out.currentIndexChanged.connect(self.update_preview)
        self.in_out.textChanged.connect(self.update_preview)
        self.chk_frag.stateChanged.connect(self.update_preview)
        self.chk_mtu.stateChanged.connect(self.update_preview)
        self.spn_mtu.valueChanged.connect(self.update_preview)
        self.spn_dlen.valueChanged.connect(self.update_preview)
        self.in_decoy.textChanged.connect(self.update_preview)
        self.in_spoofip.textChanged.connect(self.update_preview)
        self.spn_sport.valueChanged.connect(self.update_preview)

        # Init
        self.update_preview()
        self.update_button_states()

        # Load custom profiles
        self.profiles_file = Path.home() / ".nbab_profiles.json"
        self.custom_profiles = self.load_profiles()
        for name in self.custom_profiles.keys():
            if name not in ["(None)", "Quick Scan", "Full Scan", "Vuln Scan", "Custom…"]:
                self.cb_profile.insertItem(self.cb_profile.count() - 1, name)

        if not nmap_available():
            self.warn_no_nmap()
            self.update_button_states()

    # Button state logic
    def update_button_states(self):
        """
        Ready (valid target/ports & nmap present, not scanning):
           Start: enabled (green), Stop: disabled (gray)
        Scanning:
           Start: disabled (gray), Stop: enabled (red)
        Not ready:
           Start: disabled (gray), Stop: disabled (gray)
        """
        if self.scanning:
            self.btn_scan.setEnabled(False)
            self.btn_stop.setEnabled(True)
            return

        target = self.in_target.text().strip()
        ports = self.in_ports.text().strip()
        ready = bool(target) and (not ports or PORTS_RE.match(ports)) and nmap_available()

        self.btn_scan.setEnabled(ready)
        self.btn_stop.setEnabled(False)

    def load_profiles(self) -> dict:
        if not getattr(self, "presets_file", None):
            self.profiles_file = Path.home() / ".nbab_profiles.json"
        if not self.profiles_file.exists():
            return {}
        try:
            with open(self.profiles_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def persist_profiles(self):
        try:
            with open(self.profiles_file, "w", encoding="utf-8") as f:
                json.dump(self.custom_profiles, f, indent=2, ensure_ascii=False)
        except Exception as e:
            try:
                self.append_log(f"\n[!] Could not save profiles: {e}\n")
            except Exception:
                pass

    def on_profile_change(self, idx):
        name = self.cb_profile.currentText()
        if name == "Quick Scan":
            self.apply_profile({
                "scan_flags": {"-sS": True, "-sT": False, "-sU": False},
                "sv": False, "os": False, "A": False,
                "timing": "(Default)",
                "script": "",
                "top_ports": (False, 100),
                "open_only": False
            })
        elif name == "Full Scan":
            self.apply_profile({
                "scan_flags": {"-sS": True, "-sT": False, "-sU": False},
                "sv": True, "os": True, "A": False,
                "timing": "-T4",
                "script": "",
                "top_ports": (False, 0),
                "open_only": False
            })
        elif name == "Vuln Scan":
            self.apply_profile({
                "scan_flags": {"-sS": True, "-sT": False, "-sU": False},
                "sv": True, "os": True, "A": True,
                "timing": "-T3",
                "script": "vuln",
                "top_ports": (False, 0),
                "open_only": False
            })
        elif name == "Custom…":
            pass
        else:
            prof = self.custom_profiles.get(name)
            if prof:
                self.apply_profile(prof)

    def apply_profile(self, profile: dict):
        flags = profile.get("scan_flags", {})
        try:
            self.chk_sS.setChecked(bool(flags.get("-sS", False)))
            self.chk_sT.setChecked(bool(flags.get("-sT", False)))
            self.chk_sU.setChecked(bool(flags.get("-sU", False)))
            self.chk_sv.setChecked(bool(profile.get("sv", False)))
            self.chk_os.setChecked(bool(profile.get("os", False)))
            self.chk_A.setChecked(bool(profile.get("A", False)))
            timing = profile.get("timing", "(Default)")
            idx = self.cb_timing.findText(timing)
            if idx >= 0:
                self.cb_timing.setCurrentIndex(idx)
            self.in_script.setText(profile.get("script", ""))
            if not self.adv_toggle.isChecked():
                self.adv_toggle.setChecked(True)
            top_enabled, top_val = profile.get("top_ports", (False, 0))
            self.chk_top.setChecked(bool(top_enabled))
            try:
                self.spn_top.setValue(int(top_val) if top_val is not None else 0)
            except Exception:
                self.spn_top.setValue(0)
            self.chk_open.setChecked(bool(profile.get("open_only", False)))
        except Exception:
            pass
        self.preview_edited = False
        self.update_preview()
        try:
            self.append_log(f"\n[+] Applied profile: {self.cb_profile.currentText()}\n")
        except Exception:
            pass

    def save_current_profile(self):
        from PyQt6.QtWidgets import QInputDialog
        text, ok2 = QInputDialog.getText(self, "Profile name", "Enter Profile name:")
        if not ok2 or not text.strip():
            return
        prof_name = text.strip()
        prof = {
            "scan_flags": {"-sS": self.chk_sS.isChecked(), "-sT": self.chk_sT.isChecked(), "-sU": self.chk_sU.isChecked()},
            "sv": self.chk_sv.isChecked(),
            "os": self.chk_os.isChecked(),
            "A": self.chk_A.isChecked(),
            "timing": self.cb_timing.currentText(),
            "script": self.in_script.text().strip(),
            "top_ports": (self.chk_top.isChecked(), self.spn_top.value()),
            "open_only": self.chk_open.isChecked(),
        }
        self.custom_profiles[prof_name] = prof
        self.persist_profiles()
        if self.cb_profile.findText(prof_name) == -1:
            self.cb_profile.insertItem(self.cb_profile.count() - 1, prof_name)
        QMessageBox.information(self, "Saved", f"Profile '{prof_name}' saved.")

    def _update_elapsed_label(self):
        if self._scan_start_dt is None:
            self.lbl_elapsed.setText("Elapsed: 0.0s")
            return
        try:
            secs = (datetime.now() - self._scan_start_dt).total_seconds()
            self.lbl_elapsed.setText(f"Elapsed: {secs:.1f}s")
        except Exception:
            pass

    def apply_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(18, 18, 28))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Base, QColor(28, 28, 40))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(22, 22, 34))
        palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Button, QColor(32, 32, 48))
        palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Highlight, QColor(99, 102, 241))
        palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.white)
        self.setPalette(palette)

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget { font-size: 14px; color: #fff; }
            QLabel { color: #cfd3e1; }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #1f2233; color: #e8eaf6;
                border: 1px solid #2a2f45; border-radius: 10px; padding: 8px 10px;
                min-width: 120px;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #6366f1; }

            QCheckBox { spacing: 8px; }

            QPushButton#advToggle { text-align: left; }
            QPushButton { min-width: 120px; }
        """)
        self.btn_scan.setToolTip("+ Start a new scan with the selected options")
        self.btn_stop.setToolTip("- Stop the current scan (if possible)")
        self.btn_save.setToolTip("+ Save the scan results to a file")
        self.adv_toggle.setToolTip("± Show or hide advanced options")

        # Start button: green when enabled, GRAY when disabled
        self.btn_scan.setStyleSheet("""
            QPushButton {
                background-color: #22c55e; color: #0b121a; border-radius: 12px;
                padding: 10px 16px; font-weight: 700; letter-spacing: .3px;
            }
            QPushButton:hover:enabled { background-color: #16a34a; }
            QPushButton:pressed:enabled { background-color: #15803d; }
            QPushButton:disabled { background-color: #4b5563; color: #9ca3af; }
        """)

        # Stop button: RED when enabled, GRAY when disabled
        self.btn_stop.setStyleSheet("""
            QPushButton {
                background-color: #ef4444; color: #fff; border-radius: 12px;
                padding: 10px 16px; font-weight: 700; letter-spacing: .3px;
            }
            QPushButton:hover:enabled { background-color: #dc2626; }
            QPushButton:pressed:enabled { background-color: #b91c1c; }
            QPushButton:disabled { background-color: #4b5563; color: #9ca3af; }
        """)

        self.btn_save.setStyleSheet("""
            QPushButton {
                background-color: #6366f1; color: #fff; border-radius: 12px;
                padding: 10px 16px; font-weight: 700; letter-spacing: .3px;
            }
            QPushButton:hover { background-color: #4f46e5; }
            QPushButton:pressed { background-color: #4338ca; }
        """)

    def warn_no_nmap(self):
        QMessageBox.warning(self, "Nmap not found", "Nmap is not in PATH. Please install it and reopen the app.")

    def append_log(self, text: str):
        self.out.moveCursor(self.out.textCursor().MoveOperation.End)
        self.out.insertPlainText(text)
        self.out.moveCursor(self.out.textCursor().MoveOperation.End)

    def on_done(self):
        self.scanning = False
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        try:
            self.progress.setRange(0, 100)
            self.progress.setValue(100)
            self._elapsed_timer.stop()
        except Exception:
            pass
        self.update_button_states()

    def on_error(self, msg: str):
        self.append_log("\n[!] Error: " + msg + "\n")
        self.scanning = False
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        try:
            self.progress.setRange(0, 100)
            self.progress.setValue(0)
            self._elapsed_timer.stop()
        except Exception:
            pass
        self.update_button_states()

    def build_args(self) -> str:
        scan_flags = []
        if getattr(self, 'chk_sS', None) and self.chk_sS.isChecked():
            scan_flags.append('-sS')
        if getattr(self, 'chk_sT', None) and self.chk_sT.isChecked():
            scan_flags.append('-sT')
        if getattr(self, 'chk_sU', None) and self.chk_sU.isChecked():
            scan_flags.append('-sU')
        if not scan_flags:
            scan_flags = ['-sS']
        args = scan_flags
        if self.chk_A.isChecked():
            args.append("-A")
        else:
            if self.chk_sv.isChecked():
                args.append("-sV")
            if self.chk_os.isChecked():
                args.append("-O")
        sel = self.cb_timing.currentText()
        if sel != "(Default)":
            args.append(sel)
        script = self.in_script.text().strip()
        if script:
            args.extend(["--script", script])
        if self.adv_box.isVisible():
            vi = self.spn_vi.value()
            if vi != 7:
                args.extend(["--version-intensity", str(vi)])
            if self.chk_vall.isChecked():
                args.append("--version-all")
            if self.chk_oslimit.isChecked():
                args.append("--osscan-limit")
            if self.chk_osguess.isChecked():
                args.append("--osscan-guess")
            top = self.spn_top.value()
            if self.chk_top.isChecked() and top >= 1:
                args.extend(["--top-ports", str(top)])
            if self.chk_open.isChecked():
                args.append("--open")
            if self.chk_trace.isChecked():
                args.append("--traceroute")
            outflag = self.cb_out.currentText()
            outname = self.in_out.text().strip()
            if outflag != "(None)" and outname:
                args.extend([outflag, outname])
            if self.chk_frag.isChecked():
                args.append("-f")
            if self.chk_mtu.isChecked() and self.spn_mtu.value() >= 8:
                args.extend(["--mtu", str(self.spn_mtu.value())])
            if self.spn_dlen.value() > 0:
                args.extend(["--data-length", str(self.spn_dlen.value())])
            if self.in_decoy.text().strip():
                args.extend(["-D", self.in_decoy.text().strip()])
            if self.in_spoofip.text().strip():
                args.extend(["-S", self.in_spoofip.text().strip()])
            if self.spn_sport.value() > 0:
                args.extend(["-g", str(self.spn_sport.value())])
        return " ".join(args)

    def update_preview(self):
        if getattr(self, "preview_edited", False):
            return
        args = self.build_args()
        target = self.in_target.text().strip() or "<target>"
        ports = self.in_ports.text().strip()
        port_part = f"-p {ports}" if ports else ""
        cmd = f"nmap {target} {port_part} {args}".strip()
        cmd = re.sub(r"\s+", " ", cmd)
        self.in_preview.setText(cmd)

    def _reset_preview_flag_and_update(self):
        self.preview_edited = False
        self.update_preview()

    def parse_preview_command(self, preview_text: str) -> tuple[str, str, str]:
        txt = preview_text.strip()
        if not txt:
            raise ValueError("Empty command")
        try:
            parts = shlex.split(txt)
        except Exception as e:
            raise ValueError(f"Failed to parse command: {e}")
        if parts and parts[0].lower() == "nmap":
            parts = parts[1:]
        if not parts:
            raise ValueError("No target found in command.")
        target = None
        ports = ""
        args_parts = []
        i = 0
        while i < len(parts):
            p = parts[i]
            if p == "-p":
                if i + 1 < len(parts):
                    ports = parts[i + 1]
                    i += 2
                    continue
                else:
                    raise ValueError("'-p' provided without ports value.")
            if not p.startswith("-") and target is None:
                target = p
                i += 1
                continue
            args_parts.append(p)
            i += 1
        if target is None:
            raise ValueError("Could not find target in the command.")
        if ports and not PORTS_RE.match(ports):
            raise ValueError("Invalid port format in '-p' value.")
        args = " ".join(args_parts).strip()
        return target, ports, args

    def load_results_table(self, rows):
        self.tree.clear()
        for row in rows:
            item = QTreeWidgetItem([
                row['host'], row['proto'].upper(), str(row['port']), row['state'],
                row['service'], row['product'], row['version']
            ])
            query_parts = [row.get('product', ''), row.get('version', '')]
            query = " ".join(p for p in query_parts if p).strip()
            if query:
                url = f"https://www.exploit-db.com/search?q={urllib.parse.quote_plus(query)}"
                item.setData(0, Qt.ItemDataRole.UserRole, url)
            self.tree.addTopLevelItem(item)

    def open_exploitdb(self, item, column):
        url = item.data(0, Qt.ItemDataRole.UserRole)
        if url:
            QDesktopServices.openUrl(QUrl(url))

    def validate(self) -> tuple[bool, str]:
        target = self.in_target.text().strip()
        if not target:
            return False, "Please enter target (IP/Domain)."
        ports = self.in_ports.text().strip()
        if ports and not PORTS_RE.match(ports):
            return False, "Invalid port format."
        if not nmap_available():
            return False, "Nmap is not installed or not in PATH."
        return True, ""

    def start_scan(self):
        # Set scanning UI state first
        self.scanning = True
        self.update_button_states()

        if getattr(self, "preview_edited", False):
            preview_text = self.in_preview.text().strip()
            try:
                target, ports, args = self.parse_preview_command(preview_text)
            except ValueError as e:
                QMessageBox.warning(self, "Preview parse error",
                                    f"خطأ في تحليل الأمر الموجود في معاينة الأوامر:\n{e}\n\nسيتم استخدام الحقول العادية بدلاً من ذلك.")
                self.scanning = False
                self.update_button_states()
            else:
                if not nmap_available():
                    QMessageBox.warning(self, "Validation", "Nmap is not installed or not in PATH.")
                    self.scanning = False
                    self.update_button_states()
                    return
                self.out.clear(); self.tree.clear()
                self.worker = NmapWorker(target, ports, args, self.signals)
                self.btn_scan.setEnabled(False)
                self.btn_stop.setEnabled(True)
                self.worker.start()
                try:
                    self.progress.setRange(0, 0)
                    self._scan_start_dt = datetime.now()
                    self._elapsed_timer.start()
                except Exception:
                    pass
                return

        ok, msg = self.validate()
        if not ok:
            QMessageBox.warning(self, "Validation", msg)
            self.scanning = False
            self.update_button_states()
            return

        self.out.clear(); self.tree.clear()
        args = self.build_args()
        target = self.in_target.text().strip()
        ports = self.in_ports.text().strip()
        self.worker = NmapWorker(target, ports, args, self.signals)
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.worker.start()
        try:
            self.progress.setRange(0, 0)
            self._scan_start_dt = datetime.now()
            self._elapsed_timer.start()
        except Exception:
            pass

    def stop_scan(self):
        if self.worker and self.worker.is_alive():
            self.append_log("\n[!] Attempting to stop scan…\n")
        self.scanning = False
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        try:
            self.progress.setRange(0, 100)
            self.progress.setValue(0)
            self._elapsed_timer.stop()
        except Exception:
            pass
        self.update_button_states()

    def save_results(self):
        text = self.out.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "Save", "No results to save.")
            return
        fn, _ = QFileDialog.getSaveFileName(self, "Save Results", "nmap_results.txt", "Text Files (*.txt)")
        if fn:
            with open(fn, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            QMessageBox.information(self, "Save", f"Saved to:\n{fn}")

    def toggle_advanced(self, checked: bool):
        self.adv_box.setVisible(checked)
        self.adv_toggle.setText(self._adv_hide_text if checked else self._adv_show_text)
        try:
            self.append_log("\n[+] Advanced options {}.\n".format('opened' if checked else 'hidden'))
        except Exception:
            pass

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = NmapGUI()
    w.show()
    sys.exit(app.exec())

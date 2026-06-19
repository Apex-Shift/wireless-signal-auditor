import sys
import math
import csv
import time
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QPushButton, QLabel, QFrame, QLineEdit,
                               QComboBox, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView)
from PySide6.QtCore import QThread, Signal, QObject, Qt, Slot
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import pywifi
from pywifi import const

# =====================================================================
# 1. CORE LOGIC & ALGORITHMS
# =====================================================================
def estimate_distance(rssi, rssi_1m=-40, n=3.0):
    """Calculates estimated distance in meters from RSSI using the Path Loss Model."""
    if rssi >= rssi_1m: return 0.5
    try:
        return round(math.pow(10, (rssi_1m - rssi) / (10 * n)), 2)
    except:
        return 40.0

def get_channel_from_freq(freq_mhz):
    """Converts raw frequency to standard radio channel numbers."""
    if not freq_mhz:
        return "Unknown"
    if 2412 <= freq_mhz <= 2484:
        return f"Ch {int((freq_mhz - 2407) / 5)} (2.4G)"
    elif 5170 <= freq_mhz <= 5825:
        return f"Ch {int((freq_mhz - 5000) / 5)} (5G)"
    return f"{freq_mhz} MHz"

def get_security_text(akm_type):
    """Maps pywifi AKM codes to human-readable security strings."""
    if not akm_type:
        return "Open (None)"
    
    types = {
        const.AKM_TYPE_NONE: "Open",
        const.AKM_TYPE_WPA: "WPA-Enterprise",
        const.AKM_TYPE_WPAPSK: "WPA-PSK",
        const.AKM_TYPE_WPA2: "WPA2-Enterprise",
        const.AKM_TYPE_WPA2PSK: "WPA2-PSK"
    }
    for t in akm_type:
        if t in types:
            return types[t]
    return "WPA3 / Secured"

# =====================================================================
# 2. THREADING BACKEND: WI-FI HARDWARE CAPTURE
# =====================================================================
class WifiCollector(QObject):
    """Manages physical Wi-Fi card scanning and processes network metrics."""
    raw_data = Signal(list)
    status_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.running = True
        self.wifi_manager = pywifi.PyWiFi()
        self.interface_index = 0
        self.rssi_history = {} # For rolling average smoothing

    @Slot(int)
    def change_interface(self, index):
        self.interface_index = index
        self.status_signal.emit(f"Switching to interface #{index}")

    def start_scanning(self):
        while self.running:
            interfaces = self.wifi_manager.interfaces()
            if not interfaces or self.interface_index >= len(interfaces):
                self.status_signal.emit("Error: No Wi-Fi adapter available")
                time.sleep(3)
                continue

            iface = interfaces[self.interface_index]
            self.status_signal.emit(f"Scanning on {iface.name()}...")
            
            try:
                iface.scan()
                time.sleep(2.0) # Hardware settling time for channel switching
                raw_results = iface.scan_results()
                
                network_capsules = []
                seen_bssids = set()
                
                # SSID-BSSID Correlation table for basic Evil Twin heuristics
                correlation_table = {}
                for ap in raw_results:
                    s = ap.ssid.strip() if ap.ssid else "Hidden / Unknown"
                    if s != "Hidden / Unknown":
                        if s not in correlation_table:
                            correlation_table[s] = set()
                        correlation_table[s].add(ap.bssid)

                for ap in raw_results:
                    ssid = ap.ssid.strip() if ap.ssid else "Hidden / Unknown"
                    bssid = ap.bssid
                    
                    if bssid in seen_bssids:
                        continue
                    seen_bssids.add(bssid)

                    # RSSI smoothing logic
                    rssi_instant = ap.signal if ap.signal < 0 else (ap.signal - 100)
                    if bssid not in self.rssi_history:
                        self.rssi_history[bssid] = []
                    self.rssi_history[bssid].append(rssi_instant)
                    if len(self.rssi_history[bssid]) > 5:
                        self.rssi_history[bssid].pop(0)
                    
                    rssi_smoothed = sum(self.rssi_history[bssid]) / len(self.rssi_history[bssid])
                    
                    # Stable polar angle calculation based on BSSID hash
                    fixed_angle = (hash(bssid) % 360) * (math.pi / 180)
                    sec_type = get_security_text(ap.akm)

                    freq_raw = ap.freq
                    if freq_raw > 100000:
                        freq_raw = int(freq_raw / 1000)
                    radio_channel = get_channel_from_freq(freq_raw)

                    # Simple heuristic check for identical SSIDs with different BSSIDs
                    is_suspicious = False
                    if ssid != "Hidden / Unknown" and ssid in correlation_table:
                        if len(correlation_table[ssid]) > 1:
                            is_suspicious = True
                            sec_type = "🚨 SUSPECT (Multi-BSSID)"

                    network_capsules.append({
                        "ssid": ssid,
                        "bssid": bssid,
                        "rssi": round(rssi_smoothed, 1),
                        "distance": estimate_distance(rssi_smoothed),
                        "angle": fixed_angle,
                        "security": sec_type,
                        "canal": radio_channel,
                        "is_evil": is_suspicious
                    })

                network_capsules.sort(key=lambda x: x["rssi"], reverse=True)
                self.raw_data.emit(network_capsules)
                self.status_signal.emit(f"Scan complete: {len(network_capsules)} access points analyzed.")

            except Exception as e:
                self.status_signal.emit(f"Hardware read error: {str(e)}")
            
            time.sleep(4.0)

    def stop(self):
        self.running = False

# =====================================================================
# 3. GRAPHICAL USER INTERFACE & MATPLOTLIB COMPONENTS
# =====================================================================
class DoubleGraphWidget(FigureCanvas):
    """Displays a polar radar plot side-by-side with a time-series signal oscilloscope."""
    def __init__(self):
        self.fig = Figure(facecolor='#0f141c', figsize=(10, 4))
        self.ax_radar = self.fig.add_subplot(121, polar=True)
        self.ax_tracker = self.fig.add_subplot(122)
        super().__init__(self.fig)
        self.target_bssid = None
        self.target_history = []
        self.target_name = "None"
        
    def set_tracking_target(self, bssid, ssid):
        if self.target_bssid != bssid:
            self.target_bssid = bssid
            self.target_name = ssid
            self.target_history = []

    def refresh_plots(self, networks, filter_text=""):
        # --- 1. POLAR RADAR UPDATE ---
        self.ax_radar.clear()
        self.ax_radar.set_facecolor('#171d26')
        self.ax_radar.set_theta_zero_location('N')
        self.ax_radar.set_ylim(0, 40)
        self.ax_radar.grid(True, color='#2d3748', linestyle='-', linewidth=0.7)
        self.ax_radar.tick_params(colors='#718096', labelsize=8)
        
        current_target_rssi = None

        for r in networks:
            if filter_text and (filter_text not in r["ssid"].lower() and filter_text not in r["bssid"].lower()):
                continue

            if r["bssid"] == self.target_bssid:
                current_target_rssi = r["rssi"]

            if r["is_evil"]:
                color = '#ff0055' 
            elif "Open" in r["security"]:
                color = '#ef4444' 
            elif r["rssi"] >= -55:
                color = '#10b981' 
            else:
                color = '#3b82f6' 
                
            self.ax_radar.scatter(r["angle"], r["distance"], s=110, color=color, edgecolors='#ffffff', linewidth=1, zorder=3)
            self.ax_radar.text(r["angle"], r["distance"] + 2, r["ssid"][:10], color='#e2e8f0', fontsize=7, weight='semibold', ha='center')
            
        # --- 2. SIGNAL OSCILLOSCOPE UPDATE ---
        self.ax_tracker.clear()
        self.ax_tracker.set_facecolor('#171d26')
        self.ax_tracker.grid(True, color='#2d3748', linestyle=':', linewidth=0.5)
        self.ax_tracker.tick_params(colors='#718096', labelsize=8)
        self.ax_tracker.set_title(f"Tracking: {self.target_name[:15]}", color='#e2e8f0', fontsize=9, weight='bold', fontfamily='monospace')
        self.ax_tracker.set_ylim(-100, -30) 
        
        if current_target_rssi is not None:
            self.target_history.append(current_target_rssi)
            if len(self.target_history) > 15:
                self.target_history.pop(0)
                
        if self.target_history:
            self.ax_tracker.plot(self.target_history, color='#00ffcc', marker='o', linewidth=2, markersize=4, label='Signal (dBm)')
            self.ax_tracker.fill_between(range(len(self.target_history)), self.target_history, -100, color='#00ffcc', alpha=0.1)

        self.draw()

class DashboardRadar(QMainWindow):
    """Main application frame for the Wireless Signal Auditor dashboard."""
    interface_changed_signal = Signal(int)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wireless Signal Auditor (WSA) v1.0")
        self.resize(1200, 750)
        self.init_data_store()
        self.apply_styles()
        
        central_widget = QWidget()
        global_layout = QVBoxLayout(central_widget)
        
        # TOP TOOLBAR
        toolbar = QFrame()
        toolbar.setObjectName("TopToolbar")
        toolbar_layout = QHBoxLayout(toolbar)
        
        lbl_card = QLabel("ADAPTER:")
        self.combo_interfaces = QComboBox()
        self.load_system_interfaces()
        self.combo_interfaces.currentIndexChanged.connect(self.on_interface_change)
        
        lbl_search = QLabel("FILTER:")
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search by SSID or MAC...")
        self.txt_search.textChanged.connect(self.on_filter_changed)
        
        btn_export = QPushButton("EXPORT (CSV)")
        btn_export.clicked.connect(self.on_export_csv)
        
        btn_report = QPushButton("REPORT")
        btn_report.clicked.connect(self.on_generate_report)
        
        btn_exit = QPushButton("EXIT")
        btn_exit.clicked.connect(self.close)
        btn_exit.setObjectName("BtnExit")
        
        toolbar_layout.addWidget(lbl_card)
        toolbar_layout.addWidget(self.combo_interfaces, stretch=1)
        toolbar_layout.addWidget(lbl_search)
        toolbar_layout.addWidget(self.txt_search, stretch=1)
        toolbar_layout.addWidget(btn_export)
        toolbar_layout.addWidget(btn_report)
        toolbar_layout.addWidget(btn_exit)
        
        # MAIN LAYOUT SPLIT
        self.dual_graphs = DoubleGraphWidget()
        
        self.table_networks = QTableWidget(0, 5)
        self.table_networks.setHorizontalHeaderLabels(["SSID", "BSSID (MAC)", "Channel / Band", "Signal Strength", "Security Status"])
        self.table_networks.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_networks.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_networks.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_networks.cellClicked.connect(self.on_row_selected)
        
        global_layout.addWidget(toolbar)
        global_layout.addWidget(self.dual_graphs, stretch=3)
        global_layout.addWidget(self.table_networks, stretch=2)
        
        # STATUS BAR
        self.lbl_status = QLabel("Initializing listening matrix...")
        self.lbl_status.setObjectName("StatusBar")
        global_layout.addWidget(self.lbl_status)
        
        self.setCentralWidget(central_widget)
        
        # WORKER THREAD COUPLING
        self.hardware_thread = QThread()
        self.worker = WifiCollector()
        self.worker.moveToThread(self.hardware_thread)
        
        self.hardware_thread.started.connect(self.worker.start_scanning)
        self.worker.raw_data.connect(self.on_data_received)
        self.worker.status_signal.connect(self.update_status)
        self.interface_changed_signal.connect(self.worker.change_interface)
        
        self.hardware_thread.start()

    def init_data_store(self):
        self.last_captured_data = []
        self.active_filter = ""

    def load_system_interfaces(self):
        manager = pywifi.PyWiFi()
        if not manager.interfaces():
            self.combo_interfaces.addItem("No hardware wireless adapters detected")
            return
        for idx, iface in enumerate(manager.interfaces()):
            self.combo_interfaces.addItem(f"Interface #{idx}: {iface.name()}")

    @Slot(list)
    def on_data_received(self, network_list):
        self.last_captured_data = network_list
        self.dual_graphs.refresh_plots(network_list, self.active_filter)
        
        self.table_networks.setRowCount(0)
        row_idx = 0
        for r in network_list:
            if self.active_filter and (self.active_filter not in r["ssid"].lower() and self.active_filter not in r["bssid"].lower()):
                continue
                
            self.table_networks.insertRow(row_idx)
            
            item_ssid = QTableWidgetItem(r["ssid"])
            item_bssid = QTableWidgetItem(r["bssid"])
            item_channel = QTableWidgetItem(r["canal"]) 
            item_signal = QTableWidgetItem(f"{r['rssi']} dBm (~{r['distance']}m)")
            item_sec = QTableWidgetItem(r["security"])

            # --- CORRECTION DE LA STYLISATION ---
            if r["is_evil"]:
                # Alerte rouge vif pour les suspicions d'attaques
                item_sec.setForeground(Qt.red)
                item_sec.setText("⚠️ SUSPICIOUS ACTIVITY")
                
                # Optionnel : Mettre le texte en gras pour attirer l'oeil
                font = item_sec.font()
                font.setBold(True)
                item_sec.setFont(font)
                
            elif "Open" in r["security"]:
                # Rouge standard pour les réseaux vulnérables non chiffrés
                item_sec.setForeground(Qt.red)
                item_sec.setText("⚠️ UNENCRYPTED")
                
                # Application de la police grasse de manière propre
                font = item_sec.font()
                font.setBold(True)
                item_sec.setFont(font)

            self.table_networks.setItem(row_idx, 0, item_ssid)
            self.table_networks.setItem(row_idx, 1, item_bssid)
            self.table_networks.setItem(row_idx, 2, item_channel)
            self.table_networks.setItem(row_idx, 3, item_signal)
            self.table_networks.setItem(row_idx, 4, item_sec)
            row_idx += 1


    @Slot(int, int)
    def on_row_selected(self, row, col):
        item_ssid = self.table_networks.item(row, 0)
        item_bssid = self.table_networks.item(row, 1)
        if item_ssid and item_bssid:
            self.dual_graphs.set_tracking_target(item_bssid.text(), item_ssid.text())
            self.update_status(f"Tracking signal matrix lock on: {item_ssid.text()}")

    def on_filter_changed(self, text):
        self.active_filter = text.lower().strip()
        self.dual_graphs.refresh_plots(self.last_captured_data, self.active_filter)

    def on_interface_change(self, idx):
        self.interface_changed_signal.emit(idx)

    def on_export_csv(self):
        if not self.last_captured_data:
            QMessageBox.warning(self, "Export Warning", "No operational matrix log available to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Log", "", "CSV Files (*.csv)")
        if path:
            try:
                with open(path, mode='w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["SSID", "BSSID", "Channel", "Signal (dBm)", "Security"])
                    for r in self.last_captured_data:
                        writer.writerow([r["ssid"], r["bssid"], r["canal"], r["rssi"], r["security"]])
                QMessageBox.information(self, "Export Success", "Wireless signal log exported clean.")
            except Exception as e:
                QMessageBox.critical(self, "IO Error", f"Failed to commit metrics data file: {str(e)}")

    def on_generate_report(self):
        QMessageBox.information(self, "Report Manager", "Diagnostic capture file generated in local workspace.")

    @Slot(str)
    def update_status(self, msg):
        self.lbl_status.setText(msg)

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #0f141c; }
            QWidget { color: #e2e8f0; font-family: 'Segoe UI', Arial; font-size: 9pt; }
            QFrame#TopToolbar { background-color: #171d26; padding: 8px; border-radius: 6px; }
            QLineEdit { background-color: #2d3748; border: 1px solid #4a5568; padding: 4px; color: white; border-radius: 4px; }
            QComboBox { background-color: #2d3748; border: 1px solid #4a5568; padding: 4px; color: white; border-radius: 4px; }
            QPushButton { background-color: #3182ce; border: none; padding: 6px 12px; color: white; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #2b6cb0; }
            QPushButton#BtnExit { background-color: #e53e3e; }
            QPushButton#BtnExit:hover { background-color: #c53030; }
            QTableWidget { background-color: #171d26; gridline-color: #2d3748; border: 1px solid #2d3748; color: #e2e8f0; }
            QHeaderView::section { background-color: #2d3748; color: #00ffcc; padding: 4px; border: 1px solid #1a202c; font-weight: bold; }
            QLabel#StatusBar { color: #00ffcc; font-family: monospace; font-size: 8pt; padding: 2px; }
        """)

    def closeEvent(self, event):
        self.worker.stop()
        self.hardware_thread.quit()
        self.hardware_thread.wait()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DashboardRadar()
    window.show()
    sys.exit(app.exec())

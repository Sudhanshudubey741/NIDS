# main_gui.py

import tkinter as tk
from tkinter import scrolledtext
import threading
from packet_sniffer import PacketSniffer
from detection_engine import DetectionEngine
import datetime


class NIDSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced NIDS System")
        self.root.geometry("1100x700")
        self.root.configure(bg="#121212")

        self.detector = DetectionEngine()
        self.packet_count = 0
        self.alert_count = 0
        self.monitoring = False

        self.create_widgets()

    def create_widgets(self):

        # ===== TITLE =====
        title = tk.Label(
            self.root,
            text="Network Intrusion Detection System",
            font=("Helvetica", 22, "bold"),
            fg="cyan",
            bg="#121212"
        )
        title.pack(pady=10)

        # ===== STATUS FRAME =====
        status_frame = tk.Frame(self.root, bg="#1f1f1f")
        status_frame.pack(fill="x", padx=20, pady=5)

        self.status_label = tk.Label(
            status_frame,
            text="Status: STOPPED",
            font=("Arial", 12, "bold"),
            fg="red",
            bg="#1f1f1f"
        )
        self.status_label.pack(side="left", padx=20)

        self.packet_label = tk.Label(
            status_frame,
            text="Packets: 0",
            font=("Arial", 12),
            fg="white",
            bg="#1f1f1f"
        )
        self.packet_label.pack(side="left", padx=20)

        self.alert_label = tk.Label(
            status_frame,
            text="Alerts: 0",
            font=("Arial", 12),
            fg="orange",
            bg="#1f1f1f"
        )
        self.alert_label.pack(side="left", padx=20)

        # ===== LOG FRAME =====
        log_frame = tk.Frame(self.root, bg="#121212")
        log_frame.pack(fill="both", expand=True, padx=20, pady=10)

        tk.Label(log_frame, text="Traffic Logs",
                 bg="#121212", fg="white",
                 font=("Arial", 14)).pack(anchor="w")

        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            height=15,
            bg="#1e1e1e",
            fg="white",
            insertbackground="white"
        )
        self.log_area.pack(fill="both", expand=True)

        # ===== ALERT FRAME =====
        alert_frame = tk.Frame(self.root, bg="#121212")
        alert_frame.pack(fill="both", expand=True, padx=20, pady=10)

        tk.Label(alert_frame, text="Security Alerts",
                 bg="#121212", fg="red",
                 font=("Arial", 14, "bold")).pack(anchor="w")

        self.alert_area = scrolledtext.ScrolledText(
            alert_frame,
            height=8,
            bg="#330000",
            fg="red"
        )
        self.alert_area.pack(fill="both", expand=True)

        # ===== BUTTON FRAME =====
        button_frame = tk.Frame(self.root, bg="#121212")
        button_frame.pack(pady=10)

        tk.Button(
            button_frame,
            text="Start Monitoring",
            command=self.start_monitoring,
            bg="#007acc",
            fg="white",
            width=18
        ).pack(side="left", padx=10)

        tk.Button(
            button_frame,
            text="Stop Monitoring",
            command=self.stop_monitoring,
            bg="#cc0000",
            fg="white",
            width=18
        ).pack(side="left", padx=10)

        tk.Button(
            button_frame,
            text="Clear Logs",
            command=self.clear_logs,
            bg="#444444",
            fg="white",
            width=18
        ).pack(side="left", padx=10)

    # ============================

    def packet_callback(self, packet):
        if not self.monitoring:
            return

        self.packet_count += 1
        self.packet_label.config(text=f"Packets: {self.packet_count}")

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        log_message = (
            f"[{timestamp}] {packet['src_ip']} → "
            f"{packet['dst_ip']} | "
            f"Port: {packet['dst_port']} | "
            f"Size: {packet['packet_length']}\n"
        )

        self.log_area.insert(tk.END, log_message)
        self.log_area.see(tk.END)

        alerts = self.detector.analyze_packet(packet)

        for alert in alerts:
            self.alert_count += 1
            self.alert_label.config(text=f"Alerts: {self.alert_count}")

            alert_message = f"[{timestamp}] {alert}\n"
            self.alert_area.insert(tk.END, alert_message)
            self.alert_area.see(tk.END)

    # ============================

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.status_label.config(text="Status: MONITORING", fg="lime")

            self.sniffer = PacketSniffer(self.packet_callback)
            thread = threading.Thread(target=self.sniffer.start)
            thread.daemon = True
            thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.status_label.config(text="Status: STOPPED", fg="red")

    def clear_logs(self):
        self.log_area.delete(1.0, tk.END)
        self.alert_area.delete(1.0, tk.END)
        self.packet_count = 0
        self.alert_count = 0
        self.packet_label.config(text="Packets: 0")
        self.alert_label.config(text="Alerts: 0")


# ============================

if __name__ == "__main__":
    root = tk.Tk()
    app = NIDSGUI(root)
    root.mainloop()
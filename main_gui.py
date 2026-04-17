# detection_engine.py

import pandas as pd
from collections import Counter
from ml_model import MLModel

class DetectionEngine:
    def __init__(self):
        self.ml_model = MLModel()
        self.packet_history = []

    def analyze_packet(self, packet):
        self.packet_history.append(packet)

        alerts = []

        # Rule-based DoS detection
        src_ips = [p["src_ip"] for p in self.packet_history[-200:]]
        count = Counter(src_ips)

        for ip, c in count.items():
            if c > 100:
                alerts.append(f"⚠️ Possible DoS attack from {ip}")

        # ML-based anomaly detection
        if len(self.packet_history) > 50:
            df = pd.DataFrame(self.packet_history[-200:])
            predictions = self.ml_model.model.fit_predict(
                df[["packet_length", "protocol", "src_port", "dst_port"]]
            )

            if predictions[-1] == -1:
                alerts.append("🚨 ML Anomaly Detected!")

        return alerts
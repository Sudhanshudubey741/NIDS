# ml_model.py

import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

MODEL_PATH = "nids_model.pkl"

class MLModel:
    def __init__(self):
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
        else:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42
            )

    def train(self, df):
        features = df[["packet_length", "protocol", "src_port", "dst_port"]]
        self.model.fit(features)
        joblib.dump(self.model, MODEL_PATH)

    def predict(self, df):
        features = df[["packet_length", "protocol", "src_port", "dst_port"]]
        return self.model.predict(features)
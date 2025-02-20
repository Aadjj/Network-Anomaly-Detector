from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from sklearn.preprocessing import MinMaxScaler
import numpy as np
import logging

logging.basicConfig(filename="security_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")


class SecurityMonitor:
    def __init__(self):
        self.model = self.build_model()
        self.scaler = MinMaxScaler()
        self.fitted = False
        self.threshold = None

    def build_model(self):
        model = Sequential([
            Dense(64, activation='relu', input_shape=(1,)),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='mse')
        return model

    def train(self, data):
        if len(data) == 0:
            logging.warning("[SECURITY] No data available for training.")
            return

        try:
            data = np.array(data).reshape(-1, 1)
            self.scaler.fit(data)
            self.fitted = True

            scaled_data = self.scaler.transform(data)
            self.model.fit(scaled_data, scaled_data, epochs=15, batch_size=16, verbose=1)

            predictions = self.model.predict(scaled_data)
            errors = np.abs(predictions - scaled_data)
            self.threshold = np.percentile(errors, 98)

            logging.info("[SECURITY] Model trained successfully. Threshold set at: {:.4f}".format(self.threshold))
        except Exception as e:
            logging.error(f"[SECURITY ERROR] Training failed: {e}")

    def detect(self, new_data):
        if not self.fitted:
            logging.info("[SECURITY] Initial training in progress...")
            self.train(new_data)

        try:
            new_data = np.array(new_data).reshape(-1, 1)
            new_data_scaled = self.scaler.transform(new_data)
            predictions = self.model.predict(new_data_scaled)
            errors = np.mean(np.abs(predictions - new_data_scaled), axis=1)

            anomaly_threshold = self.threshold if self.threshold else 0.1
            anomalies = errors > anomaly_threshold

            if np.any(anomalies):
                logging.warning(f"[SECURITY ALERT] {np.sum(anomalies)} anomalies detected!")

            return anomalies
        except Exception as e:
            logging.error(f"[SECURITY ERROR] Anomaly detection failed: {e}")
            return np.array([False] * len(new_data))

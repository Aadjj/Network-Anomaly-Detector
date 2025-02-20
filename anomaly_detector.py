from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from sklearn.preprocessing import MinMaxScaler
import numpy as np


class AnomalyDetector:
    def __init__(self):
        self.model = self.build_model()
        self.scaler = MinMaxScaler()
        self.fitted = False
        self.threshold = None

    def build_model(self):
        model = Sequential([
            Dense(64, activation='relu', input_shape=(1,)),
            Dropout(0.2),
            Dense(32, activation='relu'),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='mse')
        return model

    def train(self, data):
        if len(data) == 0:
            print("[WARNING] No data available for training.")
            return

        data = np.array(data).reshape(-1, 1)
        self.scaler.fit(data)
        self.fitted = True

        scaled_data = self.scaler.transform(data)
        self.model.fit(scaled_data, scaled_data, epochs=20, batch_size=16, verbose=1)

        predictions = self.model.predict(scaled_data)
        errors = np.abs(predictions - scaled_data)
        self.threshold = np.percentile(errors, 95)

    def detect(self, new_data):
        if not self.fitted:
            print("[INFO] Fitting scaler with initial data...")
            self.train(new_data)

        new_data = np.array(new_data).reshape(-1, 1)
        new_data_scaled = self.scaler.transform(new_data)
        predictions = self.model.predict(new_data_scaled)
        errors = np.mean(np.abs(predictions - new_data_scaled), axis=1)

        anomaly_threshold = self.threshold if self.threshold else 0.1
        return errors > anomaly_threshold

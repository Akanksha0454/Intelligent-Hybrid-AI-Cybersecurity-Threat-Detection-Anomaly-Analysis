import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam

# Generate synthetic AIS-like dataset
def generate_synthetic_ais_data(n_samples=1000):
    np.random.seed(42)
    data = {
        'latitude': np.random.uniform(-90, 90, n_samples),
        'longitude': np.random.uniform(-180, 180, n_samples),
        'sog': np.random.uniform(0, 30, n_samples),
        'cog': np.random.uniform(0, 360, n_samples),
        'heading': np.random.uniform(0, 360, n_samples),
        'nav_status': np.random.choice(['under_way', 'at_anchor', 'moored'], n_samples),
        'vessel_type': np.random.choice(['cargo', 'tanker', 'fishing'], n_samples),
        'anomaly': np.random.choice([0, 1], n_samples, p=[0.95, 0.05])  # 5% anomalies
    }
    return pd.DataFrame(data)

# Preprocess the data
def preprocess_data(df):
    num_cols = ['latitude', 'longitude', 'sog', 'cog', 'heading']
    cat_cols = ['nav_status', 'vessel_type']
    X_num = df[num_cols]
    X_cat = df[cat_cols]
    y = df['anomaly']

    # Normalize numerical features
    scaler = MinMaxScaler()
    X_num_scaled = scaler.fit_transform(X_num)

    # Encode categorical features
    encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
    X_cat_encoded = encoder.fit_transform(X_cat)

    return X_num_scaled, X_cat_encoded, y, scaler, encoder

# Create sequences for LSTM
def create_sequences(X, y, sequence_length=10):
    X_seq, y_seq = [], []
    for i in range(len(X) - sequence_length):
        X_seq.append(X[i:i+sequence_length])
        y_seq.append(y[i+sequence_length])
    return np.array(X_seq), np.array(y_seq)

# Build LSTM model
def build_lstm_model(input_shape):
    model = Sequential()
    model.add(LSTM(64, input_shape=input_shape, return_sequences=False))
    model.add(Dropout(0.3))
    model.add(Dense(32, activation='relu'))
    model.add(Dense(1, activation='sigmoid'))
    model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', metrics=['accuracy'])
    return model

# Train Isolation Forest
def train_isolation_forest(X_train_num):
    iso_forest = IsolationForest(contamination=0.05, random_state=42)
    iso_forest.fit(X_train_num)
    return iso_forest

# Train LSTM model
def train_sequence_model(X_train_seq, y_train_seq, input_shape):
    model = build_lstm_model(input_shape)
    model.fit(X_train_seq, y_train_seq, epochs=10, batch_size=32, verbose=0)
    return model

# Predict with hybrid model
def predict_hybrid_model(iso_model, seq_model, X_num, X_cat, X_seq):
    iso_pred = iso_model.predict(X_num)
    iso_pred = np.where(iso_pred == -1, 1, 0)  # Convert to anomaly labels

    dl_pred = (seq_model.predict(X_seq, verbose=0).flatten() > 0.5).astype(int)

    # Combine predictions (logical OR)
    hybrid_pred = np.logical_or(iso_pred, dl_pred).astype(int)
    return hybrid_pred

# Evaluate model
def evaluate_model(y_true, y_pred):
    print("Confusion Matrix:")
    print(confusion_matrix(y_true, y_pred))
    print("\nClassification Report:")
    cls = classification_report(y_true, y_pred, output_dict=True)
    print(cls)
    return cls

# Main
def main():
    df = generate_synthetic_ais_data()
    X_num, X_cat, y, scaler, encoder = preprocess_data(df)

    # Split for Isolation Forest
    X_train_num, X_test_num, y_train, y_test = train_test_split(X_num, y, test_size=0.2, random_state=42)

    # Train Isolation Forest
    isolation_forest = train_isolation_forest(X_train_num)

    # Prepare sequence data for LSTM
    sequence_length = 10
    X_seq, y_seq = create_sequences(X_num, y, sequence_length)

    # Split sequence data
    split_idx = int(0.8 * len(X_seq))
    X_train_seq, X_test_seq = X_seq[:split_idx], X_seq[split_idx:]
    y_train_seq, y_test_seq = y_seq[:split_idx], y_seq[split_idx:]

    # Train LSTM
    sequence_model = train_sequence_model(X_train_seq, y_train_seq, input_shape=X_train_seq.shape[1:])

    # Align test data lengths
    min_len = len(X_test_seq)
    X_test_num = X_test_num[-min_len:]
    X_test_cat = X_cat[-min_len:]
    y_test_aligned = y_test[-min_len:]

    # Predict and evaluate
    y_pred = predict_hybrid_model(isolation_forest, sequence_model, X_test_num, X_test_cat, X_test_seq)
    return evaluate_model(y_test_aligned, y_pred)

def build_model():
    cls = main()
    return cls

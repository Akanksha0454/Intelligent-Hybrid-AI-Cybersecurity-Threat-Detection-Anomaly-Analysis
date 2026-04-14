import os
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, Flatten, Dropout
from tensorflow.keras.callbacks import EarlyStopping

# =========================
# Setup
# =========================

MODEL_DIR = "media/models"
os.makedirs(MODEL_DIR, exist_ok=True)

df = pd.read_csv("media/final.csv")

# =========================
# IP Conversion
# =========================

def ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(part) << (8 * (3 - i)) for i, part in enumerate(parts))

df["ip_numeric"] = df["ip_address"].apply(ip_to_int)

# Encode protocol
protocol_encoder = LabelEncoder()
df["protocol"] = protocol_encoder.fit_transform(df["protocol"])

# =========================
# Binary Attack Model
# =========================

binary_df = df.drop(columns=["ip_address", "attack_type"])

X = binary_df.drop("attacked", axis=1)
y = binary_df["attacked"]

noise = np.random.normal(0, 0.02, X.shape)
X = X + noise

scaler = StandardScaler()
X = scaler.fit_transform(X)

joblib.dump(scaler, f"{MODEL_DIR}/scaler.pkl")
joblib.dump(protocol_encoder,
            f"{MODEL_DIR}/protocol_encoder.pkl")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ---------- Random Forest ----------

rf = RandomForestClassifier(n_estimators=40, max_depth=8)
rf.fit(X_train, y_train)

ml_preds = rf.predict(X_test)

print("\n=== Binary ML ===")
print("Accuracy:", accuracy_score(y_test, ml_preds))
print("Recall:", recall_score(y_test, ml_preds))

joblib.dump(rf, f"{MODEL_DIR}/random_forest_model.pkl")

# ---------- CNN ----------

X_train_cnn = X_train.reshape(X_train.shape[0],
                              X_train.shape[1], 1)

X_test_cnn = X_test.reshape(X_test.shape[0],
                            X_test.shape[1], 1)

cnn = Sequential([
    Conv1D(16, 2, activation='relu',
           input_shape=(X_train.shape[1], 1)),
    Dropout(0.3),
    Flatten(),
    Dense(32, activation='relu'),
    Dropout(0.3),
    Dense(1, activation='sigmoid')
])

cnn.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

early_stop = EarlyStopping(
    patience=2,
    restore_best_weights=True
)

cnn.fit(
    X_train_cnn,
    y_train,
    epochs=6,
    batch_size=64,
    validation_split=0.2,
    callbacks=[early_stop],
    verbose=1
)

cnn.save(f"{MODEL_DIR}/cnn_model.h5")

cnn_preds = (cnn.predict(X_test_cnn) > 0.5).astype(int)
hybrid = np.round((ml_preds + cnn_preds.flatten()) / 2)

print("\n=== Hybrid ===")
print("Accuracy:",
      accuracy_score(y_test, hybrid))
print("Recall:",
      recall_score(y_test, hybrid))

# =========================
# Attack Type Model
# =========================

attack_df = df[df["attacked"] == 1].copy()

X_attack = attack_df.drop(
    columns=["ip_address",
             "attack_type",
             "attacked"]
)

y_attack = attack_df["attack_type"]

attack_encoder = LabelEncoder()
y_attack_enc = attack_encoder.fit_transform(y_attack)

X_attack = scaler.transform(X_attack)

Xa_train, Xa_test, ya_train, ya_test = train_test_split(
    X_attack,
    y_attack_enc,
    test_size=0.2,
    random_state=42
)

attack_model = RandomForestClassifier(
    n_estimators=60
)

attack_model.fit(Xa_train, ya_train)

print("\n=== Attack Type ===")
print("Accuracy:",
      accuracy_score(
          ya_test,
          attack_model.predict(Xa_test)
      ))

joblib.dump(attack_model,
            f"{MODEL_DIR}/attack_type_model.pkl")

joblib.dump(attack_encoder,
            f"{MODEL_DIR}/attack_encoder.pkl")

print("\n✅ All models saved!")

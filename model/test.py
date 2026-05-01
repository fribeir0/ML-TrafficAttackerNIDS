import pandas as pd
import joblib
import datetime

# carregar modelo
model = joblib.load("rf_model.pkl")
features = joblib.load("features.pkl")

# carregar dados
df = pd.read_csv("session01_labeled.csv")

# preprocess igual treino
df = df.drop(columns=["label", "src_ip", "dst_ip", "src_port", "dst_port"], errors="ignore")

if "protocol" in df.columns and df["protocol"].dtype == "object":
    df["protocol"] = df["protocol"].astype("category").cat.codes

df = df.select_dtypes(include=["number"])
df = df.reindex(columns=features, fill_value=0)

# predição
preds = model.predict(df)
probs = model.predict_proba(df)[:, 1]

# output estruturado
for i in range(len(df)):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if preds[i] == 1:
        risk = "HIGH" if probs[i] > 0.9 else "MEDIUM"

        print(f"""
[ALERT] 🚨 ATTACK DETECTED
[TIME] {timestamp}
[INDEX] {i}
[PROB] {probs[i]:.2f}
[RISK] {risk}
-----------------------------------
""")
    else:
        print(f"[OK] Normal traffic | prob={probs[i]:.2f}")
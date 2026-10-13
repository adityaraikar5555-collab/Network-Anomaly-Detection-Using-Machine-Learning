import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from nsl_kdd_preprocessing import load_and_preprocess

X_train, X_test, y_train, y_test = load_and_preprocess()

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=25,
    min_samples_split=4,
    min_samples_leaf=2,
    max_features="sqrt",
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

print("Training NSL-KDD Random Forest model...")
model.fit(X_train, y_train)

os.makedirs("../models", exist_ok=True)
joblib.dump(model, "../models/nsl-kdd_anomaly_model.pkl")

print("Model saved successfully at ../models/nsl-kdd_anomaly_model.pkl")
import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from nsl_kdd_preprocessing import load_and_preprocess


# Load preprocessed data
X_train, X_test, y_train, y_test = load_and_preprocess()

print("=" * 50)
print("NSL-KDD Random Forest Training")
print("=" * 50)

print("X_train shape:", X_train.shape)
print("X_test shape :", X_test.shape)
print("y_train shape:", y_train.shape)
print("y_test shape :", y_test.shape)

print("\nClass Distribution:")
print(y_train.value_counts())

# Create model
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

print("\nTraining started...")
model.fit(X_train, y_train)
print("Training completed!")

# Save model
os.makedirs("../models", exist_ok=True)

model_path = "../models/nsl-kdd_anomaly_model.pkl"
joblib.dump(model, model_path)

print("\nModel saved successfully!")
print("Path:", model_path)

print("=" * 50)
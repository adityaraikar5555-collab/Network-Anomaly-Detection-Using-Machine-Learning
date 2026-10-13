from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

from cicids_preprocessing import load_dataset, clean_dataset


DATA_PATH = "../data/CICIDS-2017"

df = load_dataset(DATA_PATH, sample_per_file=50000)
X, y, le = clean_dataset(df)

print("Final X shape:", X.shape)
print("Final y shape:", y.shape)
print("Classes:", le.classes_)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    max_features="sqrt",
    class_weight="balanced_subsample",
    random_state=42,
    n_jobs=-1
)

print("Training started...")
rf.fit(X_train, y_train)
print("Training completed!")

joblib.dump(rf, "../models/cicids_anomaly_model.pkl", compress=3)
joblib.dump(le, "../models/cicids_label_encoder.pkl", compress=3)

print("Model saved successfully!")
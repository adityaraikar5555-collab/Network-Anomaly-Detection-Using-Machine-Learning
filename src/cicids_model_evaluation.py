from cicids_preprocessing import load_dataset, clean_dataset
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)
import joblib

DATA_PATH = "../data/CICIDS-2017"

# Load sampled dataset
df = load_dataset(DATA_PATH, sample_per_file=50000)

# Preprocess
X, y, le = clean_dataset(df)

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Load trained model
rf = joblib.load("../models/cicids_anomaly_model.pkl")

# Prediction
y_pred = rf.predict(X_test)
y_prob = rf.predict_proba(X_test)[:,1]

# Metrics
print("="*50)
print("Random Forest Evaluation")
print("="*50)

print("Accuracy :", accuracy_score(y_test,y_pred))
print("Precision:", precision_score(y_test,y_pred))
print("Recall   :", recall_score(y_test,y_pred))
print("F1 Score :", f1_score(y_test,y_pred))
print("ROC-AUC  :", roc_auc_score(y_test,y_prob))

print("\nClassification Report\n")
print(classification_report(y_test,y_pred,target_names=["ATTACK","BENIGN"]))

print("\nConfusion Matrix\n")
print(confusion_matrix(y_test,y_pred))
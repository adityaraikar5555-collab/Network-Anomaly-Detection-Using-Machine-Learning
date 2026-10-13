import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve
)

from nsl_kdd_preprocessing import load_and_preprocess


# Load preprocessed data
X_train, X_test, y_train, y_test = load_and_preprocess()

# Load trained model
model = joblib.load("../models/nsl-kdd_anomaly_model.pkl")

# Predictions
train_pred = model.predict(X_train)
test_pred = model.predict(X_test)

# Probabilities for ROC-AUC
probs = model.predict_proba(X_test)[:, 1]

# Metrics
train_acc = accuracy_score(y_train, train_pred)
test_acc = accuracy_score(y_test, test_pred)
precision = precision_score(y_test, test_pred)
recall = recall_score(y_test, test_pred)
f1 = f1_score(y_test, test_pred)
roc = roc_auc_score(y_test, probs)

report = classification_report(
    y_test,
    test_pred,
    target_names=["Normal", "Attack"]
)

cm = confusion_matrix(y_test, test_pred)

# Print professional output
print("=" * 50)
print("Random Forest Evaluation - NSL-KDD")
print("=" * 50)

print(f"Training Accuracy : {train_acc}")
print(f"Testing Accuracy  : {test_acc}")
print(f"Precision         : {precision}")
print(f"Recall            : {recall}")
print(f"F1 Score          : {f1}")
print(f"ROC-AUC           : {roc}")

print("\nClassification Report\n")
print(report)

print("Confusion Matrix\n")
print(cm)

# Create reports folder
os.makedirs("../reports", exist_ok=True)

# Save metrics text file
with open("../reports/nsl-kdd_model_metrics.txt", "w") as f:
    f.write("NSL-KDD Network Intrusion Detection System\n")
    f.write("=" * 50 + "\n\n")

    f.write(f"Training Accuracy : {train_acc}\n")
    f.write(f"Testing Accuracy  : {test_acc}\n")
    f.write(f"Precision         : {precision}\n")
    f.write(f"Recall            : {recall}\n")
    f.write(f"F1 Score          : {f1}\n")
    f.write(f"ROC-AUC           : {roc}\n\n")

    f.write("Classification Report\n\n")
    f.write(report)

    f.write("\nConfusion Matrix\n\n")
    f.write(str(cm))

# Save Confusion Matrix PNG
plt.figure(figsize=(6, 5))
sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=["Normal", "Attack"],
    yticklabels=["Normal", "Attack"]
)
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("NSL-KDD Confusion Matrix")
plt.savefig("../reports/nsl-kdd_confusion_matrix.png", dpi=300, bbox_inches="tight")
plt.close()

# Feature Importance
importance_df = X_train.columns.to_frame(index=False, name="Feature")
importance_df["Importance"] = model.feature_importances_
importance_df = importance_df.sort_values(by="Importance", ascending=False)

plt.figure(figsize=(10, 6))
plt.barh(
    importance_df["Feature"].head(10),
    importance_df["Importance"].head(10)
)
plt.gca().invert_yaxis()
plt.title("NSL-KDD Top 10 Important Features")
plt.xlabel("Importance")
plt.savefig("../reports/nsl-kdd_feature_importance.png", dpi=300, bbox_inches="tight")
plt.close()

# ROC Curve
fpr, tpr, thresholds = roc_curve(y_test, probs)

plt.figure(figsize=(7, 6))
plt.plot(fpr, tpr, label=f"Random Forest AUC = {roc:.6f}")
plt.plot([0, 1], [0, 1], "r--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("NSL-KDD ROC Curve")
plt.legend()
plt.savefig("../reports/nsl-kdd_roc_curve.png", dpi=300, bbox_inches="tight")
plt.close()

print("\n" + "=" * 50)
print("Reports and PNG files saved successfully!")
print("=" * 50)
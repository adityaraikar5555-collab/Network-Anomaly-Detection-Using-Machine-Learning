"""Inference module for Network Anomaly Detection using CICIDS-2017 trained model.

Provides reusable prediction functions for individual network traffic records,
suitable for integration with FastAPI backend services and real-time inference pipelines.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import math
import joblib
import numpy as np
import pandas as pd

# Default model and encoder locations relative to this file
_BASE_DIR = Path(__file__).resolve().parent.parent
_DEFAULT_MODEL_PATH = _BASE_DIR / "models" / "cicids_anomaly_model.pkl"
_DEFAULT_ENCODER_PATH = _BASE_DIR / "models" / "cicids_label_encoder.pkl"

# Exact 78 features in the required order as expected by the trained CICIDS-2017 Random Forest model
CICIDS_FEATURE_NAMES: Tuple[str, ...] = (
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
)

# Global cache for loaded model and label encoder instances
_CACHED_MODEL = None
_CACHED_ENCODER = None


def load_cicids_artifacts(
    model_path: Optional[Union[str, Path]] = None,
    encoder_path: Optional[Union[str, Path]] = None,
    force_reload: bool = False,
) -> Tuple[Any, Any]:
    """Load and cache the trained CICIDS-2017 model and label encoder artifacts.

    Args:
        model_path: Optional path to the serialized model file (.pkl).
        encoder_path: Optional path to the serialized label encoder file (.pkl).
        force_reload: If True, forces reloading artifacts from disk even if cached.

    Returns:
        Tuple of (model, label_encoder).

    Raises:
        FileNotFoundError: If the model or encoder file does not exist.
    """
    global _CACHED_MODEL, _CACHED_ENCODER

    if not force_reload and _CACHED_MODEL is not None and _CACHED_ENCODER is not None:
        return _CACHED_MODEL, _CACHED_ENCODER

    target_model_path = Path(model_path) if model_path else _DEFAULT_MODEL_PATH
    target_encoder_path = Path(encoder_path) if encoder_path else _DEFAULT_ENCODER_PATH

    if not target_model_path.exists():
        raise FileNotFoundError(f"Model file not found at: {target_model_path}")
    if not target_encoder_path.exists():
        raise FileNotFoundError(f"Label encoder file not found at: {target_encoder_path}")

    _CACHED_MODEL = joblib.load(target_model_path)
    _CACHED_ENCODER = joblib.load(target_encoder_path)

    return _CACHED_MODEL, _CACHED_ENCODER


def validate_and_preprocess_cicids(
    features: Union[Dict[str, Any], pd.Series, pd.DataFrame, List[Any], Tuple[Any, ...], np.ndarray]
) -> pd.DataFrame:
    """Validate and preprocess input features for CICIDS model inference.

    Handles feature validation, whitespace stripping in feature names, type casting,
    and ordering into a single-row pandas DataFrame matching the model's exact feature names.

    Args:
        features: Input traffic record as a dictionary mapping feature names to values,
                  a pandas Series/DataFrame row, or an ordered sequence of 78 numeric values.

    Returns:
        pandas DataFrame of shape (1, 78) with float64 values and exact feature column names.

    Raises:
        TypeError: If input is not a supported type or contains non-numeric values.
        ValueError: If features are missing, extra unexpected features are provided,
                    feature count is incorrect, or values contain NaN/Infinity/None.
    """
    if features is None:
        raise ValueError("Input features cannot be None.")

    # Convert pandas DataFrame / Series to dict
    if isinstance(features, pd.DataFrame):
        if len(features) != 1:
            raise ValueError(f"Expected a single record (1 row), got DataFrame with {len(features)} rows.")
        features = features.iloc[0].to_dict()
    elif isinstance(features, pd.Series):
        features = features.to_dict()

    # Dictionary input validation
    if isinstance(features, dict):
        if not features:
            raise ValueError("Input features dictionary is empty.")

        # Strip whitespace from keys to match preprocessing during training
        cleaned_dict: Dict[str, Any] = {
            (str(k).strip() if isinstance(k, str) else k): v
            for k, v in features.items()
        }

        required_set = set(CICIDS_FEATURE_NAMES)
        provided_set = set(cleaned_dict.keys())

        missing = required_set - provided_set
        if missing:
            raise ValueError(
                f"Missing {len(missing)} required feature(s): {sorted(list(missing))}"
            )

        extra = provided_set - required_set
        if extra:
            raise ValueError(
                f"Unexpected {len(extra)} extra feature(s): {sorted(list(extra))}"
            )

        # Validate values and build ordered vector
        vector: List[float] = []
        for feature_name in CICIDS_FEATURE_NAMES:
            val = cleaned_dict[feature_name]
            if val is None:
                raise ValueError(f"Feature '{feature_name}' contains None value.")

            # Check numeric conversion
            try:
                if isinstance(val, bool):
                    num_val = float(int(val))
                else:
                    num_val = float(val)
            except (ValueError, TypeError) as err:
                raise TypeError(
                    f"Feature '{feature_name}' must be numeric, got value '{val}' of type {type(val).__name__}."
                ) from err

            if math.isnan(num_val) or math.isinf(num_val):
                raise ValueError(
                    f"Feature '{feature_name}' contains invalid non-finite value '{val}' (NaN or Infinity)."
                )

            vector.append(num_val)

        return pd.DataFrame([vector], columns=list(CICIDS_FEATURE_NAMES), dtype=np.float64)

    # Sequence / Array input validation
    elif isinstance(features, (list, tuple, np.ndarray)):
        arr = np.asarray(features)
        # Flatten if shape is (1, 78)
        if arr.ndim == 2 and arr.shape[0] == 1:
            arr = arr.reshape(-1)

        if arr.ndim != 1:
            raise ValueError(f"Expected 1D sequence of features, got array of shape {arr.shape}.")

        if len(arr) != len(CICIDS_FEATURE_NAMES):
            raise ValueError(
                f"Incorrect feature count: expected {len(CICIDS_FEATURE_NAMES)} features, got {len(arr)}."
            )

        vector = []
        for i, val in enumerate(arr):
            feature_name = CICIDS_FEATURE_NAMES[i]
            if val is None:
                raise ValueError(f"Feature at index {i} ('{feature_name}') is None.")

            try:
                if isinstance(val, bool):
                    num_val = float(int(val))
                else:
                    num_val = float(val)
            except (ValueError, TypeError) as err:
                raise TypeError(
                    f"Feature at index {i} ('{feature_name}') must be numeric, got value '{val}'."
                ) from err

            if math.isnan(num_val) or math.isinf(num_val):
                raise ValueError(
                    f"Feature at index {i} ('{feature_name}') contains non-finite value (NaN or Infinity)."
                )

            vector.append(num_val)

        return pd.DataFrame([vector], columns=list(CICIDS_FEATURE_NAMES), dtype=np.float64)

    else:
        raise TypeError(
            f"Unsupported input type '{type(features).__name__}'. Expected dict, list, tuple, np.ndarray, or pd.Series."
        )


def predict_cicids(
    features: Union[Dict[str, Any], pd.Series, pd.DataFrame, List[Any], Tuple[Any, ...], np.ndarray],
    model: Optional[Any] = None,
    label_encoder: Optional[Any] = None,
) -> Dict[str, Any]:
    """Predict whether a network traffic record is BENIGN or an ATTACK using CICIDS-2017 model.

    Args:
        features: Traffic record features (dictionary of feature_name: value, or 78-element sequence).
        model: Optional pre-loaded RandomForestClassifier model instance.
        label_encoder: Optional pre-loaded LabelEncoder instance.

    Returns:
        Dictionary containing prediction result, confidence score, and model identifier:
        {
            "prediction": "BENIGN",  # or "ATTACK"
            "confidence": 0.9323,
            "model": "cicids_random_forest"
        }

    Raises:
        ValueError: On missing features, extra features, invalid counts, or non-finite values.
        TypeError: On non-numeric values or unsupported input structures.
    """
    # 1. Validate & preprocess input into model-compatible DataFrame
    X = validate_and_preprocess_cicids(features)

    # 2. Get cached or provided model artifacts
    if model is None or label_encoder is None:
        cached_m, cached_le = load_cicids_artifacts()
        model = model or cached_m
        label_encoder = label_encoder or cached_le

    # 3. Model inference
    raw_pred = model.predict(X)
    numeric_class = int(raw_pred[0])

    # 4. Probabilities & confidence
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[0]
        # Classes are [0, 1] mapped to ['ATTACK', 'BENIGN']
        confidence = float(probabilities[numeric_class])
    else:
        confidence = 1.0

    # 5. Decode label name
    # LabelEncoder classes_: ['ATTACK', 'BENIGN'] -> 0: 'ATTACK', 1: 'BENIGN'
    if hasattr(label_encoder, "inverse_transform"):
        label_name = str(label_encoder.inverse_transform([numeric_class])[0])
    else:
        mapping = {0: "ATTACK", 1: "BENIGN"}
        label_name = mapping.get(numeric_class, str(numeric_class))

    return {
        "prediction": label_name,
        "confidence": round(confidence, 4),
        "model": "cicids_random_forest",
    }

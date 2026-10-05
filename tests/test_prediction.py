"""Unit tests for the CICIDS prediction inference layer."""

import math
import unittest
import numpy as np
import pandas as pd

from src.prediction import (
    CICIDS_FEATURE_NAMES,
    load_cicids_artifacts,
    validate_and_preprocess_cicids,
    predict_cicids,
)


def get_sample_cicids_features() -> dict:
    """Helper to return a valid 78-feature dictionary with representative network traffic values."""
    sample = {col: 0.0 for col in CICIDS_FEATURE_NAMES}
    sample.update({
        "Destination Port": 80,
        "Flow Duration": 120000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 8,
        "Total Length of Fwd Packets": 1500,
        "Total Length of Bwd Packets": 3200,
        "Fwd Packet Length Max": 500,
        "Fwd Packet Length Min": 40,
        "Fwd Packet Length Mean": 150.0,
        "Fwd Packet Length Std": 25.0,
        "Bwd Packet Length Max": 800,
        "Bwd Packet Length Min": 40,
        "Bwd Packet Length Mean": 400.0,
        "Bwd Packet Length Std": 50.0,
        "Flow Bytes/s": 39166.67,
        "Flow Packets/s": 150.0,
        "Flow IAT Mean": 6666.67,
        "Flow IAT Std": 1200.0,
        "Flow IAT Max": 15000,
        "Flow IAT Min": 100,
        "Fwd IAT Total": 110000,
        "Fwd IAT Mean": 12222.22,
        "Fwd IAT Std": 2000.0,
        "Fwd IAT Max": 25000,
        "Fwd IAT Min": 200,
        "Bwd IAT Total": 100000,
        "Bwd IAT Mean": 14285.71,
        "Bwd IAT Std": 2500.0,
        "Bwd IAT Max": 30000,
        "Bwd IAT Min": 150,
        "Fwd Header Length": 200,
        "Bwd Header Length": 160,
        "Fwd Packets/s": 83.33,
        "Bwd Packets/s": 66.67,
        "Min Packet Length": 40,
        "Max Packet Length": 800,
        "Packet Length Mean": 261.11,
        "Packet Length Std": 45.0,
        "Packet Length Variance": 2025.0,
        "ACK Flag Count": 1,
        "Average Packet Size": 275.6,
        "Avg Fwd Segment Size": 150.0,
        "Avg Bwd Segment Size": 400.0,
        "Init_Win_bytes_forward": 8192,
        "Init_Win_bytes_backward": 65535,
        "act_data_pkt_fwd": 6,
        "min_seg_size_forward": 20,
    })
    return sample


class TestCicidsPrediction(unittest.TestCase):
    """Test suite for validate_and_preprocess_cicids and predict_cicids."""

    def test_artifacts_loading(self):
        """Verify model and label encoder artifacts load correctly and have matching classes."""
        model, le = load_cicids_artifacts()
        self.assertIsNotNone(model)
        self.assertIsNotNone(le)
        self.assertEqual(len(model.feature_names_in_), 78)
        self.assertEqual(list(le.classes_), ["ATTACK", "BENIGN"])

    def test_valid_dict_prediction(self):
        """Test prediction with a valid 78-feature dictionary."""
        sample = get_sample_cicids_features()
        result = predict_cicids(sample)

        self.assertIsInstance(result, dict)
        self.assertIn("prediction", result)
        self.assertIn("confidence", result)
        self.assertIn("model", result)
        self.assertIn(result["prediction"], ["BENIGN", "ATTACK"])
        self.assertIsInstance(result["confidence"], float)
        self.assertTrue(0.0 <= result["confidence"] <= 1.0)
        self.assertEqual(result["model"], "cicids_random_forest")

    def test_valid_dict_with_whitespace_keys(self):
        """Test dictionary with leading/trailing whitespace in feature names."""
        sample = get_sample_cicids_features()
        whitespace_sample = {f" {k} ": v for k, v in sample.items()}
        result = predict_cicids(whitespace_sample)
        self.assertIn(result["prediction"], ["BENIGN", "ATTACK"])

    def test_valid_sequence_prediction(self):
        """Test prediction with valid 78-element list and numpy array."""
        sample_dict = get_sample_cicids_features()
        sample_list = [sample_dict[col] for col in CICIDS_FEATURE_NAMES]

        res_list = predict_cicids(sample_list)
        self.assertIn(res_list["prediction"], ["BENIGN", "ATTACK"])

        res_arr = predict_cicids(np.array(sample_list))
        self.assertIn(res_arr["prediction"], ["BENIGN", "ATTACK"])

    def test_valid_pandas_input(self):
        """Test prediction with pandas Series and 1-row DataFrame."""
        sample_dict = get_sample_cicids_features()
        series = pd.Series(sample_dict)
        res_series = predict_cicids(series)
        self.assertIn(res_series["prediction"], ["BENIGN", "ATTACK"])

        df = pd.DataFrame([sample_dict])
        res_df = predict_cicids(df)
        self.assertIn(res_df["prediction"], ["BENIGN", "ATTACK"])

    def test_missing_feature(self):
        """Test that missing required features raises ValueError."""
        sample = get_sample_cicids_features()
        del sample["Destination Port"]
        with self.assertRaises(ValueError) as ctx:
            predict_cicids(sample)
        self.assertIn("Missing 1 required feature", str(ctx.exception))
        self.assertIn("Destination Port", str(ctx.exception))

    def test_extra_feature(self):
        """Test that unexpected extra features raises ValueError."""
        sample = get_sample_cicids_features()
        sample["unknown_security_score"] = 99.9
        with self.assertRaises(ValueError) as ctx:
            predict_cicids(sample)
        self.assertIn("Unexpected 1 extra feature", str(ctx.exception))
        self.assertIn("unknown_security_score", str(ctx.exception))

    def test_wrong_feature_count(self):
        """Test that sequence with incorrect number of features raises ValueError."""
        short_list = [0.0] * 50
        with self.assertRaises(ValueError) as ctx:
            predict_cicids(short_list)
        self.assertIn("Incorrect feature count: expected 78 features, got 50", str(ctx.exception))

    def test_invalid_type_value(self):
        """Test that non-numeric value in dictionary raises TypeError."""
        sample = get_sample_cicids_features()
        sample["Destination Port"] = "invalid_string"
        with self.assertRaises(TypeError) as ctx:
            predict_cicids(sample)
        self.assertIn("must be numeric", str(ctx.exception))

    def test_nan_and_inf_values(self):
        """Test that NaN and Infinity values raise ValueError."""
        sample_nan = get_sample_cicids_features()
        sample_nan["Flow Duration"] = float("nan")
        with self.assertRaises(ValueError) as ctx:
            predict_cicids(sample_nan)
        self.assertIn("NaN or Infinity", str(ctx.exception))

        sample_inf = get_sample_cicids_features()
        sample_inf["Flow Bytes/s"] = float("inf")
        with self.assertRaises(ValueError) as ctx:
            predict_cicids(sample_inf)
        self.assertIn("NaN or Infinity", str(ctx.exception))

    def test_none_value(self):
        """Test that None value raises ValueError."""
        sample = get_sample_cicids_features()
        sample["Total Fwd Packets"] = None
        with self.assertRaises(ValueError) as ctx:
            predict_cicids(sample)
        self.assertIn("contains None value", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the live CICIDS-2017 flow feature extractor.

These tests do not depend on any committed PCAP or CICIDS dataset files.
They build small synthetic flows in-memory and verify that the extractor
produces exactly the 78 features required by the trained Random Forest model,
in the exact training order, with no NaN/Inf, and that the model accepts the
resulting vector.
"""

import math
import unittest

from src.cicids_features import CICIDS_FEATURE_NAMES
from src.flow_extractor import (
    MICROSECONDS_PER_SECOND,
    FlowExtractor,
    NetworkFlow,
    PacketRecord,
)
from src.prediction import (
    load_cicids_artifacts,
    predict_cicids,
    predict_flow,
)


def _make_packet(
    timestamp,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    length,
    *,
    protocol=6,
    ip_header_length=20,
    tcp_header_length=20,
    tcp_window_size=0,
    syn=False,
    ack=False,
    fin=False,
    rst=False,
    psh=False,
    urg=False,
    cwe=False,
    ece=False,
):
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        ip_header_length=ip_header_length,
        tcp_header_length=tcp_header_length,
        tcp_window_size=tcp_window_size,
        syn=syn,
        ack=ack,
        fin=fin,
        rst=rst,
        psh=psh,
        urg=urg,
        cwe=cwe,
        ece=ece,
    )


def build_sample_flow():
    """Build one bidirectional TCP flow with forward and backward packets."""

    extractor = FlowExtractor()

    # Forward direction (client -> server), 3 packets.
    extractor.add_packet(_make_packet(
        1000.000000, "192.168.1.10", "10.0.0.5", 51000, 443, 1466,
        tcp_window_size=65535, syn=True, ack=True, psh=True,
    ))
    extractor.add_packet(_make_packet(
        1000.002000, "192.168.1.10", "10.0.0.5", 51000, 443, 1200,
        tcp_window_size=65535, ack=True, psh=True,
    ))
    extractor.add_packet(_make_packet(
        1000.005000, "192.168.1.10", "10.0.0.5", 51000, 443, 800,
        tcp_window_size=65535, ack=True, urg=True,
    ))

    # Backward direction (server -> client), 2 packets.
    extractor.add_packet(_make_packet(
        1000.001000, "10.0.0.5", "192.168.1.10", 443, 51000, 54,
        tcp_window_size=32768, ack=True, psh=True, cwe=True, ece=True,
    ))
    extractor.add_packet(_make_packet(
        1000.010000, "10.0.0.5", "192.168.1.10", 443, 51000, 60,
        tcp_window_size=32768, ack=True, fin=True, rst=True,
    ))

    return extractor.get_flows()[0]


class TestFlowExtractorSchema(unittest.TestCase):
    """Schema / count / order / finiteness of the extracted feature vector."""

    def setUp(self):
        self.flow = build_sample_flow()

    def test_extract_features_has_exactly_78_features(self):
        features = self.flow.extract_features()
        self.assertEqual(len(features), 78)
        self.assertEqual(len(CICIDS_FEATURE_NAMES), 78)

    def test_feature_names_match_training_schema_exactly(self):
        features = self.flow.extract_features()
        self.assertEqual(set(features.keys()), set(CICIDS_FEATURE_NAMES))
        self.assertEqual(len(features), len(set(features)))

    def test_feature_order_matches_training_schema(self):
        # Fails loudly if anyone reorders the canonical schema or the extractor.
        features = self.flow.extract_features()
        self.assertEqual(list(features.keys()), list(CICIDS_FEATURE_NAMES))

    def test_feature_order_matches_model_artifact(self):
        model, _ = load_cicids_artifacts()
        self.assertEqual(list(CICIDS_FEATURE_NAMES), list(model.feature_names_in_))

    def test_all_feature_values_are_numeric(self):
        for name, value in self.flow.extract_features().items():
            self.assertIsInstance(value, float, f"{name} is not a float")

    def test_no_nan_or_inf(self):
        for name, value in self.flow.extract_features().items():
            self.assertFalse(math.isnan(value), f"{name} is NaN")
            self.assertFalse(math.isinf(value), f"{name} is Inf")

    def test_feature_vector_length_and_order(self):
        vector = self.flow.to_feature_vector()
        features = self.flow.extract_features()
        self.assertEqual(len(vector), 78)
        self.assertEqual(vector, [features[n] for n in CICIDS_FEATURE_NAMES])

    def test_extraction_is_deterministic(self):
        first = self.flow.to_feature_vector()
        second = self.flow.to_feature_vector()
        self.assertEqual(first, second)

    def test_fwd_psh_flags_present_and_correct(self):
        features = self.flow.extract_features()
        self.assertIn("Fwd PSH Flags", features)
        # Two forward packets were flagged PSH in build_sample_flow().
        self.assertEqual(features["Fwd PSH Flags"], 2.0)
        self.assertEqual(features["Bwd PSH Flags"], 1.0)

    def test_flow_duration_is_microseconds(self):
        features = self.flow.extract_features()
        expected_us = self.flow.duration * MICROSECONDS_PER_SECOND
        self.assertAlmostEqual(features["Flow Duration"], expected_us)

    def test_tcp_flag_counts(self):
        features = self.flow.extract_features()
        self.assertEqual(features["SYN Flag Count"], 1.0)
        self.assertEqual(features["FIN Flag Count"], 1.0)
        self.assertEqual(features["RST Flag Count"], 1.0)
        self.assertEqual(features["ACK Flag Count"], 5.0)
        self.assertEqual(features["PSH Flag Count"], 3.0)
        self.assertEqual(features["URG Flag Count"], 1.0)
        self.assertEqual(features["CWE Flag Count"], 1.0)
        self.assertEqual(features["ECE Flag Count"], 1.0)


class TestFlowExtractorEdgeCases(unittest.TestCase):
    """Edge cases must still yield a complete, finite 78-feature schema."""

    def test_single_packet_flow(self):
        extractor = FlowExtractor()
        extractor.add_packet(_make_packet(
            500.0, "10.0.0.1", "10.0.0.2", 12345, 80, 100,
            tcp_window_size=8192, syn=True,
        ))
        features = extractor.get_flows()[0].extract_features()
        self.assertEqual(len(features), 78)
        self.assertEqual(list(features.keys()), list(CICIDS_FEATURE_NAMES))
        for value in features.values():
            self.assertFalse(math.isnan(value))
            self.assertFalse(math.isinf(value))

    def test_empty_flow(self):
        flow = NetworkFlow(key=("a", "b", 6))
        features = flow.extract_features()
        self.assertEqual(len(features), 78)
        self.assertEqual(list(features.keys()), list(CICIDS_FEATURE_NAMES))
        self.assertTrue(all(v == 0.0 for v in features.values()))

    def test_multiple_flows(self):
        extractor = FlowExtractor()
        extractor.add_packet(_make_packet(1.0, "10.0.0.1", "10.0.0.2", 1, 80, 100, ack=True))
        extractor.add_packet(_make_packet(2.0, "10.0.0.3", "10.0.0.4", 2, 22, 120, ack=True))
        vectors = extractor.get_feature_vectors()
        self.assertEqual(len(vectors), 2)
        for vector in vectors:
            self.assertEqual(len(vector), 78)
            self.assertTrue(all(isinstance(v, float) for v in vector))


class TestFlowModelInference(unittest.TestCase):
    """End-to-end integration: extractor -> existing model -> label/confidence."""

    def setUp(self):
        self.flow = build_sample_flow()

    def test_model_accepts_extracted_vector(self):
        vector = self.flow.to_feature_vector()
        result = predict_cicids(vector)
        self.assertIsInstance(result, dict)

    def test_prediction_label_and_confidence_ranges(self):
        result = predict_cicids(self.flow.to_feature_vector())
        self.assertIn(result["prediction"], ["BENIGN", "ATTACK"])
        self.assertIsInstance(result["confidence"], float)
        self.assertTrue(0.0 <= result["confidence"] <= 1.0)
        self.assertEqual(result["model"], "cicids_random_forest")

    def test_model_accepts_extracted_dict(self):
        result = predict_cicids(self.flow.extract_features())
        self.assertIn(result["prediction"], ["BENIGN", "ATTACK"])

    def test_predict_flow_end_to_end(self):
        result = predict_flow(self.flow)
        self.assertIn(result["prediction"], ["BENIGN", "ATTACK"])
        self.assertTrue(0.0 <= result["confidence"] <= 1.0)

    def test_predict_flow_rejects_non_flow(self):
        with self.assertRaises(TypeError):
            predict_flow({"not": "a flow"})


if __name__ == "__main__":
    unittest.main()

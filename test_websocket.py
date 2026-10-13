import websocket
import json


def on_message(ws, message):
    data = json.loads(message)

    print("\n--- DETECTION EVENT ---")
    print("Prediction :", data["prediction"])
    print("Attack     :", data["attack_type"])
    print("Confidence :", data["confidence"])
    print("Severity   :", data["severity"])
    print("Timestamp  :", data["timestamp"])


ws = websocket.WebSocketApp(
    "ws://127.0.0.1:8000/ws/detections",
    on_message=on_message
)

ws.run_forever()
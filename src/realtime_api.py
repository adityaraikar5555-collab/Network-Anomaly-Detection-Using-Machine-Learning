from fastapi import FastAPI, WebSocket
import asyncio
import random
from datetime import datetime

app = FastAPI(
    title="Network Anomaly Detector - Real-Time API"
)


@app.get("/")
def root():
    return {
        "status": "online",
        "service": "Real-Time Network Anomaly Detector"
    }


@app.websocket("/ws/detections")
async def detection_stream(websocket: WebSocket):

    await websocket.accept()

    print("Extension connected to detection stream.")

    try:
        while True:

            # TEMPORARY simulated detection.
            # Later this will come from the real
            # packet capture + ML pipeline.

            attacks = [
                {
                    "prediction": "NORMAL",
                    "attack_type": "NONE",
                    "confidence": 0.96,
                    "severity": "LOW"
                },
                {
                    "prediction": "ANOMALY",
                    "attack_type": "PORT_SCAN",
                    "confidence": 0.94,
                    "severity": "HIGH"
                },
                {
                    "prediction": "ANOMALY",
                    "attack_type": "DDOS",
                    "confidence": 0.91,
                    "severity": "CRITICAL"
                }
            ]

            result = random.choice(attacks)

            result["timestamp"] = datetime.now().isoformat()

            await websocket.send_json(result)

            await asyncio.sleep(5)

    except Exception as error:
        print(f"Extension disconnected: {error}")
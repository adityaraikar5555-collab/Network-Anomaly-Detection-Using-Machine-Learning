let socket = null;

const WEBSOCKET_URL =
    "ws://127.0.0.1:8000/ws/detections";


function connectWebSocket() {

    console.log(
        "Connecting to Network Anomaly Detector..."
    );

    socket = new WebSocket(WEBSOCKET_URL);


    socket.onopen = () => {

        console.log(
            "Connected to detection server."
        );

    };


    socket.onmessage = (event) => {

        try {

            const detection =
                JSON.parse(event.data);


            console.log(
                "Detection received:",
                detection
            );


            chrome.storage.local.set({
                latestDetection: detection
            });

        } catch (error) {

            console.error(
                "Invalid detection data:",
                error
            );

        }

    };


    socket.onerror = (error) => {

        console.error(
            "WebSocket error:",
            error
        );

    };


    socket.onclose = () => {

        console.log(
            "Detection server disconnected."
        );

        socket = null;

        // Try reconnecting after 5 seconds
        setTimeout(
            connectWebSocket,
            5000
        );

    };

}


// Start connection
connectWebSocket();
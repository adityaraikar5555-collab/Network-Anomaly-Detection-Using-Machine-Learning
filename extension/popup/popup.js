document.addEventListener("DOMContentLoaded", () => {

    const statusIcon =
        document.getElementById("statusIcon");

    const statusText =
        document.getElementById("statusText");

    const statusDescription =
        document.getElementById("statusDescription");

    const anomalyScore =
        document.getElementById("anomalyScore");

    const scoreProgress =
        document.getElementById("scoreProgress");

    const detectionStatus =
        document.getElementById("detectionStatus");

    const severity =
        document.getElementById("severity");

    const attackType =
        document.getElementById("attackType");

    const currentSite =
        document.getElementById("currentSite");


    /*
     * Get current website
     */

    chrome.tabs.query(
        {
            active: true,
            currentWindow: true
        },

        (tabs) => {

            if (
                tabs &&
                tabs.length > 0
            ) {

                currentSite.textContent =
                    tabs[0].url ||
                    "Unknown";

            }

        }
    );


    /*
     * Display detection result
     */

    function displayDetection(
        result
    ) {

        if (!result) {
            return;
        }


        const score =
            Math.round(
                result.confidence * 100
            );


        anomalyScore.textContent =
            `${score}%`;

        scoreProgress.style.width =
            `${score}%`;


        /*
         * NORMAL
         */

        if (
            result.prediction ===
            "NORMAL"
        ) {

            statusIcon.textContent =
                "✓";

            statusText.textContent =
                "SYSTEM NORMAL";

            statusDescription.textContent =
                "No anomaly detected";

            detectionStatus.textContent =
                "Normal";

            severity.textContent =
                result.severity;

            attackType.textContent =
                result.attack_type;

        }


        /*
         * ANOMALY
         */

        else {

            statusIcon.textContent =
                "!";

            statusText.textContent =
                "ANOMALY DETECTED";

            statusDescription.textContent =
                "Suspicious network activity detected";

            detectionStatus.textContent =
                "Anomaly";

            severity.textContent =
                result.severity;

            attackType.textContent =
                result.attack_type;

        }

    }


    /*
     * Load latest detection
     */

    chrome.storage.local.get(
        ["latestDetection"],
        (data) => {

            displayDetection(
                data.latestDetection
            );

        }
    );


    /*
     * Listen for new detections
     */

    chrome.storage.onChanged.addListener(
        (changes, areaName) => {

            if (
                areaName === "local" &&
                changes.latestDetection
            ) {

                displayDetection(
                    changes.latestDetection.newValue
                );

            }

        }
    );

});
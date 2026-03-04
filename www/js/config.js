// config.js

(function () {
    console.log("[config.js] Loading...");

    // window.API_BASE = 'http://127.0.0.1:5000';
    // window.API_BASE = 'http://localhost:5000';

    // For local network
    // window.API_BASE = 'http://192.168.18.16:5000';  

    // For deployed backend (Render)
    window.API_BASE = 'https://farmlink-backend-rx5g.onrender.com';

    console.log("[config.js] API_BASE set to:", window.API_BASE);


    window.config = window.config || {};
    window.config.apiBaseUrl = window.API_BASE;

    // Sensor helper
    window.convertToPercent = function (raw) {
        return Math.round((1023 - raw) / 1023 * 100);
    };
})();
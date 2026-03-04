// dashboard.js - Owner Dashboard (with manual valve control)

let chart = null;
let selectedSensor = 'moisture';
let selectedTimeRange = '7days';

// ─── Valve Control Functions ────────────────────────────────────────────────
function updateValveUI(isOpen) {
    const stateEl = document.getElementById('solenoidState');
    const dotEl   = document.getElementById('solenoidDot');

    if (!stateEl || !dotEl) return;

    const text  = isOpen ? 'OPEN' : 'CLOSED';
    const color = isOpen ? '#27ae60' : '#e74c3c';
    const dot   = isOpen ? '🟢' : '🔴';

    stateEl.textContent = text;
    stateEl.style.color = color;
    dotEl.innerHTML     = dot;
}

async function sendValveCommand(action) {
    if (!confirm(`Are you sure you want to ${action.toUpperCase()} the valve?`)) {
        return;
    }

    const token = localStorage.getItem('token') || '';
    if (!token) {
        alert("Session expired. Please log in again.");
        return;
    }

    try {
        const res = await fetch(API_BASE + '/api/control', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ action: action.toLowerCase() })  // "open" or "close"
        });

        const json = await res.json();

        if (res.ok && json.ok) {
            alert(`Command sent: Valve will ${action.toLowerCase()}`);
            // Optimistic UI update (real state comes from next sensor poll)
            updateValveUI(action.toLowerCase() === 'open');
        } else {
            alert("Failed: " + (json.error || "Unknown error"));
        }
    } catch (err) {
        alert("Network error: " + err.message);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('sensorSelect')?.addEventListener('change', e => {
        selectedSensor = e.target.value;
        destroyChart();
        createChart();
    });

    document.getElementById('timeRangeSelect')?.addEventListener('change', e => {
        selectedTimeRange = e.target.value;
        destroyChart();
        createChart();
    });

    // ─── Attach valve control buttons ────────────────────────────────
    document.getElementById('openValveBtn')?.addEventListener('click', () => sendValveCommand('open'));
    document.getElementById('closeValveBtn')?.addEventListener('click', () => sendValveCommand('close'));

    setInterval(update, 1500);
    update();
    createChart();

    // Hide "Connecting..." after first load attempt
    setTimeout(() => {
        const statusEl = document.getElementById('status');
        if (statusEl) statusEl.style.display = 'none';
    }, 3000);
});

function destroyChart() {
    if (chart) {
        chart.destroy();
        chart = null;
    }
}

function createChart() {
    const canvas = document.getElementById('chart');
    if (!canvas) return;

    canvas.style.display = 'block';
    canvas.style.width = '100%';
    canvas.style.height = '220px';

    let points = selectedTimeRange === 'today' ? 24 :
                 selectedTimeRange === '7days' ? 168 :
                 selectedTimeRange === '30days' ? 720 : 24;

    const ctx = canvas.getContext('2d');
    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(points).fill(''),
            datasets: [{
                label: selectedSensor.charAt(0).toUpperCase() + selectedSensor.slice(1),
                data: Array(points).fill(0),
                borderColor: '#27ae60',
                backgroundColor: 'rgba(39,174,96,0.12)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { 
                y: { 
                    beginAtZero: true,
                    max: selectedSensor === 'temperature' ? 50 :
                         selectedSensor === 'light' ? 1000 : 100
                }
            },
            plugins: { 
                legend: { display: false }
            }
        }
    });
}

async function update() {
    try {
        const token = localStorage.getItem('token') || '';

        const [dataRes, statusRes] = await Promise.all([
            fetch(API_BASE + '/api/data', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Authorization': token ? `Bearer ${token}` : ''
                }
            }),
            fetch(API_BASE + '/api/status', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Authorization': token ? `Bearer ${token}` : ''
                }
            })
        ]);

        if (!dataRes.ok) throw new Error(`Data fetch failed: ${dataRes.status}`);
        if (!statusRes.ok) throw new Error(`Status fetch failed: ${statusRes.status}`);

        const d = await dataRes.json();
        const status = await statusRes.json();
        const zone = d.zoneA || {};

        // Update sensor readings
        document.getElementById('moistA').innerText = (zone.moisture ?? 0).toFixed(1) + '%';
        document.getElementById('humA').innerText   = (zone.humidity ?? 0).toFixed(1) + '%';
        document.getElementById('tempA').innerText  = (zone.temperature ?? 0).toFixed(1) + '°C';
        document.getElementById('lightA').innerText = (zone.light ?? '--');

        // ─── Update valve state display ────────────────────────────────
        if (zone && typeof zone.solenoid_open !== 'undefined') {
            updateValveUI(zone.solenoid_open);
        }

        // Connection status
        const loraEl = document.getElementById('lora-status');
        if (loraEl) {
            loraEl.textContent = `LoRa: ${status.lora ? 'Connected' : 'Disconnected'}`;
            loraEl.style.color = status.lora ? '#27ae60' : '#e74c3c';
        }

        ['mcu1', 'mcu2'].forEach(id => {
            const el = document.getElementById(`${id}-status`);
            if (el) {
                const online = status[id] === true;
                el.innerHTML = online ? '🟢 Online' : '🔴 Offline';
                el.className = online ? 'status-dot status-online' : 'status-dot status-offline';
            }
        });

        // ─── SIMPLE CURRENT TIME DISPLAY ────────────────────────────────
        function updateClock() {
            const now = new Date();
            const timeStr = now.toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false   // 24-hour format
            });
            document.getElementById('current-time').textContent = timeStr;
        }

        // Run immediately + every second
        updateClock();
        setInterval(updateClock, 1000);

        // Chart: push real value
        if (chart) {
            const val = zone[selectedSensor] ?? 0;
            chart.data.datasets[0].data.push(val);

            const maxPoints = selectedTimeRange === 'today' ? 24 :
                              selectedTimeRange === '7days' ? 168 :
                              selectedTimeRange === '30days' ? 720 : 24;

            while (chart.data.datasets[0].data.length > maxPoints) {
                chart.data.datasets[0].data.shift();
            }

            chart.update();
        }

    } catch (err) {
        console.error("Update failed:", err);
        const statusEl = document.getElementById('lora-status') || document.getElementById('status');
        if (statusEl) {
            statusEl.textContent = 'Update failed – check connection';
            statusEl.style.color = '#e74c3c';
        }
    }
}
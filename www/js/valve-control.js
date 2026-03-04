// valve-control.js - Manual open/close valve for both roles

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
            // Optimistic update
            updateValveUI(action.toLowerCase() === 'open');
        } else {
            alert("Failed: " + (json.error || "Unknown error"));
        }
    } catch (err) {
        alert("Network error: " + err.message);
    }
}

// Attach button listeners
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('openValveBtn')?.addEventListener('click', () => sendValveCommand('open'));
    document.getElementById('closeValveBtn')?.addEventListener('click', () => sendValveCommand('close'));
});

// Export for use in dashboard update function
window.updateValveUI = updateValveUI;
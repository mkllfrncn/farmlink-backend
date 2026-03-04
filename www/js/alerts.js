// alerts.js - Enhanced for critical farm/IoT alerts

const AUTO_REFRESH_INTERVAL = 30000; // 30 seconds
let autoRefreshTimer = null;

async function loadAlerts() {
    const container = document.getElementById('alertslist');
    if (!container) return;

    container.innerHTML = '<p class="text-center text-muted">Loading alerts...</p>';

    try {
        const token = localStorage.getItem('token') || '';
        if (!token) {
            container.innerHTML = '<p class="text-danger text-center">Please log in again.</p>';
            return;
        }

        const res = await fetch(API_BASE + '/api/alerts', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!res.ok) {
            throw new Error(`Server error: ${res.status}`);
        }

        const alerts = await res.json();

        container.innerHTML = '';

        if (!alerts || alerts.length === 0) {
            container.innerHTML = `
                <div class="alert alert-success text-center mb-0">
                    <strong>✅ All good!</strong><br>No active alerts at the moment.
                </div>`;
            return;
        }

        // Sort by severity descending (critical first)
        alerts.sort((a, b) => (b.severity || 0) - (a.severity || 0));

        alerts.forEach(a => {
            const isCritical = (a.severity || 0) >= 7;

            const div = document.createElement('div');
            div.className = `alert alert-${isCritical ? 'danger' : 'warning'} mb-3 shadow-sm`;

            let icon = '⚠️';
            let titleClass = '';
            if (a.title?.toLowerCase().includes('disconnect') || 
                a.title?.toLowerCase().includes('offline') || 
                a.message?.toLowerCase().includes('no data') ||
                a.message?.toLowerCase().includes('mcu')) {
                icon = '🔴';
                titleClass = 'text-danger fw-bold';
            } else if (a.title?.toLowerCase().includes('low battery') || 
                       a.title?.toLowerCase().includes('battery low')) {
                icon = '🔋';
            } else if (a.title?.toLowerCase().includes('valve') || 
                       a.title?.toLowerCase().includes('stuck') || 
                       a.title?.toLowerCase().includes('pump')) {
                icon = '🚰';
            } else if (a.title?.toLowerCase().includes('moisture') || 
                       a.title?.toLowerCase().includes('dry') || 
                       a.title?.toLowerCase().includes('critical low')) {
                icon = '🌵';
            }

            div.innerHTML = `
                <div class="d-flex align-items-start">
                    <span class="fs-3 me-3">${icon}</span>
                    <div class="flex-grow-1">
                        <strong class="${titleClass}">${a.title || 'Alert'}</strong>
                        <p class="mb-1">${a.message || 'No details available'}</p>
                        <small class="text-muted">
                            ${a.timestamp ? new Date(a.timestamp).toLocaleString() : 'Recent'} 
                            • Severity: ${a.severity || '?'}
                        </small>
                    </div>
                </div>
            `;

            container.appendChild(div);
        });

    } catch (e) {
        console.error(e);
        container.innerHTML = `
            <div class="alert alert-danger text-center mb-0">
                <strong>Error loading alerts</strong><br>
                ${e.message || 'Network or server issue'}<br>
                <small>Try refreshing or check your connection.</small>
            </div>`;
    }
}

// Refresh button
document.getElementById('refresh')?.addEventListener('click', loadAlerts);

// Auto-refresh
function startAutoRefresh() {
    if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    autoRefreshTimer = setInterval(loadAlerts, AUTO_REFRESH_INTERVAL);
}

// Start everything
document.addEventListener('DOMContentLoaded', () => {
    loadAlerts();
    startAutoRefresh();
});
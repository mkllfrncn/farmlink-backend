async function loadNotifications() {
    const container = document.getElementById('notifications');
   
    // If the page doesn't have a notifications container → do nothing (no crash)
    if (!container) {
        console.log("[notifications.js] No #notifications element found on this page – skipping");
        return;
    }

    try {
        const res = await fetch(API_BASE + '/api/alerts');
        const alerts = await res.json();
       
        container.innerHTML = '';
       
        if (alerts.length === 0) {
            container.innerHTML = '<li>No new alerts</li>';
            return;
        }

        alerts.forEach(a => {
            const li = document.createElement('li');
            li.className = 'notification-item';
            li.innerHTML = `
                <strong>${a.title || 'Alert'}</strong>:
                ${a.message || 'No message'}
                <small>(${new Date(a.ts * 1000).toLocaleTimeString()})</small>
            `;
            container.appendChild(li);
        });
    } catch (e) {
        console.error("Notifications fetch error:", e);
        container.innerHTML = '<li>Error loading notifications</li>';
    }
}

document.getElementById('notifRefresh')?.addEventListener('click', loadNotifications);

// Auto-load only if container exists
if (document.getElementById('notifications')) {
    loadNotifications();
}
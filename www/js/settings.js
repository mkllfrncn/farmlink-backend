function getAuthToken() {
    return localStorage.getItem('token') || '';
}

async function loadSettings() {
    try {
        const token = getAuthToken();
        if (!token) throw new Error("No token - log in again");
        const res = await fetch(API_BASE + '/api/settings', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!res.ok) throw new Error(`Failed: ${res.status}`);
        const s = await res.json();
        if (!s.ok) throw new Error(s.error);

        // Safe set (check if element exists)
        const setValue = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.value = value;
        };
        setValue('zoneA_min', s.threshold_zoneA_min ?? 40);
        setValue('zoneA_max', s.threshold_zoneA_max ?? 70);
        // Remove zoneB if not needed
        setValue('autoWaterTime', s.auto_water_time ?? "06:00");
        setValue('duration', s.duration ?? 10);
        setValue('maxTemp', s.max_temp ?? 35);
        setValue('minHumidity', s.min_humidity ?? 50);

        const isReadOnly = s.read_only;
        const saveBtn = document.getElementById('saveChanges');
        if (saveBtn) {
            saveBtn.disabled = isReadOnly;
            saveBtn.style.display = isReadOnly ? 'none' : 'block';
        }
        if (isReadOnly) {
            document.querySelectorAll('input, select').forEach(el => el.disabled = true);
            if (!document.getElementById('readOnlyNote')) {
                const note = document.createElement('p');
                note.id = 'readOnlyNote';
                note.textContent = 'View only - contact owner for changes';
                note.style.color = 'red';
                document.getElementById('settingsForm')?.appendChild(note);
            }
        }
    } catch (err) {
        alert('Failed to load settings: ' + err.message);
    }
}

async function saveSettings() {
    const token = getAuthToken();
    if (!token) return alert("No token - log in again");

    const payload = {
        threshold_zoneA_min: parseFloat(document.getElementById('zoneA_min')?.value) || 40,
        threshold_zoneA_max: parseFloat(document.getElementById('zoneA_max')?.value) || 70,
        // Removed zoneB
        auto_water_time: document.getElementById('autoWaterTime')?.value || "06:00",
        duration: parseInt(document.getElementById('duration')?.value) || 10,
        max_temp: parseFloat(document.getElementById('maxTemp')?.value) || 35,
        min_humidity: parseFloat(document.getElementById('minHumidity')?.value) || 50,
        // Removed auto_mode (no checkbox)
    };

    try {
        const res = await fetch(API_BASE + '/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify(payload)
        });
        const j = await res.json();
        if (j.ok) alert('Settings saved!');
        else alert('Failed: ' + j.error);
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

// Event listeners
document.getElementById('saveChanges')?.addEventListener('click', saveSettings);
document.getElementById('reconnectLora')?.addEventListener('click', async () => {
    try {
        const token = getAuthToken();
        const res = await fetch(API_BASE + '/api/reconnect-lora', {  // Fixed path
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const j = await res.json();
        alert(j.message || 'Reconnect sent');
    } catch (err) {
        alert('Failed to reconnect: ' + err.message);
    }
});
document.getElementById('startAutoWater')?.addEventListener('click', async () => {
    try {
        const token = getAuthToken();
        const res = await fetch(API_BASE + '/api/start-auto', {  // Fixed path
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const j = await res.json();
        if (j.ok) alert('Auto watering started!');
        else alert('Error: ' + j.error);
    } catch (err) {
        alert('Failed: ' + err.message);
    }
});

document.addEventListener('DOMContentLoaded', loadSettings);
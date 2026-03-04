// profile.js – Complete version with server-side avatar storage (PostgreSQL)
// Last updated: March 2026 – improved error handling for 405, better debug logs

document.addEventListener('DOMContentLoaded', async () => {
    // ─── Load basic user info from localStorage ───────────────────────────
    const storedUserRaw = localStorage.getItem('user');
    let storedUser = {};

    try {
        storedUser = JSON.parse(storedUserRaw || '{}');
    } catch (parseErr) {
        console.error("[PROFILE] JSON parse error:", parseErr);
        alert("Session data corrupted. Please log in again.");
        localStorage.clear();
        location.href = "login.html";
        return;
    }

    const userEmail = storedUser.email?.trim();
    if (!userEmail) {
        console.warn("[PROFILE] No valid email in session");
        alert("No email found in your session. Please log in again.");
        localStorage.clear();
        location.href = "login.html";
        return;
    }

    // ─── Populate UI fields ───────────────────────────────────────────────
    document.getElementById('displayName').textContent = storedUser.fullname || "User";
    document.getElementById('username').textContent   = userEmail.split('@')[0] || "user";
    document.getElementById('fullname').value         = storedUser.fullname || "";
    document.getElementById('email').value            = userEmail;

    // Show Logs button only for owners
    const isOwner = (storedUser.role || "sakada").toLowerCase() === "owner";
    const logsBtn = document.getElementById('logsBtn');
    if (logsBtn) logsBtn.classList.toggle('hidden', !isOwner);

    // ─── Load avatar + latest user data from server ───────────────────────
    const avatarPreview = document.getElementById('avatarPreview');
    const token = localStorage.getItem('token') || '';

    console.log("[PROFILE] Token for /api/me:", token ? token.substring(0, 20) + '...' : 'MISSING TOKEN');

    if (!token) {
        console.error("[PROFILE] No token found - authentication will fail");
        alert("Session token missing. Please log in again.");
        localStorage.clear();
        location.href = "login.html";
        return;
    }

    try {
        const res = await fetch(API_BASE + '/api/me', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        console.log("[PROFILE] /api/me status:", res.status);

        if (!res.ok) {
            if (res.status === 401 || res.status === 403) {
                alert("Session expired or unauthorized. Please log in again.");
                localStorage.clear();
                location.href = "login.html";
                return;
            }
            throw new Error(`HTTP ${res.status}`);
        }

        const data = await res.json();

        if (data.ok) {
            // Set avatar if exists
            if (data.avatar && avatarPreview) {
                avatarPreview.innerHTML = `<img src="${data.avatar}" alt="Profile Picture" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`;
            } else if (avatarPreview) {
                avatarPreview.innerHTML = '👤';
            }

            // Sync fullname if server has a newer value
            if (data.fullname && data.fullname !== storedUser.fullname) {
                storedUser.fullname = data.fullname;
                localStorage.setItem('user', JSON.stringify(storedUser));
                document.getElementById('displayName').textContent = data.fullname;
                document.getElementById('fullname').value = data.fullname;
            }
        }
    } catch (err) {
        console.error("[PROFILE] Failed to load user data from server:", err);
        if (avatarPreview) avatarPreview.innerHTML = '👤';
    }

    // ─── Save fullname changes ────────────────────────────────────────────
    const saveBtn = document.getElementById('saveBtn');
    if (saveBtn) {
        saveBtn.addEventListener('click', async () => {
            const newFullname = document.getElementById('fullname').value.trim();
            if (!newFullname) {
                alert("Full name cannot be empty");
                return;
            }

            try {
                const res = await fetch(API_BASE + '/api/update_profile', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ fullname: newFullname })
                });

                console.log("[PROFILE] /api/update_profile status:", res.status);

                const result = await res.json();

                if (result.ok) {
                    storedUser.fullname = newFullname;
                    localStorage.setItem('user', JSON.stringify(storedUser));
                    document.getElementById('displayName').textContent = newFullname;
                    alert("Profile updated successfully!");
                    location.reload();  // Refresh to sync everything
                } else {
                    alert("Failed to update profile: " + (result.error || "Unknown error"));
                }
            } catch (err) {
                console.error("[SAVE FULLNAME] Error:", err);
                alert("Network error while saving changes: " + err.message);
            }
        });
    }

    // ─── Avatar upload to server ──────────────────────────────────────────
    const avatarInput = document.getElementById('avatarInput');

    if (avatarInput) {
        avatarInput.addEventListener('change', async e => {
            const file = e.target.files[0];
            if (!file) return;

            console.log("[AVATAR] File selected:", file.name, "Size:", file.size, "Type:", file.type);

            // Basic validation
            if (file.size > 2 * 1024 * 1024) {
                alert("Image is too large (maximum 2 MB)");
                return;
            }

            if (!file.type.startsWith('image/')) {
                alert("Please select an image file");
                return;
            }

            const reader = new FileReader();

            reader.onload = async ev => {
                const base64Data = ev.target.result;
                console.log("[AVATAR] Base64 generated, length:", base64Data.length);

                // Optimistic UI update
                if (avatarPreview) {
                    avatarPreview.innerHTML = `<img src="${base64Data}" alt="Avatar" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`;
                }

                // Send to backend
                try {
                    const response = await fetch(API_BASE + '/api/update_avatar', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify({ avatar: base64Data })
                    });

                    console.log("[AVATAR] Upload status:", response.status);

                    // Check if response is JSON or HTML error page
                    let result;
                    const text = await response.text();
                    try {
                        result = JSON.parse(text);
                    } catch (jsonErr) {
                        console.error("[AVATAR] Server returned non-JSON:", text.substring(0, 200));
                        throw new Error("Server returned invalid response (likely an error page)");
                    }

                    if (result.ok) {
                        console.log("[AVATAR] Successfully uploaded to server");
                        alert("Profile picture updated! Refreshing...");
                        location.reload();  // Reload to get fresh /api/me data
                    } else {
                        alert("Failed to save picture: " + (result.error || "Server error"));
                    }
                } catch (err) {
                    console.error("[AVATAR UPLOAD ERROR]", err);
                    let msg = "Network error while uploading picture.";
                    if (err.message.includes('405')) {
                        msg += "\nThe server does not have the /api/update_avatar endpoint yet (405 Method Not Allowed).";
                        msg += "\nPlease add the route to your backend (app.py) and redeploy.";
                    } else if (err.message.includes('JSON')) {
                        msg += "\nServer returned HTML instead of JSON – check backend route exists.";
                    }
                    alert(msg + "\n" + err.message);
                }
            };

            reader.onerror = () => {
                alert("Failed to read the selected image");
            };

            reader.readAsDataURL(file);
        });
    }
});
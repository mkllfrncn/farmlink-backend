// js/auth.js – Login handler (works in both browser and Cordova)

function attachLoginHandler() {
    const loginBtn = document.getElementById('login');

    if (!loginBtn) {
        console.error("Login button (#login) not found in DOM");
        return;
    }

    console.log("Login button found – attaching click handler");

    loginBtn.addEventListener('click', async () => {
        console.log("Login button clicked!");

        // Get form values safely
        const email      = document.getElementById('email')?.value?.trim() || '';
        const password   = document.getElementById('password')?.value?.trim() || '';
        const role       = document.getElementById('role')?.value || 'sakada';
        const accessCode = document.getElementById('admincode')?.value?.trim() || '';

        // Improved logging – shows if code was actually entered
        console.log("Form values →", { 
            email, 
            role, 
            accessCodeProvided: !!accessCode,
            accessCodeLength: accessCode.length,
            accessCodeFirstFew: accessCode.substring(0, 4) + (accessCode.length > 4 ? '...' : '')
        });

        // Basic client-side validation
        if (!email || !password) {
            alert('Please enter email and password');
            return;
        }

        if (role === 'owner') {
            if (!accessCode) {
                alert('Owner login requires the Access Code');
                return;
            }
            if (accessCode.length < 6) {
                alert('The access code seems too short. Please check it.');
                return;
            }
        }

        // Build payload – using the field name the backend expects
        const payload = { 
            email, 
            password, 
            role 
        };

        if (role === 'owner') {
            payload.access_code = accessCode;   // ← This matches what backend expects
        }

        try {
            console.log("Sending login request to:", window.API_BASE + '/api/login');
            console.log("Payload being sent:", payload);

            console.log("PAYLOAD BEFORE SEND:", JSON.stringify(payload, null, 2));

            const response = await fetch(`${window.API_BASE}/api/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            console.log("Login response status:", response.status);

            if (!response.ok) {
                let errorData;
                try {
                    errorData = await response.json();
                } catch {
                    errorData = {};
                }
                const errorMsg = errorData.error || `Login failed (${response.status})`;
                console.error("Server error response:", errorData);
                throw new Error(errorMsg);
            }

            const result = await response.json();

            if (!result.ok) {
                alert(result.error || 'Login failed');
                return;
            }

            // ─── Store tokens ────────────────────────────────────────
            const accessToken = result.token || result.access_token;

            if (!accessToken) {
                console.error("No token received from server");
                alert("Login succeeded but no token was returned. Please try again.");
                return;
            }

            localStorage.setItem('token', accessToken);
            localStorage.setItem('access_token', accessToken);

            if (result.refresh_token) {
                localStorage.setItem('refresh_token', result.refresh_token);
            }

            // ─── Store user data ─────────────────────────────────────
            localStorage.setItem('user', JSON.stringify({
                email: result.user?.email || email,
                fullname: result.user?.fullname || 'User',
                role: result.user?.role || role
            }));

            console.log("Login success – tokens saved");

            // Redirect based on role
            const dashboardPath = (result.user?.role || role) === 'owner'
                ? 'dashboard-owner.html'
                : 'dashboard-worker.html';

            console.log("Redirecting to:", dashboardPath);
            window.location.href = dashboardPath;

        } catch (err) {
            console.error('Login error:', err);
            alert('Login failed: ' + (err.message || 'Unknown error') + '\nCheck console (F12) for details');
        }
    });
}

// Attach handler when DOM is ready (browser) or deviceready (Cordova)
if (window.cordova) {
    document.addEventListener('deviceready', () => {
        console.log("deviceready fired – attaching login handler");
        attachLoginHandler();
    }, false);
} else {
    document.addEventListener('DOMContentLoaded', () => {
        console.log("Browser mode – attaching login handler");
        attachLoginHandler();
    });
}
const API_BASE = "http://127.0.0.1:5000/api";
const TOKEN_KEY = "phishguard_token";

let currentUser = null;
let resetToken = null;

const authScreen = document.getElementById("authScreen");
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const forgotPasswordForm = document.getElementById("forgotPasswordForm");
const verifyOtpForm = document.getElementById("verifyOtpForm");
const resetPasswordForm = document.getElementById("resetPasswordForm");
const authMessage = document.getElementById("authMessage");

const sidebar = document.getElementById("sidebar");
const mainContent = document.getElementById("mainContent");

const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const resultCard = document.getElementById("resultCard");

const dashboardPage = document.getElementById("dashboardPage");
const historyPage = document.getElementById("historyPage");

const TOKEN = () => sessionStorage.getItem(TOKEN_KEY);


// ==========================================
// AUTHENTICATION SCREEN
// ==========================================

function showAuth(mode = "login") {
    authScreen.classList.remove("hidden");
    sidebar.classList.add("hidden");
    mainContent.classList.add("hidden");

    authMessage.textContent = "";
    if (mode !== "reset") {
    resetToken = null;
}

    const forms = {
        login: loginForm,
        register: registerForm,
        forgot: forgotPasswordForm,
        verify: verifyOtpForm,
        reset: resetPasswordForm
    };

    Object.entries(forms).forEach(([key, form]) => {
        form.classList.toggle("hidden", key !== mode);
    });

    const titles = {
        login: "Welcome User",
        register: "Create Account",
        forgot: "Forgot Password?",
        verify: "Verify Your Email",
        reset: "Reset Password"
    };

    const descriptions = {
        login: "Login to access your personal security dashboard.",
        register: "Create your PhishGuard account.",
        forgot: "Enter your registered email to receive a password reset code.",
        verify: "Enter the 6-digit OTP sent to your email.",
        reset: "Choose a new password for your account."
    };

    document.getElementById("authTitle").textContent =
        titles[mode] || titles.login;

    document.getElementById("authDescription").textContent =
        descriptions[mode] || descriptions.login;

    document.getElementById("authSwitch").classList.toggle(
        "hidden", mode !== "login"
    );

    document.getElementById("loginSwitch").classList.toggle(
        "hidden", mode !== "register"
    );
}


function showAuthMessage(message, success = false) {
    authMessage.textContent = message;
    authMessage.style.color = success ? "#21966b" : "#d94350";
}


function saveToken(token) {
    sessionStorage.setItem(TOKEN_KEY, token);
}


function clearToken() {
    sessionStorage.removeItem(TOKEN_KEY);
}


function showApp(user) {
    currentUser = user || {};

    authScreen.classList.add("hidden");
    sidebar.classList.remove("hidden");
    mainContent.classList.remove("hidden");

    document.getElementById("loggedInUser").textContent =
        currentUser.username || currentUser.name || currentUser.email || "User";

    showPage("dashboard");
    updateDashboard();
    renderHistory();
}


// ==========================================
// API REQUEST
// ==========================================

async function apiRequest(endpoint, options = {}) {
    const headers = { ...(options.headers || {}) };

    if (options.body) {
        headers["Content-Type"] = "application/json";
    }

    const publicAuthEndpoints = [
        "/auth/login",
        "/auth/register",
        "/auth/forgot-password",
        "/auth/verify-reset-otp",
        "/auth/reset-password"
    ];

    const isPublicAuthEndpoint =
        publicAuthEndpoints.includes(endpoint);

    const token = TOKEN();

    if (token && !isPublicAuthEndpoint) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers
    });

    let data = {};

    try {
        data = await response.json();
    } catch {
        data = {};
    }

    if (
        response.status === 401 &&
        token &&
        !isPublicAuthEndpoint
    ) {
        clearToken();
        currentUser = null;

        showAuth("login");
        showAuthMessage("Session expired. Please login again.");
    }

    if (!response.ok) {
        throw new Error(
            data.message || data.error || "Request failed."
        );
    }

    return data;
}


// ==========================================
// LOGIN
// ==========================================

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const identifier =
        document.getElementById("loginEmail").value.trim();

    const password =
        document.getElementById("loginPassword").value;

    const button = document.getElementById("loginButton");

    try {
        button.disabled = true;
        button.textContent = "Logging in...";

        const data = await apiRequest("/auth/login", {
            method: "POST",
            body: JSON.stringify({
                identifier,
                password
            })
        });

        if (!data.token) {
            throw new Error("Login token was not received.");
        }

        saveToken(data.token);

        showApp(data.user || {
            username: identifier
        });

        showToast("Login successful!");
        loginForm.reset();

    } catch (error) {
        showAuthMessage(error.message);

    } finally {
        button.disabled = false;
        button.textContent = "Login";
    }
});


// ==========================================
// REGISTRATION
// ==========================================

registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const name =
        document.getElementById("registerName").value.trim();

    const username =
        document.getElementById("registerUsername").value.trim();

    const email =
        document.getElementById("registerEmail").value.trim();

    const password =
        document.getElementById("registerPassword").value;

    const button = document.getElementById("registerButton");

    try {
        button.disabled = true;
        button.textContent = "Creating account...";

        const data = await apiRequest("/auth/register", {
            method: "POST",
            body: JSON.stringify({
                name,
                username,
                email,
                password
            })
        });

        if (!data.token) {
            throw new Error("Registration token was not received.");
        }

        saveToken(data.token);

        showApp(data.user || {
            name,
            username,
            email
        });

        showToast("Account created successfully!");
        registerForm.reset();

    } catch (error) {
        showAuthMessage(error.message);

    } finally {
        button.disabled = false;
        button.textContent = "Create Account";
    }
});


// ==========================================
// FORGOT PASSWORD
// ==========================================

document.getElementById("forgotPasswordLink")
    .addEventListener("click", () => {
        forgotPasswordForm.reset();
        verifyOtpForm.reset();
        resetPasswordForm.reset();

        showAuth("forgot");
    });


forgotPasswordForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const email =
        document.getElementById("forgotEmail").value.trim();

    const button = document.getElementById("forgotButton");

    try {
        button.disabled = true;
        button.textContent = "Sending OTP...";

        const data = await apiRequest("/auth/forgot-password", {
            method: "POST",
            body: JSON.stringify({ email })
        });

        // Keep email for the OTP verification step.
        document.getElementById("otpEmail").value = email;

        showAuth("verify");

        showAuthMessage(
            data.message ||
            "If an account exists with this email, a password reset code will be sent.",
            true
        );

    } catch (error) {
        showAuthMessage(error.message);

    } finally {
        button.disabled = false;
        button.textContent = "Send OTP";
    }
});


// ==========================================
// VERIFY OTP
// ==========================================

verifyOtpForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const email =
        document.getElementById("otpEmail").value.trim();

    const otp =
        document.getElementById("resetOtp").value.trim();

    const button =
        document.getElementById("verifyOtpButton");

    try {
        button.disabled = true;
        button.textContent = "Verifying...";

        const data = await apiRequest("/auth/verify-reset-otp", {
            method: "POST",
            body: JSON.stringify({
                email,
                otp
            })
        });

        if (!data.reset_token) {
            throw new Error("Reset token was not received.");
        }

        resetToken = data.reset_token;

        resetPasswordForm.reset();

        showAuth("reset");

        showAuthMessage(
            "OTP verified successfully. Create your new password.",
            true
        );

    } catch (error) {
        showAuthMessage(error.message);

    } finally {
        button.disabled = false;
        button.textContent = "Verify OTP";
    }
});


// ==========================================
// RESET PASSWORD
// ==========================================

resetPasswordForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const newPassword =
        document.getElementById("newPassword").value;

    const confirmPassword =
        document.getElementById("confirmNewPassword").value;

    const button =
        document.getElementById("resetPasswordButton");

    if (newPassword !== confirmPassword) {
        showAuthMessage("Passwords do not match.");
        return;
    }

    if (newPassword.length < 8 || newPassword.length > 128) {
        showAuthMessage("Password must contain 8-128 characters.");
        return;
    }

    if (!resetToken) {
        showAuthMessage("Reset session expired. Please request a new OTP.");
        return;
    }

    try {
        button.disabled = true;
        button.textContent = "Resetting...";

        const data = await apiRequest("/auth/reset-password", {
            method: "POST",
            body: JSON.stringify({
                reset_token: resetToken,
                new_password: newPassword
            })
        });

        resetToken = null;

        loginForm.reset();
        resetPasswordForm.reset();

        showAuth("login");

        showAuthMessage(
            data.message || "Password reset successfully. Please login.",
            true
        );

    } catch (error) {
        showAuthMessage(error.message);

    } finally {
        button.disabled = false;
        button.textContent = "Reset Password";
    }
});


// ==========================================
// AUTH NAVIGATION
// ==========================================

document.getElementById("showRegister")
    .addEventListener("click", () => {
        registerForm.reset();
        showAuth("register");
    });


document.getElementById("showLogin")
    .addEventListener("click", () => {
        loginForm.reset();
        showAuth("login");
    });


document.getElementById("backToLoginFromForgot")
    .addEventListener("click", () => {
        showAuth("login");
    });


document.getElementById("backToForgot")
    .addEventListener("click", () => {
        showAuth("forgot");
    });


// ==========================================
// PASSWORD SHOW / HIDE
// ==========================================

document.querySelectorAll(".password-toggle").forEach(button => {
    button.addEventListener("click", () => {
        const targetId = button.dataset.passwordTarget;
        const input = document.getElementById(targetId);

        if (!input) return;

        const isPassword = input.type === "password";

        input.type = isPassword ? "text" : "password";
        button.textContent = isPassword ? "Hide" : "Show";

        button.setAttribute(
            "aria-label",
            isPassword ? "Hide password" : "Show password"
        );
    });
});


// ==========================================
// LOGOUT
// ==========================================

document.getElementById("logoutButton")
    .addEventListener("click", async () => {
        try {
            await apiRequest("/auth/logout", {
                method: "POST"
            });

        } catch (error) {
            console.warn("Logout request:", error.message);
        }

        clearToken();
        currentUser = null;

        showAuth("login");
        showAuthMessage("You have logged out successfully.", true);
    });


// ==========================================
// SESSION CHECK
// ==========================================

async function checkSession() {
    if (!TOKEN()) {
        showAuth("login");
        return;
    }

    try {
        const data = await apiRequest("/auth/me");
        showApp(data.user || data);

    } catch (error) {
        clearToken();
        showAuth("login");
    }
}


// ==========================================
// PAGE NAVIGATION
// ==========================================

function showPage(page) {
    dashboardPage.classList.toggle("active", page === "dashboard");
    historyPage.classList.toggle("active", page === "history");

    document.querySelectorAll("[data-page]").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.page === page
        );
    });
}


document.querySelectorAll("[data-page]").forEach(button => {
    button.addEventListener("click", () => {
        showPage(button.dataset.page);

        if (button.dataset.page === "history") {
            renderHistory();
        }
    });
});


document.getElementById("backDashboardButton")
    .addEventListener("click", () => {
        showPage("dashboard");
    });


document.getElementById("viewHistoryButton")
    .addEventListener("click", () => {
        showPage("history");
        renderHistory();
    });


document.getElementById("menuToggle")
    .addEventListener("click", () => {
        sidebar.classList.toggle("expanded");
    });


// ==========================================
// TOAST
// ==========================================

function showToast(message) {
    const toast = document.getElementById("toast");

    toast.textContent = message;
    toast.classList.add("show");

    setTimeout(() => {
        toast.classList.remove("show");
    }, 3000);
}


// ==========================================
// HTML ESCAPE
// ==========================================

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[char]);
}


// ==========================================
// RISK CLASS
// ==========================================

function getRiskClass(level) {
    const value = String(level || "").toLowerCase();

    if (value.includes("high")) return "high";
    if (value.includes("suspicious")) return "suspicious";

    return "low";
}


// ==========================================
// RDAP DISPLAY
// ==========================================

function displayRdapInfo(result) {
    let container = document.getElementById("rdapInfo");

    if (!container) {
        container = document.createElement("div");
        container.id = "rdapInfo";
        container.className = "rdap-info";

        const disclaimer = resultCard.querySelector(".disclaimer");
        resultCard.insertBefore(container, disclaimer);
    }

    const status = result.rdap_status || "unknown";
    const age = result.domain_age_days;
    const expiry = result.days_to_expiry;

    let ageText = "Unavailable";

    if (age != null && Number.isFinite(Number(age))) {
        const totalDays = Math.max(0, Math.floor(Number(age)));
        const years = Math.floor(totalDays / 365);
        const days = totalDays % 365;

        ageText = years > 0
            ? `${years} Years, ${days} Days`
            : `${days} Days`;
    }

    container.innerHTML = `
        <h3>Domain Registration Information</h3>

        <div class="rdap-grid">

            <div class="rdap-item">
                <span>Domain Age</span>
                <strong>${escapeHTML(ageText)}</strong>
            </div>

            <div class="rdap-item">
                <span>Days Until Expiry</span>
                <strong>
                    ${expiry != null
                        ? escapeHTML(expiry) + " days"
                        : "Unavailable"}
                </strong>
            </div>

            <div class="rdap-item">
                <span>RDAP Status</span>
                <strong>${escapeHTML(status)}</strong>
            </div>

        </div>
    `;
}


// ==========================================
// DISPLAY ANALYSIS RESULT
// ==========================================

function displayResult(data) {
    const result = data.result || data;

    resultCard.classList.remove("hidden");

    const score = Number(result.risk_score ?? 0);
    const level = result.risk_level || "Unknown";

    const badge = document.getElementById("riskBadge");

    badge.textContent = level;
    badge.className = `risk-badge ${getRiskClass(level)}`;

    const scoreCircle = document.getElementById("scoreCircle");

    scoreCircle.className =
        `score-circle ${getRiskClass(level)}`;

    document.getElementById("riskScore").textContent = score;

    document.getElementById("resultUrl").textContent =
        result.url || urlInput.value;

    document.getElementById("resultTitle").textContent =
        result.message || `${level} Result`;

    document.getElementById("resultMessage").textContent =
        result.summary || result.description ||
        "Review the detected indicators below.";

    // Indicators

    const indicatorList = document.getElementById("indicatorList");

    const indicators = result.indicators || [];

    if (indicators.length > 0) {
        indicatorList.innerHTML = indicators.map(item => {
            const description = typeof item === "string"
                ? item
                : item.description || item.message || item.name || "";

            return `
                <div class="indicator-item">
                    ${escapeHTML(description)}
                </div>
            `;
        }).join("");

    } else {
        indicatorList.innerHTML = `
            <div class="indicator-item">
                No major warning signs found.
            </div>
        `;
    }

    // RDAP

    displayRdapInfo(result);

    resultCard.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


// ==========================================
// URL SCAN
// ==========================================

scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {
        showToast("Please enter a URL.");
        return;
    }

    const button = document.getElementById("analyzeButton");

    try {
        button.disabled = true;
        button.textContent = "Analyzing...";

        const data = await apiRequest("/scan", {
            method: "POST",
            body: JSON.stringify({ url })
        });

        displayResult(data);

        showToast("Analysis completed!");

        await updateDashboard();
        await renderHistory();

    } catch (error) {
        showToast(error.message);

    } finally {
        button.disabled = false;
        button.innerHTML = 'Analyze Link <span>→</span>';
    }
});


// ==========================================
// DEMO LINKS
// ==========================================

document.querySelectorAll(".demo-link").forEach(button => {
    button.addEventListener("click", () => {
        urlInput.value = button.dataset.url;
        scanForm.requestSubmit();
    });
});


// ==========================================
// TABLE ROW
// ==========================================

function createTableRow(scan) {
    const level = scan.risk_level || "Unknown";

    const scanDate = scan.scanned_at || scan.created_at;

let date = "—";

if (scanDate) {
    const timestamp = String(scanDate).replace(" ", "T");
    const parsedDate = new Date(timestamp + "Z");

    date = parsedDate.toLocaleString("en-GB", {
        timeZone: "Asia/Dhaka",
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: true
    });
}

    return `
        <tr>
            <td>${escapeHTML(scan.url || "—")}</td>

            <td>
                <span class="table-risk ${getRiskClass(level)}">
                    ${escapeHTML(level)}
                </span>
            </td>

            <td>${escapeHTML(scan.risk_score ?? "—")}/100</td>

            <td>${escapeHTML(date)}</td>
        </tr>
    `;
}


// ==========================================
// DASHBOARD STATISTICS
// ==========================================

async function updateDashboard() {
    try {
        const data = await apiRequest("/stats");
        const stats = data.stats || data;

        document.getElementById("totalScans").textContent =
            stats.total_scans ?? 0;

        document.getElementById("highRisk").textContent =
            stats.high_risk ?? stats.high_risk_count ?? 0;

        document.getElementById("suspiciousCount").textContent =
            stats.suspicious ?? stats.suspicious_count ?? 0;

        document.getElementById("lowRisk").textContent =
            stats.low_risk ?? stats.low_risk_count ?? 0;

        const recentData = await apiRequest("/scans?limit=5");
        const scans = recentData.scans || [];

        const body = document.getElementById("recentTableBody");

        body.innerHTML = scans.length
            ? scans.map(createTableRow).join("")
            : `<tr><td colspan="4" class="empty-state">No scans yet.</td></tr>`;

    } catch (error) {
        console.error("Dashboard error:", error);
    }
}


// ==========================================
// HISTORY
// ==========================================

async function renderHistory() {
    const body = document.getElementById("historyTableBody");

    try {
        const data = await apiRequest("/scans?limit=100");
        const scans = data.scans || [];

        body.innerHTML = scans.length
            ? scans.map(createTableRow).join("")
            : `<tr><td colspan="4" class="empty-state">No scan history found.</td></tr>`;

    } catch (error) {
        console.error("History error:", error);
    }
}


// ==========================================
// CLEAR HISTORY
// ==========================================

document.getElementById("clearHistoryButton")
    .addEventListener("click", async () => {

        if (!confirm("Are you sure you want to delete your scan history?")) {
            return;
        }

        try {
            await apiRequest("/scans", {
                method: "DELETE"
            });

            showToast("Scan history cleared!");

            await renderHistory();
            await updateDashboard();

        } catch (error) {
            showToast(error.message);
        }
    });


// ==========================================
// INITIALIZE
// ==========================================

async function initializeApp() {
    await checkSession();
}

initializeApp();
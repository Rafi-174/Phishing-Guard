const API_BASE = "http://127.0.0.1:5000/api";

const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const resultCard = document.getElementById("resultCard");
const sidebar = document.getElementById("sidebar");


// SIDEBAR

document.getElementById("menuToggle").addEventListener("click", () => {
  sidebar.classList.toggle("expanded");
});


// PAGE NAVIGATION

function showPage(page) {

  document.querySelectorAll(".page").forEach(section => {
    section.classList.remove("active");
  });

  document.querySelectorAll(".nav-item").forEach(button => {
    button.classList.remove("active");
  });

  if (page === "history") {

    document.getElementById("historyPage").classList.add("active");

    document.querySelector('[data-page="history"]')
      .classList.add("active");

    renderHistory();

  } else {

    document.getElementById("dashboardPage").classList.add("active");

    document.querySelector('[data-page="dashboard"]')
      .classList.add("active");

  }
}


document.querySelectorAll(".nav-item").forEach(button => {

  button.addEventListener("click", () => {
    showPage(button.dataset.page);
  });

});


document.getElementById("viewHistoryButton").addEventListener("click", () => {
  showPage("history");
});


document.getElementById("backDashboardButton").addEventListener("click", () => {
  showPage("dashboard");
});


// TOAST MESSAGE

function showToast(message) {

  const toast = document.getElementById("toast");

  toast.textContent = message;
  toast.classList.add("show");

  setTimeout(() => {
    toast.classList.remove("show");
  }, 2500);

}


// SAFE HTML OUTPUT

function escapeHTML(value) {

  return String(value).replace(/[&<>"']/g, char => ({

    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"

  })[char]);

}


// API REQUEST HELPER

async function apiRequest(endpoint, options = {}) {

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,

    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.message || "Something went wrong.");
  }

  return data;

}


// RISK CLASS

function getRiskClass(level) {

  if (level === "High Risk") {
    return "high";
  }

  if (level === "Suspicious") {
    return "suspicious";
  }

  return "low";

}


// DISPLAY RESULT

function displayResult(result) {

  resultCard.classList.remove("hidden");

  const badge = document.getElementById("riskBadge");
  const circle = document.getElementById("scoreCircle");


  badge.textContent = result.risk_level;
  badge.className = "risk-badge";

  circle.className = "score-circle";


  if (result.risk_level === "High Risk") {

    badge.classList.add("high");
    circle.classList.add("high");

  } else if (result.risk_level === "Suspicious") {

    badge.classList.add("suspicious");
    circle.classList.add("suspicious");

  }


  document.getElementById("riskScore").textContent =
    result.risk_score;

  document.getElementById("resultUrl").textContent =
    result.url;


  let title = "";
  let message = "";


  if (result.risk_level === "Low Risk") {

    title = "No major warning signs found";

    message =
      "The URL has a relatively low score based on the current detection rules.";

  } else if (result.risk_level === "Suspicious") {

    title = "Some warning signs detected";

    message =
      "This URL contains indicators that may require extra attention.";

  } else {

    title = "Multiple warning signs detected";

    message =
      "This URL has several suspicious characteristics. Avoid opening it unless its source is verified.";

  }


  document.getElementById("resultTitle").textContent = title;

  document.getElementById("resultMessage").textContent = message;


  const indicatorList = document.getElementById("indicatorList");


  if (!result.indicators || result.indicators.length === 0) {

    indicatorList.innerHTML = `
      <span class="indicator-item">
        No suspicious indicators detected
      </span>
    `;

  } else {

    indicatorList.innerHTML = result.indicators.map(item => `
      <span class="indicator-item">
        ${escapeHTML(item)}
      </span>
    `).join("");

  }


  resultCard.scrollIntoView({
    behavior: "smooth",
    block: "center"
  });

}


// SCAN FORM

scanForm.addEventListener("submit", async event => {

  event.preventDefault();

  const url = urlInput.value.trim();

  if (!url) {
    showToast("Please enter a URL.");
    return;
  }

  const button = document.getElementById("analyzeButton");

  button.disabled = true;
  button.textContent = "Analyzing...";

  try {

    const data = await apiRequest("/scan", {

      method: "POST",

      body: JSON.stringify({
        url: url
      })

    });


    displayResult(data.result);

    await updateDashboard();

    showToast("Link analysis completed!");

  } catch (error) {

    showToast(error.message);

  } finally {

    button.disabled = false;
    button.innerHTML = 'Analyze Link <span>→</span>';

  }

});


// DEMO BUTTONS

document.querySelectorAll(".demo-link").forEach(button => {

  button.addEventListener("click", () => {

    urlInput.value = button.dataset.url;

    scanForm.requestSubmit();

  });

});


// CREATE TABLE ROW

function createTableRow(scan) {

  return `
    <tr>

      <td title="${escapeHTML(scan.url)}">
        ${escapeHTML(scan.url)}
      </td>

      <td>
        <span class="table-risk ${getRiskClass(scan.risk_level)}">
          ${escapeHTML(scan.risk_level)}
        </span>
      </td>

      <td>${scan.risk_score}/100</td>

      <td>${escapeHTML(scan.scanned_at || "")}</td>

    </tr>
  `;

}


// UPDATE DASHBOARD STATISTICS

async function updateDashboard() {

  try {

    const data = await apiRequest("/stats");

    const stats = data.stats;

    document.getElementById("totalScans").textContent =
      stats.total_scans;

    document.getElementById("highRisk").textContent =
      stats.high_risk;

    document.getElementById("suspiciousCount").textContent =
      stats.suspicious;

    document.getElementById("lowRisk").textContent =
      stats.low_risk;


    // LOAD RECENT SCANS

    const historyData = await apiRequest("/scans?limit=5");

    const recentBody = document.getElementById("recentTableBody");

    if (historyData.scans.length === 0) {

      recentBody.innerHTML = `
        <tr>
          <td colspan="4" class="empty-state">
            No scans yet. Analyze your first link!
          </td>
        </tr>
      `;

    } else {

      recentBody.innerHTML = historyData.scans
        .map(createTableRow)
        .join("");

    }

  } catch (error) {

    showToast("Could not load dashboard data.");

  }

}


// HISTORY PAGE

async function renderHistory() {

  const historyBody = document.getElementById("historyTableBody");

  historyBody.innerHTML = `
    <tr>
      <td colspan="4" class="empty-state">
        Loading scan history...
      </td>
    </tr>
  `;

  try {

    const data = await apiRequest("/scans?limit=500");

    if (data.scans.length === 0) {

      historyBody.innerHTML = `
        <tr>
          <td colspan="4" class="empty-state">
            No scan history available.
          </td>
        </tr>
      `;

      return;

    }

    historyBody.innerHTML = data.scans
      .map(createTableRow)
      .join("");

  } catch (error) {

    historyBody.innerHTML = `
      <tr>
        <td colspan="4" class="empty-state">
          Could not load scan history.
        </td>
      </tr>
    `;

    showToast(error.message);

  }

}


// CLEAR HISTORY

document.getElementById("clearHistoryButton")
  .addEventListener("click", async () => {

    const confirmed = confirm(
      "Are you sure you want to clear all scan history?"
    );

    if (!confirmed) {
      return;
    }

    try {

      await apiRequest("/scans", {
        method: "DELETE"
      });

      resultCard.classList.add("hidden");

      await updateDashboard();

      await renderHistory();

      showToast("Scan history cleared.");

    } catch (error) {

      showToast(error.message);

    }

  });


// INITIAL LOAD

async function initializeApp() {

  try {

    await apiRequest("/health");

    await updateDashboard();

  } catch (error) {

    showToast("Backend is not connected. Start Flask first.");

  }

}

initializeApp();
// ============================
// 🔹 1. Core Popup Function
// ============================
function showPopup(message, type = "info") {
  // Remove any old popup before showing new
  const oldPopup = document.querySelector(".popup-overlay");
  if (oldPopup) oldPopup.remove();

  // Create overlay
  const overlay = document.createElement("div");
  overlay.className = "popup-overlay";

  // Create popup card
  const popup = document.createElement("div");
  popup.className = `popup-card ${type}`;
  popup.innerHTML = `
    <div class="popup-content">
      <span class="popup-icon">${
        type === "success" ? "✅" :
        type === "error" ? "❌" :
        "ℹ️"
      }</span>
      <p>${message}</p>
      <button id="popup-close">OK</button>
    </div>
  `;

  overlay.appendChild(popup);
  document.body.appendChild(overlay);

  // Close behaviors
  document.getElementById("popup-close").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  // Optional auto-hide after 4s
  setTimeout(() => {
    if (document.body.contains(overlay)) overlay.remove();
  }, 4000);
}

// ============================
// 🔹 2. Auto-popup for Redirect URLs
// ============================
// Example: /dashboard?msg=Item+deleted&type=success
const params = new URLSearchParams(window.location.search);
if (params.get("msg")) {
  const msg = decodeURIComponent(params.get("msg"));
  const type = params.get("type") || "info";
  showPopup(msg, type);

  // Optional: remove ?msg=... from URL after showing
  window.history.replaceState({}, document.title, window.location.pathname);
}

// ============================
// 🔹 3. Helper for Fetch/AJAX Requests (Improved)
// ============================
// Use this in delete / found / contact / update actions
async function handlePopupFetch(url, options = {}) {
  try {
    const res = await fetch(url, options);
    const contentType = res.headers.get("content-type") || "";

    // Case 1: JSON response
    if (contentType.includes("application/json")) {
      const data = await res.json();
      showPopup(data.message || "Action completed!", data.success ? "success" : "error");
    }

    // Case 2: Redirects (server sent a redirect response)
    else if (res.redirected) {
      window.location.href = res.url;
      return;
    }

    // Case 3: HTML or unknown response
    else {
      const text = await res.text();
      if (text.includes("<!DOCTYPE")) {
        showPopup("Action completed successfully!", "success");
      } else {
        showPopup(text || "Done!", "info");
      }
    }
  } catch (err) {
    console.error("Popup Fetch Error:", err);
    showPopup("Server error: " + err.message, "error");
  }
}

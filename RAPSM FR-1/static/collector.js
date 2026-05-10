/**
 * RAPAS - FR-02: Browser-Side Data Collector
 * Collects device info, keystroke timing, mouse activity,
 * and generates a SHA-256 device fingerprint.
 */

const keystrokeData = [];
let lastKeyDownTime = null;
let lastKeyUpTime = null;
let mouseClicks = 0;
const mousePositions = [];

// --- Device Info ---
function getBrowserName() {
    const ua = navigator.userAgent;
    if (ua.includes("Edg/")) return "Edge";
    if (ua.includes("OPR/")) return "Opera";
    if (ua.includes("Chrome/")) return "Chrome";
    if (ua.includes("Firefox/")) return "Firefox";
    if (ua.includes("Safari/")) return "Safari";
    return "Unknown";
}

function getOSName() {
    const ua = navigator.userAgent;
    if (ua.includes("Windows")) return "Windows";
    if (ua.includes("Mac OS")) return "macOS";
    if (ua.includes("Linux")) return "Linux";
    if (ua.includes("Android")) return "Android";
    if (ua.includes("iPhone") || ua.includes("iPad")) return "iOS";
    return "Unknown";
}

function collectDeviceInfo() {
    return {
        browser: getBrowserName(),
        os: getOSName(),
        user_agent: navigator.userAgent,
        screen_resolution: screen.width + "x" + screen.height,
        hardware_concurrency: navigator.hardwareConcurrency || "N/A",
        device_memory: navigator.deviceMemory || "N/A",
        language: navigator.language || "en",
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown",
        platform: navigator.platform || "Unknown",
    };
}

// --- SHA-256 Fingerprint via SubtleCrypto ---
async function generateFingerprint(deviceInfo) {
    const rawString = [
        deviceInfo.user_agent,
        deviceInfo.screen_resolution,
        deviceInfo.hardware_concurrency,
        deviceInfo.device_memory,
        deviceInfo.language,
        deviceInfo.timezone,
        deviceInfo.platform,
    ].join("|");

    const encoder = new TextEncoder();
    const data = encoder.encode(rawString);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// --- Keystroke Dynamics ---
function handleKeyDown(event) {
    if (event.key.length !== 1) return;
    const now = performance.now();
    let flight = 0;
    if (lastKeyUpTime !== null) flight = Math.round(now - lastKeyUpTime);
    lastKeyDownTime = now;
    keystrokeData.push({ flight: flight, dwell: 0 });
}

function handleKeyUp(event) {
    if (event.key.length !== 1) return;
    const now = performance.now();
    lastKeyUpTime = now;
    if (keystrokeData.length > 0 && lastKeyDownTime !== null) {
        keystrokeData[keystrokeData.length - 1].dwell = Math.round(now - lastKeyDownTime);
    }
}

// --- Mouse Activity ---
function handleMouseClick(event) {
    mouseClicks++;
    if (mousePositions.length < 20) {
        mousePositions.push({ x: event.clientX, y: event.clientY });
    }
}

// --- Form Submission ---
async function handleFormSubmit(event) {
    event.preventDefault();
    const submitBtn = document.getElementById("login-btn");
    submitBtn.textContent = "Collecting data...";
    submitBtn.disabled = true;

    try {
        const deviceInfo = collectDeviceInfo();
        const fingerprint = await generateFingerprint(deviceInfo);

        const collectedData = {
            browser: deviceInfo.browser,
            os: deviceInfo.os,
            user_agent: deviceInfo.user_agent,
            screen_resolution: deviceInfo.screen_resolution,
            hardware_concurrency: deviceInfo.hardware_concurrency,
            device_memory: deviceInfo.device_memory,
            language: deviceInfo.language,
            timezone: deviceInfo.timezone,
            platform: deviceInfo.platform,
            device_fingerprint: fingerprint,
            keystroke_data: keystrokeData,
            mouse_clicks: mouseClicks,
            mouse_positions: mousePositions,
        };

        document.getElementById("client_data").value = JSON.stringify(collectedData);
        document.getElementById("login-form").submit();
    } catch (error) {
        console.error("[RAPAS] Error:", error);
        document.getElementById("login-form").submit();
    }
}

// --- Initialize ---
document.addEventListener("DOMContentLoaded", function () {
    const usernameInput = document.getElementById("username");
    if (usernameInput) {
        usernameInput.addEventListener("keydown", handleKeyDown);
        usernameInput.addEventListener("keyup", handleKeyUp);
    }
    document.addEventListener("click", handleMouseClick);
    const form = document.getElementById("login-form");
    if (form) form.addEventListener("submit", handleFormSubmit);
});

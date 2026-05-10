"""
RAPAS - Risk-Adaptive Passwordless Authentication System
=========================================================
Main Flask Application — FR-02: Context Data Collection & Feature Engineering

How it works:
  1. User opens the login page (GET /)
  2. User types their username and clicks "Authenticate"
  3. JavaScript (collector.js) silently collects browser/device data
  4. Flask receives the form data (POST /login)
  5. Server-side collector adds IP, geolocation, and time features
  6. Feature engine builds the complete feature vector
  7. Result page displays everything in a clean dashboard

Run with:
    python app.py
Then open http://127.0.0.1:5000 in your browser.
"""

import json
import webbrowser
import threading
from flask import Flask, render_template, request

# Import our custom modules
from modules.collector import collect_server_context
from modules.feature_engine import build_feature_vector

# =========================================================================
# CREATE THE FLASK APP
# =========================================================================
app = Flask(__name__)


# =========================================================================
# ROUTE 1: Login Page (GET /)
# =========================================================================
@app.route("/")
def login_page():
    """
    Serve the login page.
    The page loads collector.js which starts tracking keystrokes and
    mouse activity as soon as the page loads.
    """
    return render_template("login.html")


# =========================================================================
# ROUTE 2: Handle Login (POST /login)
# =========================================================================
@app.route("/login", methods=["POST"])
def handle_login():
    """
    Process the login form submission.

    Steps:
      1. Get the username from the form
      2. Parse the client-side data (JSON from hidden field)
      3. Collect server-side context (IP, geolocation, time)
      4. Build the feature vector using feature_engine
      5. Render the result page with all data
    """

    # --- Step 1: Get the username ---
    username = request.form.get("username", "anonymous").strip().lower()

    # --- Step 2: Parse client-side collected data ---
    # collector.js puts a JSON string into the hidden "client_data" field
    client_data_raw = request.form.get("client_data", "{}")
    try:
        client_data = json.loads(client_data_raw)
    except json.JSONDecodeError:
        # If parsing fails, use empty dict (won't crash the app)
        client_data = {}
        print("[RAPAS] Warning: Could not parse client_data JSON")

    # --- Step 3: Collect server-side context ---
    # This calls collector.py to get IP, geolocation, and time features
    server_context = collect_server_context(request)

    # --- Step 4: Build the feature vector ---
    # This calls feature_engine.py which computes all 9 features
    # and compares against the user's historical profile
    result = build_feature_vector(username, client_data, server_context)

    # --- Step 5: Render the result page ---
    # Pass all three sections to the template:
    #   - feature_vector: the computed numeric features
    #   - flags: status indicators (normal/unusual) for each feature
    #   - raw_data: all the raw input data for the table
    return render_template(
        "result.html",
        feature_vector=result["feature_vector"],
        flags=result["flags"],
        raw_data=result["raw_data"],
    )


# =========================================================================
# OPEN BROWSER AUTOMATICALLY
# =========================================================================
def open_browser():
    """Open the browser automatically after a short delay."""
    import time
    time.sleep(2)  # Wait 2 seconds for server to start
    webbrowser.open("http://127.0.0.1:5000")


# =========================================================================
# RUN THE APP
# =========================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  RAPAS — Risk-Adaptive Passwordless Authentication System")
    print("  FR-02: Context Data Collection & Feature Engineering")
    print("=" * 60)
    print("  Opening browser... http://127.0.0.1:5000")
    print("=" * 60)

    # Start browser in a background thread
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()

    # debug=False disables the reloader, making Ctrl+C work properly
    # The server will still run, but won't auto-reload code changes
    app.run(debug=False, host="127.0.0.1", port=5000)

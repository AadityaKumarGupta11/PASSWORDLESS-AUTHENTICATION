"""
RAPAS - FR-02: Feature Engineering Module
==========================================
This module takes the raw context data (from both browser and server)
and transforms it into a normalized feature vector that can be fed
directly into the ML Risk Engine (FR-03).

Features produced:
  1. device_fingerprint     – SHA-256 hash string of device attributes
  2. device_novelty         – 0.0 (known device) or 1.0 (new device)
  3. location_change        – 0.0 (same city) or 1.0 (different city)
  4. session_gap_hours      – Hours since the user's last login
  5. login_hour_deviation   – How far this login hour is from the user's average
  6. avg_keystroke_dwell    – Average key-press duration in ms
  7. avg_keystroke_flight   – Average time between key presses in ms
  8. login_frequency_score  – Normalized login frequency (0-1)
  9. time_category_encoded  – Numeric encoding of time-of-day
"""

import json
import os
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Path to the user profiles JSON file
# We store each user's history here so we can compare current vs past logins.
# --------------------------------------------------------------------------
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
PROFILES_PATH = os.path.join(DATA_DIR, "user_profiles.json")


# ==========================================================================
# HELPER FUNCTIONS
# ==========================================================================

def _load_profiles():
    """Load all user profiles from the JSON file."""
    try:
        with open(PROFILES_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_profiles(profiles):
    """Save all user profiles back to the JSON file."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(PROFILES_PATH, "w") as f:
        json.dump(profiles, f, indent=2)


def _get_user_profile(profiles, username):
    """
    Get or create a profile for the given username.
    
    Each user profile stores:
      - known_fingerprints: list of SHA-256 device fingerprints seen before
      - login_history: list of past login timestamps (ISO format)
      - known_cities: list of cities the user has logged in from
      - login_hours: list of hours (0-23) the user has logged in at
    """
    if username not in profiles:
        profiles[username] = {
            "known_fingerprints": [],
            "login_history": [],
            "known_cities": [],
            "login_hours": [],
        }
    return profiles[username]


# ==========================================================================
# FEATURE COMPUTATION FUNCTIONS
# ==========================================================================

def compute_device_novelty(fingerprint, known_fingerprints):
    """
    Check if this device fingerprint has been seen before.
    
    Args:
        fingerprint (str): SHA-256 hash of current device attributes.
        known_fingerprints (list): List of previously seen fingerprints.
    
    Returns:
        float: 0.0 if the device is known, 1.0 if it's brand new.
    """
    if fingerprint in known_fingerprints:
        return 0.0  # Known device — no risk from device change
    return 1.0      # New device — potential risk indicator


def compute_location_change(current_city, known_cities):
    """
    Check if the user is logging in from a new city.
    
    Args:
        current_city (str): City name from geolocation lookup.
        known_cities (list): List of cities the user has logged in from before.
    
    Returns:
        float: 0.0 if same city, 1.0 if new city.
    """
    if not known_cities:
        return 0.0  # First login — no change to compare against
    if current_city in known_cities:
        return 0.0  # User has logged in from this city before
    return 1.0      # New city — could indicate stolen credentials


def compute_session_gap(login_history):
    """
    Calculate how many hours have passed since the user's last login.
    
    A very large gap (e.g., 720 hours = 30 days) might indicate an
    inactive account being accessed by an attacker.
    
    Args:
        login_history (list): List of ISO-format timestamp strings.
    
    Returns:
        float: Hours since last login. 0.0 if this is the first login.
    """
    if not login_history:
        return 0.0  # First login — no previous session to compare

    # Parse the most recent login timestamp
    last_login_str = login_history[-1]
    last_login = datetime.fromisoformat(last_login_str)

    # Calculate the gap in hours
    now = datetime.now(timezone.utc)
    gap = (now - last_login).total_seconds() / 3600.0  # Convert seconds to hours

    return round(gap, 2)


def compute_login_hour_deviation(current_hour, login_hours):
    """
    How different is this login hour from the user's typical login time?
    
    Example: If a user always logs in at hour 10 (10 AM), and now logs in
    at hour 3 (3 AM), the deviation is 7 hours — suspicious!
    
    We use circular distance to handle the midnight wraparound.
    For example, hour 23 and hour 1 are only 2 hours apart, not 22.
    
    Args:
        current_hour (int): Current login hour (0-23).
        login_hours (list): List of previous login hours.
    
    Returns:
        float: Deviation in hours (0.0 to 12.0). Normalized to 0-1 range.
    """
    if not login_hours:
        return 0.0  # First login — no history to compare against

    # Calculate the average login hour
    avg_hour = sum(login_hours) / len(login_hours)

    # Circular distance (handles midnight wraparound)
    # The maximum possible circular distance is 12 hours
    diff = abs(current_hour - avg_hour)
    circular_diff = min(diff, 24 - diff)

    # Normalize to 0-1 range (divide by max possible = 12)
    return round(circular_diff / 12.0, 4)


def compute_keystroke_features(keystroke_data):
    """
    Extract keystroke timing features from the raw keystroke data.
    
    Keystroke dynamics are a form of behavioral biometrics:
      - Dwell time: How long a key is held down (keydown → keyup)
      - Flight time: Time between releasing one key and pressing the next
    
    Args:
        keystroke_data (list): List of dicts with "dwell" and "flight" values.
            Example: [{"dwell": 85, "flight": 120}, {"dwell": 92, "flight": 105}]
    
    Returns:
        tuple: (avg_dwell_ms, avg_flight_ms)
    """
    if not keystroke_data:
        return (0.0, 0.0)

    dwells = [k.get("dwell", 0) for k in keystroke_data if k.get("dwell", 0) > 0]
    flights = [k.get("flight", 0) for k in keystroke_data if k.get("flight", 0) > 0]

    avg_dwell = round(sum(dwells) / len(dwells), 2) if dwells else 0.0
    avg_flight = round(sum(flights) / len(flights), 2) if flights else 0.0

    return (avg_dwell, avg_flight)


def compute_login_frequency(login_history):
    """
    Calculate a normalized login frequency score.
    
    This measures how often the user logs in. We look at the number of
    logins in the past 30 days and normalize it.
    
    Score interpretation:
      - 0.0 = Never logged in before (or very rarely)
      - 0.5 = Logs in about once a day
      - 1.0 = Extremely frequent logins (multiple times per day)
    
    Args:
        login_history (list): List of ISO-format timestamp strings.
    
    Returns:
        float: Login frequency score between 0.0 and 1.0.
    """
    if not login_history:
        return 0.0

    now = datetime.now(timezone.utc)
    thirty_days_ago = now.timestamp() - (30 * 24 * 3600)  # 30 days in seconds

    # Count logins in the past 30 days
    recent_logins = 0
    for ts_str in login_history:
        ts = datetime.fromisoformat(ts_str)
        if ts.timestamp() >= thirty_days_ago:
            recent_logins += 1

    # Normalize: 30 logins in 30 days = 1.0 (once per day)
    # Cap at 1.0 to avoid scores > 1
    score = min(recent_logins / 30.0, 1.0)
    return round(score, 4)


def encode_time_category(time_category):
    """
    Convert the time-of-day category to a numeric value.
    
    This encoding is used as a feature for the ML model.
    
    Args:
        time_category (str): One of "morning", "afternoon", "evening", "night".
    
    Returns:
        float: Numeric encoding (0.0, 0.25, 0.5, 0.75).
    """
    mapping = {
        "morning": 0.0,
        "afternoon": 0.25,
        "evening": 0.5,
        "night": 0.75,
    }
    return mapping.get(time_category, 0.5)


# ==========================================================================
# MAIN FEATURE ENGINEERING FUNCTION
# ==========================================================================

def build_feature_vector(username, client_data, server_context):
    """
    Build the complete feature vector from raw data.
    
    This is the MAIN function called by app.py. It:
      1. Loads the user's historical profile
      2. Computes each feature by comparing current data vs history
      3. Updates the user's profile with this login
      4. Returns the feature vector + flag indicators
    
    Args:
        username (str): The username attempting to log in.
        client_data (dict): Data collected by JavaScript in the browser:
            - browser, os, screen_resolution, hardware_concurrency,
              device_memory, user_agent, device_fingerprint,
              keystroke_data, mouse_clicks, mouse_positions
        server_context (dict): Data collected by collector.py on the server:
            - ip_address, city, country, lat, lon, timestamp,
              login_hour, day_of_week, time_category
    
    Returns:
        dict: {
            "feature_vector": { ... all computed features ... },
            "flags": { ... which features are normal vs unusual ... },
            "raw_data": { ... all the raw input data for display ... }
        }
    """
    # --- Load user profile history ---
    profiles = _load_profiles()
    profile = _get_user_profile(profiles, username)

    # --- Extract values from client data ---
    fingerprint = client_data.get("device_fingerprint", "unknown")
    keystroke_data = client_data.get("keystroke_data", [])
    mouse_clicks = client_data.get("mouse_clicks", 0)

    # --- Extract values from server context ---
    current_city = server_context.get("city", "Unknown")
    current_hour = server_context.get("login_hour", 12)
    time_category = server_context.get("time_category", "afternoon")
    timestamp = server_context.get("timestamp", datetime.now(timezone.utc).isoformat())

    # =====================================================================
    # COMPUTE EACH FEATURE
    # =====================================================================

    # Feature 1: Device Novelty (is this a new device?)
    device_novelty = compute_device_novelty(
        fingerprint, profile["known_fingerprints"]
    )

    # Feature 2: Location Change (is the user in a new city?)
    location_change = compute_location_change(
        current_city, profile["known_cities"]
    )

    # Feature 3: Session Gap (hours since last login)
    session_gap = compute_session_gap(profile["login_history"])

    # Feature 4: Login Hour Deviation (how unusual is this login time?)
    hour_deviation = compute_login_hour_deviation(
        current_hour, profile["login_hours"]
    )

    # Feature 5 & 6: Keystroke Dynamics
    avg_dwell, avg_flight = compute_keystroke_features(keystroke_data)

    # Feature 7: Login Frequency Score
    login_freq = compute_login_frequency(profile["login_history"])

    # Feature 8: Time Category Encoded
    time_encoded = encode_time_category(time_category)

    # =====================================================================
    # BUILD THE FEATURE VECTOR
    # =====================================================================
    feature_vector = {
        "device_fingerprint": fingerprint,
        "device_novelty": device_novelty,
        "location_change": location_change,
        "session_gap_hours": session_gap,
        "login_hour_deviation": hour_deviation,
        "avg_keystroke_dwell_ms": avg_dwell,
        "avg_keystroke_flight_ms": avg_flight,
        "login_frequency_score": login_freq,
        "time_category_encoded": time_encoded,
    }

    # =====================================================================
    # DETERMINE FLAGS (normal vs unusual)
    # =====================================================================
    # These thresholds help the result page show which features are "flagged"
    flags = {
        "device_novelty": "🟢 Known Device" if device_novelty == 0.0 else "🔴 New Device",
        "location_change": "🟢 Known Location" if location_change == 0.0 else "🔴 New Location",
        "session_gap_hours": (
            "🟢 Normal"
            if session_gap < 168  # Less than 7 days
            else "🟡 Long Gap ({}h)".format(round(session_gap))
        ),
        "login_hour_deviation": (
            "🟢 Typical Time"
            if hour_deviation < 0.4
            else "🟡 Unusual Time"
        ),
        "avg_keystroke_dwell_ms": (
            "🟢 Normal"
            if 50 <= avg_dwell <= 200 or avg_dwell == 0.0
            else "🟡 Unusual"
        ),
        "avg_keystroke_flight_ms": (
            "🟢 Normal"
            if 50 <= avg_flight <= 300 or avg_flight == 0.0
            else "🟡 Unusual"
        ),
        "login_frequency_score": (
            "🟢 Active User"
            if login_freq > 0.1
            else "🟡 Infrequent"
        ),
        "time_category_encoded": "🟢 " + time_category.capitalize(),
    }

    # =====================================================================
    # UPDATE USER PROFILE (save this login for future comparisons)
    # =====================================================================

    # Add fingerprint if it's new
    if fingerprint not in profile["known_fingerprints"]:
        profile["known_fingerprints"].append(fingerprint)

    # Add city if it's new
    if current_city not in profile["known_cities"]:
        profile["known_cities"].append(current_city)

    # Record this login timestamp
    profile["login_history"].append(timestamp)

    # Record this login hour
    profile["login_hours"].append(current_hour)

    # Keep only the last 100 entries to prevent the file from growing too large
    profile["login_history"] = profile["login_history"][-100:]
    profile["login_hours"] = profile["login_hours"][-100:]

    # Save updated profiles
    profiles[username] = profile
    _save_profiles(profiles)

    # =====================================================================
    # PREPARE RAW DATA FOR DISPLAY ON RESULT PAGE
    # =====================================================================
    raw_data = {
        "username": username,
        "ip_address": server_context.get("ip_address", "N/A"),
        "city": current_city,
        "country": server_context.get("country", "Unknown"),
        "latitude": server_context.get("lat", 0.0),
        "longitude": server_context.get("lon", 0.0),
        "timestamp": timestamp,
        "login_hour": current_hour,
        "day_of_week": server_context.get("day_of_week", 0),
        "time_category": time_category,
        "browser": client_data.get("browser", "Unknown"),
        "os": client_data.get("os", "Unknown"),
        "screen_resolution": client_data.get("screen_resolution", "Unknown"),
        "hardware_concurrency": client_data.get("hardware_concurrency", "N/A"),
        "device_memory": client_data.get("device_memory", "N/A"),
        "user_agent": client_data.get("user_agent", "N/A"),
        "mouse_clicks": mouse_clicks,
        "keystroke_samples": len(keystroke_data),
    }

    return {
        "feature_vector": feature_vector,
        "flags": flags,
        "raw_data": raw_data,
    }

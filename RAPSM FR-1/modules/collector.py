"""
RAPAS - FR-02: Context Data Collector
=====================================
This module collects server-side context data for each login attempt:
  - IP address of the user
  - Geolocation (city, country) via ip-api.com
  - UTC timestamp and time features (hour, day of week)

The browser-side data (device info, keystrokes) is collected by
static/collector.js and sent along with the login POST request.
"""

import requests
from datetime import datetime, timezone


def get_client_ip(flask_request):
    """
    Extract the real IP address of the user.
    
    Why we check 'X-Forwarded-For':
      If the app is behind a reverse proxy (like Nginx), the real IP
      is stored in the X-Forwarded-For header. Otherwise, we use
      flask_request.remote_addr directly.
    
    Args:
        flask_request: The Flask request object from the current request.
    
    Returns:
        str: The client's IP address (e.g., "103.21.58.193").
    """
    # Check if there's a proxy forwarding the request
    forwarded_for = flask_request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs; the first one is the client
        return forwarded_for.split(",")[0].strip()
    
    # No proxy — use the direct connection IP
    return flask_request.remote_addr


def get_geolocation(ip_address):
    """
    Look up the city and country for a given IP address using ip-api.com.
    
    ip-api.com is free (no API key needed) and gives us:
      - city (e.g., "Bengaluru")
      - country (e.g., "India")
      - lat/lon, ISP, etc. (we only use city and country for now)
    
    Note: For localhost (127.0.0.1), ip-api returns the server's public IP info.
    
    Args:
        ip_address (str): The IP address to look up.
    
    Returns:
        dict: {"city": "...", "country": "...", "lat": ..., "lon": ...}
              Returns "Unknown" values if the lookup fails.
    """
    try:
        # ip-api.com free endpoint — no API key required
        # We ask for JSON format with specific fields
        url = f"http://ip-api.com/json/{ip_address}?fields=city,country,lat,lon,status"
        response = requests.get(url, timeout=5)  # 5-second timeout to avoid hanging
        data = response.json()

        # ip-api returns status "success" or "fail"
        if data.get("status") == "success":
            return {
                "city": data.get("city", "Unknown"),
                "country": data.get("country", "Unknown"),
                "lat": data.get("lat", 0.0),
                "lon": data.get("lon", 0.0),
            }
        else:
            # This happens for private/localhost IPs
            print(f"[Collector] ip-api returned fail for IP: {ip_address}")
            return {"city": "Unknown", "country": "Unknown", "lat": 0.0, "lon": 0.0}

    except Exception as e:
        # Network errors, timeouts, etc.
        print(f"[Collector] Geolocation lookup failed: {e}")
        return {"city": "Unknown", "country": "Unknown", "lat": 0.0, "lon": 0.0}


def get_time_features():
    """
    Capture the current UTC timestamp and extract time-based features.
    
    Features extracted:
      - timestamp: Full ISO-format UTC time (e.g., "2025-05-07T12:30:45+00:00")
      - login_hour: Hour of day 0-23 (used to detect unusual login times)
      - day_of_week: 0 = Monday, 6 = Sunday (used to detect unusual days)
      - time_category: Human-readable period of day:
          * "night"     = 00:00 - 05:59
          * "morning"   = 06:00 - 11:59
          * "afternoon"  = 12:00 - 17:59
          * "evening"   = 18:00 - 23:59
    
    Returns:
        dict: Dictionary with all time features.
    """
    now = datetime.now(timezone.utc)  # Always use UTC for consistency

    # Determine the time-of-day category
    hour = now.hour
    if hour < 6:
        time_category = "night"
    elif hour < 12:
        time_category = "morning"
    elif hour < 18:
        time_category = "afternoon"
    else:
        time_category = "evening"

    return {
        "timestamp": now.isoformat(),          # Full timestamp string
        "login_hour": hour,                     # 0-23
        "day_of_week": now.weekday(),           # 0=Mon, 6=Sun
        "time_category": time_category,         # Human-readable category
    }


def collect_server_context(flask_request):
    """
    Master function: collects ALL server-side context in one call.
    
    This is the main function called by app.py during login.
    It combines IP, geolocation, and time features into a single dict.
    
    Args:
        flask_request: The Flask request object.
    
    Returns:
        dict: Combined server-side context data, for example:
            {
                "ip_address": "103.21.58.193",
                "city": "Bengaluru",
                "country": "India",
                "lat": 12.9716,
                "lon": 77.5946,
                "timestamp": "2025-05-07T12:30:45+00:00",
                "login_hour": 12,
                "day_of_week": 2,
                "time_category": "afternoon"
            }
    """
    # Step 1: Get the user's IP address
    ip = get_client_ip(flask_request)

    # Step 2: Look up geolocation from IP
    geo = get_geolocation(ip)

    # Step 3: Get time-based features
    time_features = get_time_features()

    # Combine everything into one dictionary
    context = {
        "ip_address": ip,
        "city": geo["city"],
        "country": geo["country"],
        "lat": geo["lat"],
        "lon": geo["lon"],
    }
    context.update(time_features)  # Add timestamp, login_hour, day_of_week, time_category

    return context

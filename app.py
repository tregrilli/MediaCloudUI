from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
import requests
import os
import logging, time, json, traceback

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret')

# Simple in-memory user store. Replace with database or proper user management in production.
USERS = {
    'admin': 'password'
}

# Base URL and credentials for OME API

# The environment variable `OME_API_URL` should point to the stream discovery
# endpoint (``/v1/stream``). We derive the base API path for other queries by
# trimming the final path component and ensuring it ends with ``/`` so that
# further paths can be appended safely.
OME_STREAM_URL = os.environ.get('OME_API_URL', 'http://ome.northeurope.cloudapp.azure.com:8081/v1/')
OME_API_BASE = OME_STREAM_URL.rsplit('/', 1)[0].rstrip('/') + '/'
OME_API_USER = os.environ.get('OME_API_USER', 'user')
OME_API_PASS = os.environ.get('OME_API_PASS', 'pass')
OME_VHOST = os.environ.get('OME_VHOST', 'default')
OME_APP = os.environ.get('OME_APP', 'app')

# Base for composing WebRTC playback URLs
from urllib.parse import urlparse
_parsed = urlparse(OME_STREAM_URL)
_default_host = _parsed.hostname or 'localhost'
OME_WEBRTC_BASE = os.environ.get('OME_WEBRTC_BASE', f"wss://{_default_host}:3334/")
OME_WEBRTC_BASE = OME_WEBRTC_BASE.rstrip('/') + '/'

# ---------- Verbose Debug / Logging Setup ----------
LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG").upper()
VERBOSE_DEBUG = os.environ.get("VERBOSE_DEBUG", "1") not in ("0", "false", "False")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.DEBUG),
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
log = logging.getLogger("MediaCloudUI")

def _mask(v):
    if v is None:
        return None
    return v[:2] + "****" if len(v) > 2 else "**"

def timed(label):
    def deco(fn):
        def wrapper(*args, **kwargs):
            if VERBOSE_DEBUG:
                log.debug(f"[START] {label}")
            t0 = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                dt = (time.perf_counter() - t0) * 1000
                if VERBOSE_DEBUG:
                    log.debug(f"[END] {label} took {dt:.1f} ms")
        return wrapper
    return deco

@app.before_request
def _log_request():
    if not VERBOSE_DEBUG:
        return
    log.debug(
        "Incoming request: path=%s method=%s args=%s form=%s user=%s",
        request.path, request.method,
        dict(request.args), dict(request.form),
        session.get("username")
    )

@app.after_request
def _log_response(resp):
    if VERBOSE_DEBUG:
        log.debug(
            "Response: path=%s status=%s len=%s content_type=%s",
            request.path, resp.status, resp.content_length, resp.content_type
        )
    return resp

def login_required(f):
    """Decorator to ensure routes require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Root redirects based on authentication state."""
    if 'username' in session:
        return redirect(url_for('streams'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if USERS.get(username) == password:
            session['username'] = username
            return redirect(url_for('streams'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """Log out the current user."""
    session.clear()
    return redirect(url_for('login'))

@timed("fetch_streams")
def fetch_streams():
    """Retrieve stream information from OME API."""
    try:
        pub_url = f"{OME_API_BASE}vhosts/{OME_VHOST}/apps/{OME_APP}/streams"

        if VERBOSE_DEBUG:
            log.debug("Fetching streams from %s authUser=%s", pub_url, OME_API_USER)
        response = requests.get(pub_url, timeout=5, auth=(OME_API_USER, OME_API_PASS))
        if VERBOSE_DEBUG:
            log.debug("Streams response status=%s headers=%s", response.status_code, dict(response.headers))
        response.raise_for_status()
        raw_text = response.text
        if VERBOSE_DEBUG:
            log.debug("Raw stream payload (truncated 500 chars): %s", raw_text[:500])
        try:
            raw = response.json()
        except Exception:
            log.error("Failed parsing JSON for streams")
            if VERBOSE_DEBUG:
                log.debug("Offending text: %s", raw_text)
            raise

        # Normalize payload
        payload = raw.get('response', raw) if isinstance(raw, dict) else raw

        if isinstance(payload, dict):
            # Typical structure: {'streams': [...]}
            candidate = payload.get('streams')
            raw_streams = candidate if isinstance(candidate, list) else []
        elif isinstance(payload, list):
            # Already a list
            raw_streams = payload
        else:
            raw_streams = []

        streams = []
        for idx, item in enumerate(raw_streams):
            if isinstance(item, dict):
                name = item.get('name') or item.get('id') or f'stream{idx}'
            else:
                name = str(item)
            url = f"{OME_WEBRTC_BASE}{OME_APP}/{name}"
            streams.append({'name': name, 'url': url})

        if not streams and VERBOSE_DEBUG:
            log.debug("No streams available (0 discovered).")
        elif VERBOSE_DEBUG:
            log.debug("Discovered %d streams: %s", len(streams), [s['name'] for s in streams])
        return streams
    except Exception as e:
        log.error("fetch_streams failed: %s", e)
        if VERBOSE_DEBUG:
            log.debug("Trace:\n%s", traceback.format_exc())
        return []

@timed("fetch_system_info")
def fetch_system_info():
    """Return application-level statistics from OME."""
    try:
        url = f"{OME_API_BASE}stats/current/vhosts/{OME_VHOST}/apps/{OME_APP}"

        if VERBOSE_DEBUG:
            log.debug("Fetching system info from %s", url)
        response = requests.get(url, timeout=5, auth=(OME_API_USER, OME_API_PASS))
        if VERBOSE_DEBUG:
            log.debug("System info status=%s", response.status_code)
        response.raise_for_status()
        data = response.json()
        data = data.get('response', data)
        if VERBOSE_DEBUG:
            summary_keys = list(data.keys())[:15] if isinstance(data, dict) else None
            log.debug(
                "System info keys=%s (total=%d)",
                summary_keys,
                len(data.keys()) if isinstance(data, dict) else -1,
            )
        return data
    except Exception as e:
        log.error("fetch_system_info failed: %s", e)
        if VERBOSE_DEBUG:
            log.debug("Trace:\n%s", traceback.format_exc())
        return {}

@timed("fetch_stream_connections")
def fetch_stream_connections():
    """Collect statistics for each stream from OME."""
    streams = {}
    names = [s['name'] for s in fetch_streams()]
    for name in names:
        try:
            url = f"{OME_API_BASE}stats/current/vhosts/{OME_VHOST}/apps/{OME_APP}/streams/{name}"

            if VERBOSE_DEBUG:
                log.debug("Fetching stream stats from %s", url)
            resp = requests.get(url, timeout=5, auth=(OME_API_USER, OME_API_PASS))
            resp.raise_for_status()
            data = resp.json()
            streams[name] = data.get('response', data)
        except Exception:
            log.error("Failed fetching stats for stream %s", name, exc_info=VERBOSE_DEBUG)
    if VERBOSE_DEBUG:
        log.debug(
            "Stream stats keys: %s",
            {k: list(v.keys())[:5] if isinstance(v, dict) else type(v) for k, v in streams.items()},
        )
    return streams

@app.route('/streams')
@login_required
def streams():
    """Display available streams using OvenPlayer."""
    stream_list = fetch_streams()
    empty_message = "0 stream available" if not stream_list else None
    if VERBOSE_DEBUG:
        log.debug("Rendering /streams with %d entries", len(stream_list))
    return render_template('streams.html', streams=stream_list, empty_message=empty_message)

@app.route('/info')
@login_required
def info():
    """Display general system information and per-stream connection details."""
    system_info = fetch_system_info()
    stream_info = fetch_stream_connections()
    if VERBOSE_DEBUG:
        log.debug("Rendering /info system_keys=%s stream_count=%d",
                  list(system_info.keys())[:10] if isinstance(system_info, dict) else None,
                  len(stream_info))
    return render_template('info.html', system=system_info, streams=stream_info)

if __name__ == '__main__':
    log.info(
        "Starting Flask app with OME_STREAM_URL=%s OME_API_BASE=%s user=%s pass=%s vhost=%s app=%s webrtc=%s",
        OME_STREAM_URL,
        OME_API_BASE,
        OME_API_USER,
        _mask(OME_API_PASS),
        OME_VHOST,
        OME_APP,
        OME_WEBRTC_BASE,
    )
    app.run(debug=True, host="0.0.0.0")

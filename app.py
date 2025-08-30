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
# trimming the final path component.
OME_STREAM_URL = os.environ.get('OME_API_URL', 'http://20.123.40.223:8081/')
OME_API_BASE = OME_STREAM_URL.rsplit('/', 1)[0]
OME_API_USER = os.environ.get('OME_API_USER', 'user')
OME_API_PASS = os.environ.get('OME_API_PASS', 'pass')

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
        pub_url = f"{OME_API_BASE}v1/vhosts/default/apps/app/streams"
        if VERBOSE_DEBUG:
            log.debug(f"Fetching streams from %s authUser=%s", OME_STREAM_URL, OME_API_USER)
        response = requests.get(pub_url, timeout=5, auth=(OME_API_USER, OME_API_PASS))
        if VERBOSE_DEBUG:
            log.debug("Streams response status=%s headers=%s", response.status_code, dict(response.headers))
        response.raise_for_status()
        raw_text = response.text
        if VERBOSE_DEBUG:
            log.debug("Raw stream payload (truncated 500 chars): %s", raw_text[:500])
        try:
            data = response.json()
        except Exception:
            log.error("Failed parsing JSON for streams")
            if VERBOSE_DEBUG:
                log.debug("Offending text: %s", raw_text)
            raise
        streams = []
        # Expecting data either as list of streams or dict containing 'streams'
        if isinstance(data, list):
            for idx, item in enumerate(data):
                if VERBOSE_DEBUG:
                    log.debug("Stream list item[%d] keys=%s", idx, list(item.keys()))
                streams.append({
                    'name': item.get('name', f'stream{idx}'),
                    'url': item.get('playUrl')
                })
        elif isinstance(data, dict) and 'streams' in data:
            for item in data.get('streams', []):
                if VERBOSE_DEBUG:
                    log.debug("Stream dict entry keys=%s", list(item.keys()))
                streams.append({
                    'name': item.get('name', item.get('id')), 
                    'url': item.get('playUrl')
                })
        if VERBOSE_DEBUG:
            log.debug("Discovered %d streams: %s", len(streams), [s['name'] for s in streams])
        return streams
    except Exception as e:
        log.error("fetch_streams failed: %s", e)
        if VERBOSE_DEBUG:
            log.debug("Trace:\n%s", traceback.format_exc())
        return []

@timed("fetch_system_info")
def fetch_system_info():
    """Return general system information from OME."""
    try:
        url = f"{OME_API_BASE}/v1/stats/current/vhosts/default/apps/app"
        if VERBOSE_DEBUG:
            log.debug("Fetching system info from %s", url)
        response = requests.get(url, timeout=5, auth=(OME_API_USER, OME_API_PASS))
        if VERBOSE_DEBUG:
            log.debug("System info status=%s", response.status_code)
        response.raise_for_status()
        data = response.json()
        if VERBOSE_DEBUG:
            summary_keys = list(data.keys())[:15]
            log.debug("System info keys=%s (total=%d)", summary_keys, len(data.keys()) if isinstance(data, dict) else -1)
        return data
    except Exception as e:
        log.error("fetch_system_info failed: %s", e)
        if VERBOSE_DEBUG:
            log.debug("Trace:\n%s", traceback.format_exc())
        return {}

@timed("fetch_stream_connections")
def fetch_stream_connections():
    """Gather publisher (inputs) and subscriber (outputs) info grouped by stream."""
    streams = {}
    # Publishers / inputs
    try:
        pub_url = f"{OME_API_BASE}/publishers"
        if VERBOSE_DEBUG:
            log.debug("Fetching publishers from %s", pub_url)
        resp = requests.get(pub_url, timeout=5, auth=(OME_API_USER, OME_API_PASS))
        resp.raise_for_status()
        data = resp.json()
        publishers = data.get('publishers') if isinstance(data, dict) else data
        for item in publishers or []:
            name = item.get('streamName') or item.get('stream') or item.get('name')
            if not name:
                continue
            streams.setdefault(name, {'in': [], 'out': []})
            streams[name]['in'].append(item)
        if VERBOSE_DEBUG:
            log.debug("Publishers grouped: %s", {k: len(v['in']) for k,v in streams.items()})
    except Exception:
        log.error("Failed fetching publishers", exc_info=VERBOSE_DEBUG)
    # Subscribers / outputs
    try:
        sub_url = f"{OME_API_BASE}/subscribers"
        if VERBOSE_DEBUG:
            log.debug("Fetching subscribers from %s", sub_url)
        resp = requests.get(sub_url, timeout=5, auth=(OME_API_USER, OME_API_PASS))
        resp.raise_for_status()
        data = resp.json()
        subscribers = data.get('subscribers') if isinstance(data, dict) else data
        for item in subscribers or []:
            name = item.get('streamName') or item.get('stream') or item.get('name')
            if not name:
                continue
            streams.setdefault(name, {'in': [], 'out': []})
            streams[name]['out'].append(item)
        if VERBOSE_DEBUG:
            log.debug("Subscribers grouped: %s", {k: len(v['out']) for k,v in streams.items()})
    except Exception:
        log.error("Failed fetching subscribers", exc_info=VERBOSE_DEBUG)
    if VERBOSE_DEBUG:
        log.debug("Combined stream connection map: %s", {
            k: {"in": len(v['in']), "out": len(v['out'])} for k,v in streams.items()
        })
    return streams

@app.route('/streams')
@login_required
def streams():
    """Display available streams using OvenPlayer."""
    stream_list = fetch_streams()
    if VERBOSE_DEBUG:
        log.debug("Rendering /streams with %d entries", len(stream_list))
    return render_template('streams.html', streams=stream_list)

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
    log.info("Starting Flask app with OME_STREAM_URL=%s OME_API_BASE=%s user=%s pass=%s",
             OME_STREAM_URL, OME_API_BASE, OME_API_USER, _mask(OME_API_PASS))
    app.run(debug=True, host="0.0.0.0")

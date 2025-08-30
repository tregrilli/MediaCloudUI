from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
import requests
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret')

# Simple in-memory user store. Replace with database or proper user management in production.
USERS = {
    'admin': 'password'
}

# Base URL and credentials for OME API
b
# The environment variable `OME_API_URL` should point to the stream discovery
# endpoint (``/v1/stream``). We derive the base API path for other queries by
# trimming the final path component.
OME_STREAM_URL = os.environ.get('OME_API_URL', 'http://localhost:8081/v1/stream')
OME_API_BASE = OME_STREAM_URL.rsplit('/', 1)[0]
OME_API_USER = os.environ.get('OME_API_USER', 'user')
OME_API_PASS = os.environ.get('OME_API_PASS', 'pass')


def login_required(f):
    """Decorator to ensure routes require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

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

def fetch_streams():
    """Retrieve stream information from OME API."""
    try:

        response = requests.get(OME_STREAM_URL, timeout=3, auth=(OME_API_USER, OME_API_PASS))

        response.raise_for_status()
        data = response.json()
        streams = []
        # Expecting data either as list of streams or dict containing 'streams'
        if isinstance(data, list):
            for idx, item in enumerate(data):
                streams.append({
                    'name': item.get('name', f'stream{idx}'),
                    'url': item.get('playUrl')
                })
        elif isinstance(data, dict) and 'streams' in data:
            for item in data.get('streams', []):
                streams.append({
                    'name': item.get('name', item.get('id')), 
                    'url': item.get('playUrl')
                })
        return streams
    except Exception:
        # On failure return empty list (could log error in real application)
        return []


def fetch_system_info():
    """Return general system information from OME."""
    try:
        response = requests.get(f"{OME_API_BASE}/system", timeout=3, auth=(OME_API_USER, OME_API_PASS))
        response.raise_for_status()
        return response.json()
    except Exception:
        return {}

def fetch_stream_connections():
    """Gather publisher (inputs) and subscriber (outputs) info grouped by stream."""
    streams = {}
    # Publishers / inputs
    try:
        resp = requests.get(f"{OME_API_BASE}/publishers", timeout=3, auth=(OME_API_USER, OME_API_PASS))
        resp.raise_for_status()
        data = resp.json()
        publishers = data.get('publishers') if isinstance(data, dict) else data
        for item in publishers or []:
            name = item.get('streamName') or item.get('stream') or item.get('name')
            if not name:
                continue
            streams.setdefault(name, {'in': [], 'out': []})
            streams[name]['in'].append(item)
    except Exception:
        pass
    # Subscribers / outputs
    try:
        resp = requests.get(f"{OME_API_BASE}/subscribers", timeout=3, auth=(OME_API_USER, OME_API_PASS))
        resp.raise_for_status()
        data = resp.json()
        subscribers = data.get('subscribers') if isinstance(data, dict) else data
        for item in subscribers or []:
            name = item.get('streamName') or item.get('stream') or item.get('name')
            if not name:
                continue
            streams.setdefault(name, {'in': [], 'out': []})
            streams[name]['out'].append(item)
    except Exception:
        pass
    return streams


@app.route('/streams')
@login_required
def streams():
    """Display available streams using OvenPlayer."""
    stream_list = fetch_streams()
    return render_template('streams.html', streams=stream_list)


@app.route('/info')
@login_required
def info():
    """Display general system information and per-stream connection details."""
    system_info = fetch_system_info()
    stream_info = fetch_stream_connections()
    return render_template('info.html', system=system_info, streams=stream_info)


if __name__ == '__main__':
    app.run(debug=True)

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
OME_API_URL = os.environ.get('OME_API_URL', 'http://localhost:8081/v1/stream')
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
        response = requests.get(OME_API_URL, timeout=3, auth=(OME_API_USER, OME_API_PASS))
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

@app.route('/streams')
@login_required
def streams():
    """Display available streams using OvenPlayer."""
    stream_list = fetch_streams()
    return render_template('streams.html', streams=stream_list)

if __name__ == '__main__':
    app.run(debug=True)

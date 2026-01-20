from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import json
import os
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import re

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=7)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configuration
DATA_FILE = 'data/users.json'
CONFIG_FILE = 'data/config.json'
WG_API_BASE = 'http://localhost:10086/api'
WG_CONFIG_NAME = 'wg0'

# Initialize data files
def init_data_files():
    os.makedirs('data', exist_ok=True)
    
    if not os.path.exists(DATA_FILE):
        default_admin = {
            'users': {
                'admin': {
                    'email': 'admin@cisf.gov.in',
                    'password': generate_password_hash('Admin@123'),
                    'role': 'admin',
                    'mfa_secret': None,
                    'mfa_enabled': False,
                    'must_reset_password': True,
                    'vpn_peer_id': None,
                    'vpn_enabled': False,
                    'created_at': datetime.now().isoformat()
                }
            }
        }
        save_data(default_admin)
    
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            'wg_api_key': 'stkORQvvZ1ehzvtiPT67IUyLfDJgfvrJuRx9dQ2A2kE'
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(default_config, f, indent=2)

def load_data():
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

# Password validation
def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

# WireGuard API functions
def wg_api_call(endpoint, method='GET', data=None):
    config = load_config()
    headers = {
        'wg-dashboard-apikey': config['wg_api_key'],
        'Content-Type': 'application/json'
    }
    url = f"{WG_API_BASE}/{endpoint}"
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data)
        
        return response.json()
    except Exception as e:
        return {'status': False, 'message': str(e)}

def restrict_peer(peer_id):
    return wg_api_call(f'restrictPeers/{WG_CONFIG_NAME}', 'POST', {'peers': [peer_id]})

def allow_peer(peer_id):
    return wg_api_call(f'allowAccessPeers/{WG_CONFIG_NAME}', 'POST', {'peers': [peer_id]})

def get_wg_peers():
    return wg_api_call(f'getWireguardConfigurationInfo?configurationName={WG_CONFIG_NAME}', 'GET')

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        
        # Check session timeout
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(hours=7):
                session.clear()
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            return jsonify({'status': False, 'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def mfa_verified(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('mfa_verified', False):
            return jsonify({'status': False, 'message': 'MFA verification required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'username' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/debug')
def debug():
    return render_template('debug.html')

@app.route('/login')
def login():
    return render_template('login_simple.html')

@app.route('/login-original')
def login_original():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username_or_email = data.get('username', '').strip()
    password = data.get('password', '')
    
    users_data = load_data()
    
    # Find user by username or email
    user = None
    found_username = None
    
    # First try direct username match
    if username_or_email in users_data['users']:
        user = users_data['users'][username_or_email]
        found_username = username_or_email
    else:
        # Try email match
        for uname, udata in users_data['users'].items():
            if udata.get('email', '').lower() == username_or_email.lower():
                user = udata
                found_username = uname
                break
    
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'status': False, 'message': 'Invalid username/email or password'})
    
    # Check if MFA is enabled
    if user['mfa_enabled']:
        session['pending_username'] = found_username
        session['pending_role'] = user['role']
        session['pending_must_reset'] = user.get('must_reset_password', False)
        return jsonify({'status': True, 'mfa_required': True})
    else:
        # First time login - setup required
        session['pending_username'] = found_username
        session['pending_role'] = user['role']
        return jsonify({'status': True, 'setup_required': True})

@app.route('/api/verify-mfa', methods=['POST'])
def verify_mfa():
    data = request.json
    token = data.get('token', '')
    
    username = session.get('pending_username')
    if not username:
        return jsonify({'status': False, 'message': 'Session expired'})
    
    users_data = load_data()
    user = users_data['users'].get(username)
    
    if not user or not user['mfa_enabled']:
        return jsonify({'status': False, 'message': 'MFA not configured'})
    
    totp = pyotp.TOTP(user['mfa_secret'])
    if not totp.verify(token, valid_window=1):
        return jsonify({'status': False, 'message': 'Invalid MFA token'})
    
    # MFA verified
    session['username'] = username
    session['role'] = user['role']
    session['mfa_verified'] = True
    session['last_activity'] = datetime.now().isoformat()
    session.pop('pending_username', None)
    session.pop('pending_role', None)
    session.pop('pending_must_reset', None)
    
    # Auto-disable VPN on logout tracking
    session['vpn_auto_disabled'] = False
    
    if user.get('must_reset_password', False):
        return jsonify({'status': True, 'must_reset_password': True})
    
    return jsonify({'status': True, 'redirect': '/admin' if user['role'] == 'admin' else '/dashboard'})

@app.route('/setup-mfa')
def setup_mfa():
    username = session.get('pending_username')
    if not username:
        return redirect(url_for('login'))
    return render_template('setup_mfa.html')

@app.route('/api/generate-mfa', methods=['POST'])
def generate_mfa():
    username = session.get('pending_username')
    if not username:
        return jsonify({'status': False, 'message': 'Session expired'})
    
    users_data = load_data()
    user = users_data['users'].get(username)
    
    if not user:
        return jsonify({'status': False, 'message': 'User not found'})
    
    # Generate MFA secret
    secret = pyotp.random_base32()
    users_data['users'][username]['mfa_secret'] = secret
    save_data(users_data)
    
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='CISF VPN Panel'
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return jsonify({
        'status': True,
        'secret': secret,
        'qr_code': f'data:image/png;base64,{qr_base64}'
    })

@app.route('/api/confirm-mfa', methods=['POST'])
def confirm_mfa():
    data = request.json
    token = data.get('token', '')
    
    username = session.get('pending_username')
    if not username:
        return jsonify({'status': False, 'message': 'Session expired'})
    
    users_data = load_data()
    user = users_data['users'].get(username)
    
    if not user or not user.get('mfa_secret'):
        return jsonify({'status': False, 'message': 'MFA not configured'})
    
    totp = pyotp.TOTP(user['mfa_secret'])
    if not totp.verify(token, valid_window=1):
        return jsonify({'status': False, 'message': 'Invalid MFA token'})
    
    # Enable MFA
    users_data['users'][username]['mfa_enabled'] = True
    save_data(users_data)
    
    return jsonify({'status': True, 'message': 'MFA enabled successfully'})

@app.route('/reset-password')
def reset_password_page():
    if 'pending_username' not in session and 'username' not in session:
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    username = session.get('username') or session.get('pending_username')
    if not username:
        return jsonify({'status': False, 'message': 'Session expired'})
    
    if new_password != confirm_password:
        return jsonify({'status': False, 'message': 'Passwords do not match'})
    
    valid, message = validate_password(new_password)
    if not valid:
        return jsonify({'status': False, 'message': message})
    
    users_data = load_data()
    users_data['users'][username]['password'] = generate_password_hash(new_password)
    users_data['users'][username]['must_reset_password'] = False
    save_data(users_data)
    
    # Complete login if pending
    if 'pending_username' in session:
        session['username'] = username
        session['role'] = session.get('pending_role')
        session['mfa_verified'] = True
        session['last_activity'] = datetime.now().isoformat()
        session.pop('pending_username', None)
        session.pop('pending_role', None)
    
    return jsonify({'status': True, 'message': 'Password reset successfully'})

@app.route('/dashboard')
@login_required
def user_dashboard():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    return render_template('user_dashboard.html')

@app.route('/api/user-info')
@login_required
def user_info():
    username = session['username']
    users_data = load_data()
    user = users_data['users'].get(username)
    
    if not user:
        return jsonify({'status': False, 'message': 'User not found'})
    
    # Get VPN status from WireGuard
    vpn_status = 'disabled'
    peer_info = None
    
    if user.get('vpn_peer_id'):
        wg_data = get_wg_peers()
        if wg_data.get('status'):
            all_peers = wg_data['data']['configurationPeers'] + wg_data['data'].get('configurationRestrictedPeers', [])
            for peer in all_peers:
                if peer['id'] == user['vpn_peer_id']:
                    peer_info = peer
                    # Check if in restricted list
                    restricted_peers = wg_data['data'].get('configurationRestrictedPeers', [])
                    is_restricted = any(p['id'] == user['vpn_peer_id'] for p in restricted_peers)
                    vpn_status = 'disabled' if is_restricted else 'enabled'
                    break
    
    return jsonify({
        'status': True,
        'user': {
            'username': username,
            'email': user['email'],
            'vpn_name': peer_info['name'] if peer_info else 'Not Configured',
            'vpn_public_key': user.get('vpn_peer_id', 'Not Configured'),
            'vpn_status': vpn_status,
            'vpn_enabled': user.get('vpn_enabled', False)
        }
    })

@app.route('/api/toggle-vpn', methods=['POST'])
@login_required
@mfa_verified
def toggle_vpn():
    username = session['username']
    users_data = load_data()
    user = users_data['users'].get(username)
    
    if not user or not user.get('vpn_peer_id'):
        return jsonify({'status': False, 'message': 'VPN not configured for this user'})
    
    peer_id = user['vpn_peer_id']
    
    # Toggle VPN
    if user.get('vpn_enabled', False):
        # Disable VPN
        result = restrict_peer(peer_id)
        if result.get('status'):
            users_data['users'][username]['vpn_enabled'] = False
            save_data(users_data)
            return jsonify({'status': True, 'message': 'VPN disabled', 'vpn_enabled': False})
    else:
        # Enable VPN
        result = allow_peer(peer_id)
        if result.get('status'):
            users_data['users'][username]['vpn_enabled'] = True
            save_data(users_data)
            return jsonify({'status': True, 'message': 'VPN enabled', 'vpn_enabled': True})
    
    return jsonify({'status': False, 'message': 'Failed to toggle VPN'})

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/api/admin/users')
@login_required
@admin_required
@mfa_verified
def admin_get_users():
    users_data = load_data()
    wg_data = get_wg_peers()
    
    users_list = []
    for username, user in users_data['users'].items():
        if user['role'] != 'admin':
            vpn_status = 'disabled'
            peer_name = 'Not Configured'
            
            if user.get('vpn_peer_id') and wg_data.get('status'):
                all_peers = wg_data['data']['configurationPeers'] + wg_data['data'].get('configurationRestrictedPeers', [])
                for peer in all_peers:
                    if peer['id'] == user['vpn_peer_id']:
                        peer_name = peer['name']
                        restricted_peers = wg_data['data'].get('configurationRestrictedPeers', [])
                        is_restricted = any(p['id'] == user['vpn_peer_id'] for p in restricted_peers)
                        vpn_status = 'disabled' if is_restricted else 'enabled'
                        break
            
            users_list.append({
                'username': username,
                'email': user['email'],
                'vpn_name': peer_name,
                'vpn_peer_id': user.get('vpn_peer_id', ''),
                'vpn_status': vpn_status,
                'mfa_enabled': user.get('mfa_enabled', False),
                'created_at': user.get('created_at', '')
            })
    
    return jsonify({'status': True, 'users': users_list})

@app.route('/api/admin/add-user', methods=['POST'])
@login_required
@admin_required
@mfa_verified
def admin_add_user():
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    temp_password = data.get('temp_password', '')
    vpn_peer_id = data.get('vpn_peer_id', '').strip()
    
    if not all([username, email, temp_password, vpn_peer_id]):
        return jsonify({'status': False, 'message': 'All fields are required'})
    
    # Validate against WireGuard peers
    wg_data = get_wg_peers()
    if not wg_data.get('status'):
        return jsonify({'status': False, 'message': 'Failed to verify with WireGuard'})
    
    all_peers = wg_data['data']['configurationPeers'] + wg_data['data'].get('configurationRestrictedPeers', [])
    peer_exists = any(peer['id'] == vpn_peer_id for peer in all_peers)
    
    if not peer_exists:
        return jsonify({'status': False, 'message': 'VPN Peer ID does not exist in WireGuard'})
    
    users_data = load_data()
    
    if username in users_data['users']:
        return jsonify({'status': False, 'message': 'Username already exists'})
    
    valid, message = validate_password(temp_password)
    if not valid:
        return jsonify({'status': False, 'message': message})
    
    users_data['users'][username] = {
        'email': email,
        'password': generate_password_hash(temp_password),
        'role': 'user',
        'mfa_secret': None,
        'mfa_enabled': False,
        'must_reset_password': True,
        'vpn_peer_id': vpn_peer_id,
        'vpn_enabled': False,
        'created_at': datetime.now().isoformat()
    }
    
    save_data(users_data)
    
    # Ensure VPN is disabled for new user
    restrict_peer(vpn_peer_id)
    
    return jsonify({'status': True, 'message': 'User added successfully'})

@app.route('/api/admin/delete-user', methods=['POST'])
@login_required
@admin_required
@mfa_verified
def admin_delete_user():
    data = request.json
    username = data.get('username', '').strip()
    
    users_data = load_data()
    
    if username not in users_data['users']:
        return jsonify({'status': False, 'message': 'User not found'})
    
    if users_data['users'][username]['role'] == 'admin':
        return jsonify({'status': False, 'message': 'Cannot delete admin user'})
    
    # Disable VPN before deleting
    peer_id = users_data['users'][username].get('vpn_peer_id')
    if peer_id:
        restrict_peer(peer_id)
    
    del users_data['users'][username]
    save_data(users_data)
    
    return jsonify({'status': True, 'message': 'User deleted successfully'})

@app.route('/api/admin/reset-user-password', methods=['POST'])
@login_required
@admin_required
@mfa_verified
def admin_reset_user_password():
    data = request.json
    username = data.get('username', '').strip()
    temp_password = data.get('temp_password', '')
    
    users_data = load_data()
    
    if username not in users_data['users']:
        return jsonify({'status': False, 'message': 'User not found'})
    
    valid, message = validate_password(temp_password)
    if not valid:
        return jsonify({'status': False, 'message': message})
    
    users_data['users'][username]['password'] = generate_password_hash(temp_password)
    users_data['users'][username]['must_reset_password'] = True
    save_data(users_data)
    
    return jsonify({'status': True, 'message': 'Password reset successfully'})

@app.route('/api/admin/get-api-key')
@login_required
@admin_required
@mfa_verified
def admin_get_api_key():
    config = load_config()
    return jsonify({'status': True, 'api_key': config['wg_api_key']})

@app.route('/api/admin/update-api-key', methods=['POST'])
@login_required
@admin_required
@mfa_verified
def admin_update_api_key():
    data = request.json
    new_api_key = data.get('api_key', '').strip()
    
    if not new_api_key:
        return jsonify({'status': False, 'message': 'API key is required'})
    
    config = load_config()
    config['wg_api_key'] = new_api_key
    save_config(config)
    
    return jsonify({'status': True, 'message': 'API key updated successfully'})

@app.route('/api/admin/update-user', methods=['POST'])
@login_required
@admin_required
@mfa_verified
def admin_update_user():
    data = request.json
    old_username = data.get('old_username', '').strip()
    new_username = data.get('new_username', '').strip()
    new_email = data.get('new_email', '').strip()
    
    if not all([old_username, new_username, new_email]):
        return jsonify({'status': False, 'message': 'All fields are required'})
    
    users_data = load_data()
    
    if old_username not in users_data['users']:
        return jsonify({'status': False, 'message': 'User not found'})
    
    # Check if new username already exists (and it's different from old username)
    if new_username != old_username and new_username in users_data['users']:
        return jsonify({'status': False, 'message': 'Username already exists'})
    
    # Check if email is already used by another user
    for uname, udata in users_data['users'].items():
        if uname != old_username and udata.get('email', '').lower() == new_email.lower():
            return jsonify({'status': False, 'message': 'Email already in use'})
    
    # Update user data
    user_data = users_data['users'][old_username]
    user_data['email'] = new_email
    
    # If username changed, move the user data
    if new_username != old_username:
        users_data['users'][new_username] = user_data
        del users_data['users'][old_username]
    
    save_data(users_data)
    
    return jsonify({'status': True, 'message': 'User updated successfully'})

@app.route('/api/admin/sync-peers')
@login_required
@admin_required
@mfa_verified
def admin_sync_peers():
    wg_data = get_wg_peers()
    if not wg_data.get('status'):
        return jsonify({'status': False, 'message': 'Failed to fetch WireGuard peers'})
    
    all_peers = wg_data['data']['configurationPeers'] + wg_data['data'].get('configurationRestrictedPeers', [])
    
    # Get existing users' peer IDs
    users_data = load_data()
    existing_peer_ids = set()
    for user in users_data['users'].values():
        if user.get('vpn_peer_id'):
            existing_peer_ids.add(user['vpn_peer_id'])
    
    peers_list = []
    new_peers = []
    
    for peer in all_peers:
        peer_info = {
            'id': peer['id'],
            'name': peer['name'],
            'allowed_ip': peer['allowed_ip'],
            'latest_handshake': peer['latest_handshake'],
            'in_panel': peer['id'] in existing_peer_ids
        }
        peers_list.append(peer_info)
        
        # Track new peers not in panel
        if peer['id'] not in existing_peer_ids:
            new_peers.append(peer_info)
    
    return jsonify({
        'status': True, 
        'peers': peers_list,
        'new_peers': new_peers,
        'total_peers': len(peers_list),
        'new_peers_count': len(new_peers),
        'message': f'Found {len(peers_list)} peers in WireGuard. {len(new_peers)} not yet added to panel.'
    })

@app.route('/logout')
def logout():
    username = session.get('username')
    
    # Auto-disable VPN on logout
    if username:
        users_data = load_data()
        user = users_data['users'].get(username)
        if user and user.get('vpn_peer_id') and user.get('vpn_enabled'):
            restrict_peer(user['vpn_peer_id'])
            users_data['users'][username]['vpn_enabled'] = False
            save_data(users_data)
    
    session.clear()
    return redirect(url_for('login'))

@app.before_request
def session_timeout():
    if 'username' in session:
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(hours=7):
                username = session.get('username')
                # Auto-disable VPN on session timeout
                if username:
                    users_data = load_data()
                    user = users_data['users'].get(username)
                    if user and user.get('vpn_peer_id') and user.get('vpn_enabled'):
                        restrict_peer(user['vpn_peer_id'])
                        users_data['users'][username]['vpn_enabled'] = False
                        save_data(users_data)
                session.clear()

if __name__ == '__main__':
    init_data_files()
    app.run(host='0.0.0.0', port=80, debug=False)

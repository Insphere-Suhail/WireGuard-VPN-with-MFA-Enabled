# CISF VPN Panel

A secure, responsive Flask-based VPN management panel with Multi-Factor Authentication (MFA), session management, and automatic VPN control via WireGuard API.

## Features

### User Features
- **Secure Authentication**: Username/password login with mandatory MFA
- **First-Time Setup**: 
  - MFA setup with QR code (Google Authenticator, Microsoft Authenticator, Authy)
  - Mandatory password reset on first login
- **VPN Control**: Enable/disable VPN access with a single click
- **Auto-Disable**: VPN automatically disables on logout or session timeout (7 hours)
- **Responsive UI**: Works seamlessly on desktop, tablet, and mobile devices
- **Password Security**: Strong password requirements (min 8 chars, 1 number, 1 special char)

### Admin Features
- **User Management**: Add, delete, and manage users
- **Password Reset**: Admin can provide temporary passwords to users
- **WireGuard Integration**: Sync and verify peers from WireGuard Dashboard
- **API Key Management**: Update WireGuard API key (MFA protected)
- **Real-time Status**: View all users' VPN status and login information
- **Cross-Verification**: Only create users that exist in WireGuard Dashboard

### Security Features
- ✅ Mandatory MFA for all users
- ✅ Salted password hashing (Werkzeug)
- ✅ Session timeout (7 hours)
- ✅ Auto-disable VPN on logout/timeout
- ✅ CSRF protection
- ✅ Secure session cookies
- ✅ MFA-protected admin actions
- ✅ Input validation
- ✅ No database - JSON file storage for 30 users

## Technology Stack

- **Backend**: Python Flask 3.0
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Authentication**: PyOTP (TOTP-based MFA)
- **Password Hashing**: Werkzeug Security
- **QR Code**: qrcode library
- **VPN API**: WireGuard Dashboard API
- **Deployment**: Docker & Docker Compose

## Prerequisites

- Docker and Docker Compose installed
- Access to WireGuard Dashboard API
- WireGuard API key

## Quick Start with Docker

### 1. Clone or Download the Project

```bash
cd cisf-vpn-panel
```

### 2. Set Environment Variables (Optional)

Create a `.env` file:

```bash
SECRET_KEY=your-super-secret-random-key-here
```

Or generate a random secret key:

```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
```

### 3. Build and Run with Docker Compose

```bash
docker-compose up -d
```

### 4. Access the Application

Open your browser and navigate to:
```
http://localhost:80
```

or

```
http://your-server-ip:80
```

### 5. Default Admin Credentials

**Username**: `admin`  
**Password**: `Admin@123`

**⚠️ IMPORTANT**: On first login:
1. You will be prompted to setup MFA
2. Scan the QR code with your authenticator app
3. Reset your password immediately

## Manual Installation (Without Docker)

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python app.py
```

The application will be available at `http://localhost:80`

## File Structure

```
cisf-vpn-panel/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker container configuration
├── docker-compose.yml          # Docker Compose setup
├── README.md                   # This file
├── data/                       # Auto-created data directory
│   ├── users.json             # User database (auto-created)
│   └── config.json            # API configuration (auto-created)
├── templates/                  # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── setup_mfa.html
│   ├── reset_password.html
│   ├── user_dashboard.html
│   └── admin_dashboard.html
└── static/                     # Static assets
    ├── css/
    │   └── style.css
    └── js/
        └── main.js
```

## Configuration

### WireGuard API Configuration

The application uses the following WireGuard Dashboard API endpoints:

1. **Restrict Peer** (Disable VPN):
   ```
   POST http://13.204.113.128:10086/api/restrictPeers/wg0
   ```

2. **Allow Peer** (Enable VPN):
   ```
   POST http://13.204.113.128:10086/api/allowAccessPeers/wg0
   ```

3. **Get Configuration Info**:
   ```
   GET http://13.204.113.128:10086/api/getWireguardConfigurationInfo?configurationName=wg0
   ```

**Default API Key**: `stkORQvvZ1ehzvtiPT67IUyLfDJgfvrJuRx9dQ2A2kE`

You can update the API key through the Admin Dashboard → Settings.

### Changing API Endpoints

Edit `app.py` and modify these variables:

```python
WG_API_BASE = 'http://your-wireguard-server:port/api'
WG_CONFIG_NAME = 'wg0'  # Your WireGuard interface name
```

## User Workflow

### For Normal Users:

1. **First Login**:
   - Receive username and temporary password from admin
   - Login with provided credentials
   - Setup MFA using Google Authenticator (or similar app)
   - Reset password to a strong password

2. **Regular Login**:
   - Enter username and password
   - Enter 6-digit MFA code from authenticator app
   - Access dashboard

3. **Enable VPN**:
   - Click "Enable VPN" button on dashboard
   - VPN access is granted via WireGuard

4. **Logout**:
   - Click "Logout" button
   - VPN access is automatically disabled

### For Admins:

1. **Add New User**:
   - Go to Admin Dashboard → User Management
   - Click "Add New User"
   - Enter username, email, temporary password
   - Select VPN Peer ID from WireGuard (or enter manually)
   - User can now login and complete setup

2. **Reset User Password**:
   - Find user in User Management table
   - Click "Reset Password"
   - Provide new temporary password
   - User must reset on next login

3. **Delete User**:
   - Find user in User Management table
   - Click "Delete"
   - Confirm deletion
   - User's VPN access is automatically disabled

4. **Update API Key**:
   - Go to Admin Dashboard → Settings
   - Enter MFA code when prompted
   - Enter new API key
   - Click "Update API Key"

## Security Best Practices

1. **Change Default Admin Password**: Immediately change the default admin password after first login

2. **Use Strong Passwords**: Enforce minimum 8 characters, 1 number, 1 special character

3. **Secure Secret Key**: Use a random, long secret key in production

4. **HTTPS**: Deploy behind a reverse proxy (nginx/Apache) with SSL/TLS certificates

5. **Firewall**: Restrict access to the application port (80) as needed

6. **Regular Backups**: Backup the `data` directory regularly

7. **Session Security**: The default 7-hour session timeout can be adjusted in `app.py`

## Database vs JSON Storage

**Current Implementation**: JSON file storage (`data/users.json`)

**Why JSON is OK for this use case:**
- ✅ Only 30 users maximum
- ✅ Simple read/write operations
- ✅ No complex queries needed
- ✅ Easy to backup and restore
- ✅ No database server overhead
- ✅ Portable across systems

**When to Consider Database:**
- ⚠️ More than 50 users
- ⚠️ Need for complex queries
- ⚠️ Multiple concurrent admin operations
- ⚠️ Audit logging requirements
- ⚠️ Advanced reporting needs

If you need to migrate to a database, consider SQLite (lightweight) or PostgreSQL (production-grade).

## Troubleshooting

### Application Won't Start

```bash
# Check logs
docker-compose logs -f

# Ensure port 80 is not in use
sudo netstat -tulpn | grep :80

# Rebuild container
docker-compose down
docker-compose up --build -d
```

### Can't Connect to WireGuard API

1. Verify WireGuard Dashboard is running
2. Check API endpoint URL in `app.py`
3. Verify API key is correct
4. Check network connectivity

### MFA Not Working

1. Ensure device time is synchronized (NTP)
2. Try entering code within 30-second window
3. Regenerate MFA secret if needed

### VPN Not Enabling/Disabling

1. Check WireGuard API is accessible
2. Verify peer ID matches WireGuard configuration
3. Check admin dashboard logs
4. Verify API key is valid

## Production Deployment Recommendations

1. **Use HTTPS**: Deploy behind nginx with Let's Encrypt SSL

   Example nginx configuration:
   ```nginx
   server {
       listen 443 ssl;
       server_name vpn-panel.example.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location / {
           proxy_pass http://localhost:80;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

2. **Environment Variables**: Use environment variables for sensitive data

3. **Firewall**: Restrict access to specific IPs if possible

4. **Monitoring**: Set up application and container monitoring

5. **Backups**: Regular backups of the `data` directory

6. **Updates**: Keep Docker images and dependencies updated

## License

This project is provided as-is for CISF internal use.

## Support

For issues or questions, contact your system administrator.

## Version

**Version**: 1.0.0  
**Last Updated**: January 2026

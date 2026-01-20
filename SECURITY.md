# Security Best Practices for CISF VPN Panel

## Overview

This document outlines the security features and best practices for deploying and maintaining the CISF VPN Panel.

## Built-in Security Features

### 1. Authentication & Authorization

✅ **Multi-Factor Authentication (MFA)**
- Mandatory TOTP-based MFA for all users
- Compatible with Google Authenticator, Microsoft Authenticator, Authy
- 30-second time window with 1-step tolerance

✅ **Password Security**
- Passwords hashed using Werkzeug's PBKDF2-SHA256
- Salt automatically generated for each password
- Minimum requirements: 8 characters, 1 number, 1 special character
- Forced password reset on first login

✅ **Session Management**
- 7-hour session timeout (configurable)
- Session cookie with HttpOnly flag
- Automatic logout on inactivity
- Session invalidation on logout

✅ **Role-Based Access Control**
- Admin vs User roles
- Admin-only routes protected
- MFA verification required for sensitive admin actions

### 2. VPN Access Control

✅ **Auto-Disable Mechanism**
- VPN automatically disabled on logout
- VPN disabled on session timeout
- No orphaned active VPN connections

✅ **WireGuard Integration**
- Real-time status verification
- Cross-validation with WireGuard Dashboard
- Peer ID verification before user creation

### 3. Input Validation

✅ **Server-Side Validation**
- Email format validation
- Username format validation
- Password strength validation
- API input sanitization

✅ **Client-Side Validation**
- HTML5 form validation
- JavaScript validation
- Pattern matching for MFA codes

### 4. Data Protection

✅ **Storage Security**
- JSON files with restricted permissions
- No plain-text passwords stored
- API keys hidden by default in UI
- Sensitive data not logged

## Deployment Security Recommendations

### 1. HTTPS/SSL Configuration

**CRITICAL**: Always use HTTPS in production

#### Option A: Let's Encrypt (Free SSL)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d vpn.yourdomain.com

# Auto-renewal
sudo certbot renew --dry-run
```

#### Option B: Commercial SSL Certificate

```nginx
server {
    listen 443 ssl http2;
    server_name vpn.yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 2. Firewall Configuration

#### UFW (Ubuntu)

```bash
# Default deny
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (change port if using non-standard)
sudo ufw allow 22/tcp

# Allow HTTPS only
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose
```

#### IP Whitelisting

```bash
# Allow only from specific IP ranges
sudo ufw delete allow 443/tcp
sudo ufw allow from 192.168.1.0/24 to any port 443
sudo ufw allow from 10.0.0.0/8 to any port 443
```

### 3. Secret Key Management

**NEVER** use the default secret key in production!

```bash
# Generate strong secret key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Set in environment
export SECRET_KEY="your-generated-key-here"

# Or in .env file
echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > .env
```

### 4. File Permissions

```bash
# Application directory
sudo chown -R www-data:www-data /opt/cisf-vpn-panel
sudo chmod -R 755 /opt/cisf-vpn-panel

# Data directory (more restrictive)
sudo chmod 700 /opt/cisf-vpn-panel/data
sudo chmod 600 /opt/cisf-vpn-panel/data/*.json

# Environment file
sudo chmod 600 /opt/cisf-vpn-panel/.env
```

### 5. Docker Security

#### Run as Non-Root User

Update Dockerfile:

```dockerfile
# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser
```

#### Docker Compose Security

```yaml
version: '3.8'

services:
  cisf-vpn-panel:
    build: .
    container_name: cisf-vpn-panel
    ports:
      - "127.0.0.1:8080:80"  # Only localhost
    volumes:
      - ./data:/app/data
    environment:
      - SECRET_KEY=${SECRET_KEY}
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp
```

### 6. Nginx Security Headers

Add to nginx configuration:

```nginx
# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

# Hide nginx version
server_tokens off;
```

### 7. Rate Limiting

#### Nginx Rate Limiting

```nginx
# Define rate limit zone
limit_req_zone $binary_remote_addr zone=loginlimit:10m rate=5r/m;

server {
    location /api/login {
        limit_req zone=loginlimit burst=10 nodelay;
        proxy_pass http://localhost:8080;
    }
}
```

#### Application-Level Rate Limiting

Install Flask-Limiter:

```bash
pip install Flask-Limiter
```

Add to app.py:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_login():
    # ... existing code
```

## Operational Security

### 1. Access Control

- [ ] Change default admin password immediately
- [ ] Use strong, unique passwords
- [ ] Enable MFA for all accounts
- [ ] Review user access regularly
- [ ] Remove inactive users promptly
- [ ] Limit admin account creation

### 2. Monitoring & Logging

#### Enable Application Logging

Add to app.py:

```python
import logging

logging.basicConfig(
    filename='data/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Log authentication attempts
@app.route('/api/login', methods=['POST'])
def api_login():
    username = request.json.get('username')
    # ... authentication logic
    if successful:
        logging.info(f"Successful login: {username}")
    else:
        logging.warning(f"Failed login attempt: {username}")
```

#### Monitor Logs

```bash
# Watch application logs
tail -f /opt/cisf-vpn-panel/data/app.log

# Watch nginx access logs
tail -f /var/log/nginx/access.log

# Watch auth logs
sudo tail -f /var/log/auth.log
```

#### Setup Log Rotation

Create `/etc/logrotate.d/cisf-vpn-panel`:

```
/opt/cisf-vpn-panel/data/app.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
    sharedscripts
}
```

### 3. Backup Security

```bash
# Encrypt backups
tar -czf - data/ | gpg -c > backup-$(date +%Y%m%d).tar.gz.gpg

# Set backup file permissions
chmod 600 backup-*.tar.gz.gpg

# Store backups securely
# - Off-site location
# - Encrypted storage
# - Access restricted
```

### 4. Regular Updates

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Python packages
pip install --upgrade -r requirements.txt

# Update Docker images
docker-compose pull
docker-compose up -d
```

### 5. Security Auditing

#### Monthly Security Checklist

- [ ] Review user accounts and remove inactive users
- [ ] Check for failed login attempts
- [ ] Review VPN access logs
- [ ] Update system packages
- [ ] Rotate API keys
- [ ] Test backup restoration
- [ ] Review firewall rules
- [ ] Check SSL certificate expiration
- [ ] Scan for vulnerabilities

#### Vulnerability Scanning

```bash
# Scan Python dependencies
pip install safety
safety check

# Scan Docker images
docker scan cisf-vpn-panel
```

## Incident Response

### Compromised Account

1. **Immediate Actions**:
   ```bash
   # Disable VPN access
   # Reset user password via admin panel
   # Force MFA re-enrollment
   ```

2. **Investigation**:
   - Check login logs
   - Review VPN access history
   - Check for unusual activity

3. **Recovery**:
   - Reset password
   - Re-setup MFA
   - Monitor account activity

### Suspected Breach

1. **Immediate Actions**:
   - Take application offline
   - Disable all VPN access
   - Backup current state for forensics

2. **Investigation**:
   - Review all logs
   - Check for unauthorized access
   - Identify attack vector

3. **Recovery**:
   - Patch vulnerabilities
   - Rotate all secrets (API keys, SECRET_KEY)
   - Force password reset for all users
   - Force MFA re-enrollment
   - Restore from clean backup if needed

## Compliance Considerations

### Data Protection

- [ ] User data stored securely (hashed passwords, encrypted if needed)
- [ ] Data access logged
- [ ] Data retention policy defined
- [ ] Backup and recovery procedures documented

### Access Audit Trail

- [ ] Login attempts logged
- [ ] VPN enable/disable logged
- [ ] Admin actions logged
- [ ] User creation/deletion logged

## Security Testing

### Penetration Testing Checklist

- [ ] SQL Injection (N/A - no database)
- [ ] XSS vulnerabilities
- [ ] CSRF protection
- [ ] Session hijacking
- [ ] Brute force login attempts
- [ ] MFA bypass attempts
- [ ] Authorization bypass
- [ ] API endpoint security

### Recommended Tools

```bash
# OWASP ZAP for web scanning
# Burp Suite for penetration testing
# Nmap for network scanning
# SSLyze for SSL/TLS testing
```

## Conclusion

Security is an ongoing process. Regularly review and update your security measures, stay informed about new vulnerabilities, and maintain a proactive security posture.

**Remember**: The security of your VPN infrastructure depends on the weakest link. Follow all recommendations and maintain vigilance.

# CISF VPN Panel - Deployment Guide

## Quick Deployment Steps

### Option 1: Docker Compose (Recommended)

1. **Install Docker and Docker Compose**
   ```bash
   # For Ubuntu/Debian
   sudo apt update
   sudo apt install docker.io docker-compose -y
   sudo systemctl start docker
   sudo systemctl enable docker
   ```

2. **Upload Files to Server**
   ```bash
   # Upload the entire cisf-vpn-panel directory to your server
   scp -r cisf-vpn-panel user@server:/opt/
   ```

3. **Generate Secret Key**
   ```bash
   cd /opt/cisf-vpn-panel
   python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
   ```

4. **Build and Start**
   ```bash
   sudo docker-compose up -d
   ```

5. **Check Status**
   ```bash
   sudo docker-compose ps
   sudo docker-compose logs -f
   ```

6. **Access Application**
   - Open browser: `http://your-server-ip:80`
   - Default login: `admin` / `Admin@123`

### Option 2: Direct Python Deployment

1. **Install Python 3.11+**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip -y
   ```

2. **Install Dependencies**
   ```bash
   cd cisf-vpn-panel
   pip3 install -r requirements.txt
   ```

3. **Set Environment Variable**
   ```bash
   export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   ```

4. **Run Application**
   ```bash
   sudo python3 app.py
   ```

## Production Deployment with Nginx + SSL

### 1. Install Nginx

```bash
sudo apt install nginx certbot python3-certbot-nginx -y
```

### 2. Configure Nginx

Create `/etc/nginx/sites-available/cisf-vpn-panel`:

```nginx
server {
    listen 80;
    server_name vpn.yourdomain.com;  # Change this
    
    location / {
        proxy_pass http://localhost:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. Enable Site

```bash
sudo ln -s /etc/nginx/sites-available/cisf-vpn-panel /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 4. Setup SSL with Let's Encrypt

```bash
sudo certbot --nginx -d vpn.yourdomain.com
```

### 5. Update Docker Compose for Production

Edit `docker-compose.yml` to change port binding:

```yaml
ports:
  - "127.0.0.1:8080:80"  # Only accessible via localhost
```

Then restart:
```bash
sudo docker-compose down
sudo docker-compose up -d
```

Update nginx config to proxy to port 8080:
```nginx
proxy_pass http://localhost:8080;
```

## Systemd Service (Alternative to Docker)

Create `/etc/systemd/system/cisf-vpn-panel.service`:

```ini
[Unit]
Description=CISF VPN Panel
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/cisf-vpn-panel
Environment="SECRET_KEY=your-secret-key-here"
ExecStart=/usr/bin/python3 /opt/cisf-vpn-panel/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable cisf-vpn-panel
sudo systemctl start cisf-vpn-panel
sudo systemctl status cisf-vpn-panel
```

## Firewall Configuration

### UFW (Ubuntu)

```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
```

### Restrict Access to Specific IPs (Optional)

```bash
# Allow only from specific IP
sudo ufw allow from 192.168.1.100 to any port 80
sudo ufw allow from 192.168.1.100 to any port 443
```

## Backup and Restore

### Backup

```bash
# Backup data directory
tar -czf cisf-vpn-panel-backup-$(date +%Y%m%d).tar.gz data/

# Copy to safe location
scp cisf-vpn-panel-backup-*.tar.gz user@backup-server:/backups/
```

### Restore

```bash
# Stop application
sudo docker-compose down

# Restore data
tar -xzf cisf-vpn-panel-backup-YYYYMMDD.tar.gz

# Start application
sudo docker-compose up -d
```

### Automated Daily Backup

Create `/etc/cron.daily/cisf-vpn-panel-backup`:

```bash
#!/bin/bash
cd /opt/cisf-vpn-panel
tar -czf /backups/cisf-vpn-panel-$(date +%Y%m%d).tar.gz data/
find /backups/ -name "cisf-vpn-panel-*.tar.gz" -mtime +30 -delete
```

Make executable:
```bash
sudo chmod +x /etc/cron.daily/cisf-vpn-panel-backup
```

## Monitoring

### Check Application Health

```bash
# Docker logs
sudo docker-compose logs -f cisf-vpn-panel

# System logs
sudo journalctl -u cisf-vpn-panel -f

# Check if application is responding
curl http://localhost:80
```

### Monitor Resource Usage

```bash
# Docker stats
sudo docker stats cisf-vpn-panel

# System resources
htop
```

## Updating the Application

### With Docker

```bash
cd /opt/cisf-vpn-panel

# Pull latest code
git pull  # or upload new files

# Rebuild and restart
sudo docker-compose down
sudo docker-compose build --no-cache
sudo docker-compose up -d
```

### Without Docker

```bash
cd /opt/cisf-vpn-panel

# Pull latest code
git pull  # or upload new files

# Restart service
sudo systemctl restart cisf-vpn-panel
```

## Troubleshooting

### Port Already in Use

```bash
# Find what's using port 80
sudo lsof -i :80
sudo netstat -tulpn | grep :80

# Stop the service
sudo systemctl stop apache2  # or nginx
```

### Permission Denied

```bash
# Give proper permissions
sudo chown -R $USER:$USER /opt/cisf-vpn-panel
chmod -R 755 /opt/cisf-vpn-panel
```

### Can't Access from External IP

```bash
# Check if listening on all interfaces
sudo netstat -tulpn | grep :80

# Check firewall
sudo ufw status
```

### Application Crashes

```bash
# Check logs
sudo docker-compose logs --tail=100 cisf-vpn-panel

# Check disk space
df -h

# Check memory
free -m
```

## Security Checklist

- [ ] Changed default admin password
- [ ] Generated strong SECRET_KEY
- [ ] Configured HTTPS/SSL
- [ ] Configured firewall (UFW/iptables)
- [ ] Set up automated backups
- [ ] Restricted access to specific IPs (if applicable)
- [ ] Updated WireGuard API key
- [ ] Configured session timeout appropriately
- [ ] Set up monitoring/alerting
- [ ] Reviewed and secured data directory permissions

## Performance Tuning

For high-traffic deployments, consider:

1. **Use Gunicorn** instead of Flask dev server:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:80 app:app
   ```

2. **Enable nginx caching** for static assets

3. **Use Redis** for session storage instead of filesystem

4. **Optimize Docker** with multi-stage builds

## Support

For deployment issues, check:
1. Application logs
2. System logs
3. Docker logs
4. Nginx logs (if using)

Common log locations:
- Docker: `sudo docker-compose logs`
- Systemd: `sudo journalctl -u cisf-vpn-panel`
- Nginx: `/var/log/nginx/error.log`

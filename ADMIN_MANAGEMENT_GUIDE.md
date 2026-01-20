# Admin User Management Guide

## 📋 Table of Contents
1. [Create Another Admin User](#create-another-admin-user)
2. [Change Admin Password](#change-admin-password)
3. [Convert Regular User to Admin](#convert-regular-user-to-admin)
4. [Security Best Practices](#security-best-practices)

---

## 🔐 Create Another Admin User

There are **3 methods** to create additional admin users:

### Method 1: Using Python Script (Easiest & Recommended)

**Step 1:** Stop the application
```bash
# If running with Python
Ctrl+C

# If running with Docker
docker-compose down
```

**Step 2:** Navigate to your application folder
```bash
cd cisf-vpn-panel
```

**Step 3:** Run this Python script
```bash
python3 << 'EOF'
from werkzeug.security import generate_password_hash
import json
from datetime import datetime

# Load existing users
with open('data/users.json', 'r') as f:
    users_data = json.load(f)

# Create new admin user
new_admin_username = 'admin2'  # Change this to your desired username
new_admin_email = 'admin2@cisf.gov.in'  # Change this to desired email
new_admin_password = 'Admin2@123'  # Change this to desired password

users_data['users'][new_admin_username] = {
    'email': new_admin_email,
    'password': generate_password_hash(new_admin_password),
    'role': 'admin',  # This makes them an admin
    'mfa_secret': None,
    'mfa_enabled': False,
    'must_reset_password': True,
    'vpn_peer_id': None,
    'vpn_enabled': False,
    'created_at': datetime.now().isoformat()
}

# Save back to file
with open('data/users.json', 'w') as f:
    json.dump(users_data, f, indent=2)

print(f'✅ Admin user created successfully!')
print(f'Username: {new_admin_username}')
print(f'Email: {new_admin_email}')
print(f'Password: {new_admin_password}')
print(f'⚠️  User must setup MFA and reset password on first login')
EOF
```

**Step 4:** Restart the application
```bash
# If running with Python
python app.py

# If running with Docker
docker-compose up -d
```

**Step 5:** Login with new admin credentials
1. Go to `http://localhost:80`
2. Login with:
   - Username: `admin2` (or whatever you set)
   - Password: `Admin2@123` (or whatever you set)
3. Setup MFA (scan QR code)
4. Reset password
5. You're done! ✅

---

### Method 2: Manual JSON Edit (For Advanced Users)

**Step 1:** Stop the application

**Step 2:** Open `data/users.json` in a text editor

**Step 3:** Generate password hash
```bash
python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YourPassword123'))"
```

Copy the output (it will look like: `scrypt:32768:8:1$...`)

**Step 4:** Add new admin entry to users.json

**Before:**
```json
{
  "users": {
    "admin": {
      "email": "admin@cisf.gov.in",
      "password": "scrypt:32768:8:1$...",
      "role": "admin",
      ...
    }
  }
}
```

**After:**
```json
{
  "users": {
    "admin": {
      "email": "admin@cisf.gov.in",
      "password": "scrypt:32768:8:1$...",
      "role": "admin",
      ...
    },
    "admin2": {
      "email": "admin2@cisf.gov.in",
      "password": "scrypt:32768:8:1$j2zddE6CPymgDWg2$...",
      "role": "admin",
      "mfa_secret": null,
      "mfa_enabled": false,
      "must_reset_password": true,
      "vpn_peer_id": null,
      "vpn_enabled": false,
      "created_at": "2026-01-17T13:00:00.000000"
    }
  }
}
```

**Important:** 
- Add a comma after the first admin user's closing brace
- Use the password hash you generated
- Make sure `"role": "admin"` (not "user")
- Set `"mfa_enabled": false` and `"must_reset_password": true`

**Step 5:** Save the file and restart application

---

### Method 3: Using Docker Exec (If Running in Docker)

**Step 1:** Run this command while app is running
```bash
docker exec -it cisf-vpn-panel python3 << 'EOF'
from werkzeug.security import generate_password_hash
import json
from datetime import datetime

with open('data/users.json', 'r') as f:
    users_data = json.load(f)

new_admin = {
    'email': 'admin2@cisf.gov.in',
    'password': generate_password_hash('Admin2@123'),
    'role': 'admin',
    'mfa_secret': None,
    'mfa_enabled': False,
    'must_reset_password': True,
    'vpn_peer_id': None,
    'vpn_enabled': False,
    'created_at': datetime.now().isoformat()
}

users_data['users']['admin2'] = new_admin

with open('data/users.json', 'w') as f:
    json.dump(users_data, f, indent=2)

print('Admin created!')
EOF
```

**Step 2:** Restart container
```bash
docker-compose restart
```

---

## 🔑 Change Admin Password

There are **3 methods** to change an admin password:

### Method 1: Through the Application (Recommended)

This is the **easiest** method if you can still login.

**Step 1:** Login as the admin whose password you want to change

**Step 2:** After MFA, you'll see the dashboard

**Step 3:** Create a simple password reset script
```bash
cd cisf-vpn-panel
python3 << 'EOF'
from werkzeug.security import generate_password_hash
import json

# Load users
with open('data/users.json', 'r') as f:
    users_data = json.load(f)

# Change admin password
admin_username = 'admin'  # Username to change
new_password = 'NewAdmin@2026'  # New password

users_data['users'][admin_username]['password'] = generate_password_hash(new_password)
users_data['users'][admin_username]['must_reset_password'] = False

# Save
with open('data/users.json', 'w') as f:
    json.dump(users_data, f, indent=2)

print(f'✅ Password changed for user: {admin_username}')
print(f'New password: {new_password}')
print('⚠️  You can now login with the new password')
EOF
```

**Step 4:** Logout and login with new password

---

### Method 2: If You Forgot Your Password (Password Reset)

**Step 1:** Stop the application
```bash
# Python
Ctrl+C

# Docker
docker-compose down
```

**Step 2:** Reset password using Python
```bash
cd cisf-vpn-panel

python3 << 'EOF'
from werkzeug.security import generate_password_hash
import json

# Configuration
username_to_reset = 'admin'  # Change this if needed
new_password = 'ResetAdmin@2026'  # Your new password

# Load users
with open('data/users.json', 'r') as f:
    users_data = json.load(f)

# Check if user exists
if username_to_reset not in users_data['users']:
    print(f'❌ User "{username_to_reset}" not found!')
    exit(1)

# Reset password
users_data['users'][username_to_reset]['password'] = generate_password_hash(new_password)
users_data['users'][username_to_reset]['must_reset_password'] = False

# Save
with open('data/users.json', 'w') as f:
    json.dump(users_data, f, indent=2)

print(f'✅ Password reset successfully!')
print(f'Username: {username_to_reset}')
print(f'New Password: {new_password}')
print('You can now start the application and login.')
EOF
```

**Step 3:** Restart application
```bash
# Python
python app.py

# Docker
docker-compose up -d
```

**Step 4:** Login with new password

---

### Method 3: Quick Password Reset (One-Liner)

Stop the app, then run:

```bash
python3 -c "
from werkzeug.security import generate_password_hash
import json

with open('data/users.json', 'r') as f:
    data = json.load(f)

data['users']['admin']['password'] = generate_password_hash('NewPassword@123')
data['users']['admin']['must_reset_password'] = False

with open('data/users.json', 'w') as f:
    json.dump(data, f, indent=2)

print('Password changed to: NewPassword@123')
"
```

Then restart the app.

---

## 👤 Convert Regular User to Admin

If you have a regular user and want to make them an admin:

**Step 1:** Stop the application

**Step 2:** Run this script
```bash
python3 << 'EOF'
import json

# Configuration
username_to_promote = 'testuser'  # Username to make admin

# Load users
with open('data/users.json', 'r') as f:
    users_data = json.load(f)

# Check if user exists
if username_to_promote not in users_data['users']:
    print(f'❌ User "{username_to_promote}" not found!')
    exit(1)

# Change role to admin
users_data['users'][username_to_promote]['role'] = 'admin'

# Save
with open('data/users.json', 'w') as f:
    json.dump(users_data, f, indent=2)

print(f'✅ User "{username_to_promote}" is now an admin!')
print('Restart the application for changes to take effect.')
EOF
```

**Step 3:** Restart application

**Step 4:** User can now access admin dashboard

---

## 🛡️ Security Best Practices

### ✅ DO's:

1. **Use Strong Passwords:**
   - Minimum 8 characters
   - Include numbers
   - Include special characters
   - Example: `Admin@2026!Secure`

2. **Always Setup MFA:**
   - Every admin MUST have MFA enabled
   - Use Google Authenticator or similar

3. **Limit Admin Accounts:**
   - Only create admin accounts for people who need them
   - Regular users don't need admin access

4. **Change Default Password:**
   - NEVER keep `Admin@123` in production
   - Change it immediately after first login

5. **Backup Before Changes:**
   ```bash
   cp data/users.json data/users.json.backup
   ```

6. **Logout After Admin Tasks:**
   - Don't leave admin sessions open
   - Sessions expire after 7 hours anyway

### ❌ DON'Ts:

1. ❌ Don't share admin credentials
2. ❌ Don't disable MFA
3. ❌ Don't use weak passwords
4. ❌ Don't create unnecessary admin accounts
5. ❌ Don't edit users.json while app is running
6. ❌ Don't forget to backup before making changes

---

## 📊 Quick Reference Table

| Task | Method | Difficulty | App Running? |
|------|--------|-----------|--------------|
| Create admin | Python script | Easy | Must stop |
| Change password | Python script | Easy | Must stop |
| Reset password | One-liner | Easy | Must stop |
| Promote user | Python script | Easy | Must stop |
| Manual edit JSON | Text editor | Medium | Must stop |

---

## 🔧 Troubleshooting

### Problem: "User already exists"

**Solution:** Choose a different username or delete the existing user first.

### Problem: Script says "Module not found"

**Solution:** Make sure you're in the `cisf-vpn-panel` directory:
```bash
cd cisf-vpn-panel
pip install -r requirements.txt
```

### Problem: Changes don't take effect

**Solution:** 
1. Make sure you stopped the app before making changes
2. Make sure you restarted after making changes
3. Check `data/users.json` to verify changes were saved

### Problem: Can't login after password change

**Solution:**
1. Check if you're using the correct new password
2. Check if `users.json` was properly saved
3. Restart the application
4. Try the password reset script again

### Problem: Invalid JSON error

**Solution:**
1. Restore from backup: `cp data/users.json.backup data/users.json`
2. Use the Python script instead of manual editing
3. Validate JSON: `python3 -m json.tool data/users.json`

---

## 📝 Example: Complete Admin Creation Workflow

Here's a complete example of creating a second admin:

```bash
# 1. Navigate to app folder
cd cisf-vpn-panel

# 2. Backup current users
cp data/users.json data/users.json.backup

# 3. Stop the app
# Press Ctrl+C if running, or:
docker-compose down

# 4. Create new admin
python3 << 'EOF'
from werkzeug.security import generate_password_hash
import json
from datetime import datetime

with open('data/users.json', 'r') as f:
    users_data = json.load(f)

users_data['users']['superadmin'] = {
    'email': 'superadmin@cisf.gov.in',
    'password': generate_password_hash('SuperAdmin@2026'),
    'role': 'admin',
    'mfa_secret': None,
    'mfa_enabled': False,
    'must_reset_password': True,
    'vpn_peer_id': None,
    'vpn_enabled': False,
    'created_at': datetime.now().isoformat()
}

with open('data/users.json', 'w') as f:
    json.dump(users_data, f, indent=2)

print('✅ Admin "superadmin" created!')
print('Password: SuperAdmin@2026')
EOF

# 5. Start the app
python app.py
# or
docker-compose up -d

# 6. Login at http://localhost:80
# Username: superadmin
# Password: SuperAdmin@2026
# Setup MFA and reset password
```

---

## 🎯 Summary

**To create an admin:**
1. Stop app
2. Run Python script to add admin user
3. Restart app
4. Login and setup MFA

**To change password:**
1. Stop app
2. Run Python script to change password
3. Restart app
4. Login with new password

**Remember:**
- ✅ Always backup before changes
- ✅ Always stop app before editing users.json
- ✅ Always restart app after changes
- ✅ Set `"role": "admin"` for admin users
- ✅ Setup MFA on first login

---

**Need help? Check the troubleshooting section above!** 🚀

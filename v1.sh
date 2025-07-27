#!/bin/bash
set -e

PANEL_PORT=8080
VPN_PORT=4443
PANEL_DIR="/opt/ocserv-admin"
ADMIN_USER="admin"
ADMIN_PASS=$(tr -dc 'A-Z' </dev/urandom | head -c2)$(tr -dc '0-9' </dev/urandom | head -c3)
ADMIN_INFO="$PANEL_DIR/admin.json"
CSV_FILE="/root/vpn_users.csv"
USER_FILE="/etc/ocserv/ocpasswd"
CERT_DIR="/etc/ocserv/certs"
SOCKET_FILE="/run/ocserv.socket"
LOG_FILE="/var/log/ocserv.log"

echo "[*] Installing dependencies..."
apt update
apt install -y python3 python3-pip python3-venv ocserv curl openssl pwgen iproute2 iptables-persistent sudo

echo "[*] Configuring ocserv VPN on port $VPN_PORT..."
mkdir -p $CERT_DIR
if [ ! -f "$CERT_DIR/server.crt" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=NA/L=NA/O=NA/CN=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')"
fi

cat >/etc/ocserv/ocserv.conf <<EOF
auth = "plain[/etc/ocserv/ocpasswd]"
tcp-port = $VPN_PORT
udp-port = $VPN_PORT
server-cert = $CERT_DIR/server.crt
server-key = $CERT_DIR/server.key
socket-file = $SOCKET_FILE
device = vpns
max-clients = 6000
max-same-clients = 1
default-domain = vpn
ipv4-network = 192.168.150.0/24
dns = 8.8.8.8
dns = 1.1.1.1
log-file = $LOG_FILE
EOF

echo "[*] Opening firewall for VPN port $VPN_PORT..."
if command -v ufw &>/dev/null; then
    ufw allow $VPN_PORT/tcp || true
    ufw allow $VPN_PORT/udp || true
    ufw reload || true
else
    iptables -I INPUT -p tcp --dport $VPN_PORT -j ACCEPT || true
    iptables -I INPUT -p udp --dport $VPN_PORT -j ACCEPT || true
fi

echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ocserv-forward.conf
sysctl -w net.ipv4.ip_forward=1
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
iptables -t nat -A POSTROUTING -s 192.168.150.0/24 -o "$IFACE" -j MASQUERADE || true
netfilter-persistent save

touch "$USER_FILE"
chmod 600 "$USER_FILE"

if [ ! -f "$CSV_FILE" ]; then
    echo "username,password" > "$CSV_FILE"
fi
chmod 666 "$CSV_FILE"

mkdir -p $PANEL_DIR
cd $PANEL_DIR
python3 -m venv venv
source venv/bin/activate
pip install flask

cat > $ADMIN_INFO <<EOF
{
    "username": "$ADMIN_USER",
    "password": "$ADMIN_PASS"
}
EOF

cat > $PANEL_DIR/requirements.txt <<EOF
flask
EOF

# ========= Flask Admin Panel app.py =========
cat > $PANEL_DIR/app.py <<"EOF"
import os, json, subprocess, csv, socket
from flask import Flask, render_template_string, request, redirect, url_for, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
CSV_FILE = '/root/vpn_users.csv'
USER_FILE = '/etc/ocserv/ocpasswd'
LOG_FILE = '/var/log/ocserv.log'
MAX_USERS = 6000
PANEL_PORT = 8080
VPN_PORT = 4443

app = Flask(__name__)
app.secret_key = 'this-is-super-secret-change-me'

def get_ip():
    try:
        import urllib.request
        ip = urllib.request.urlopen('https://ipv4.icanhazip.com').read().decode().strip()
        return ip
    except:
        return socket.gethostbyname(socket.gethostname())

def load_admin():
    with open(ADMIN_INFO) as f:
        return json.load(f)
def save_admin(admin):
    with open(ADMIN_INFO, 'w') as f:
        json.dump(admin, f)
def get_users():
    users = []
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE) as f:
            reader = csv.reader(f)
            for row in reader:
                if row and row[0] == 'username':
                    continue
                if len(row) >= 2:
                    users.append({'username': row[0], 'password': row[1]})
    return users

@app.route('/', methods=['GET', 'POST'])
def login():
    if session.get('admin'):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        creds = load_admin()
        if request.form['username'] == creds['username'] and request.form['password'] == creds['password']:
            session['admin'] = True
            return redirect(url_for('dashboard'))
        flash('Login failed.', 'error')
    return render_template_string('''
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>OpenConnect Admin Login</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@700;900&display=swap" rel="stylesheet">
      <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
      <style>
        body {background: linear-gradient(120deg, #232e47 0%, #447cfb 100%); min-height:100vh; font-family: 'Inter',sans-serif; margin:0;}
        .login-card {max-width:380px; margin:80px auto; background:#fff; border-radius:20px; box-shadow:0 8px 32px #0002; padding:36px 28px;}
        h2 {margin:0 0 20px 0; color:#2354be; font-size:2em; font-weight:900;}
        input {width:100%; padding:15px; border-radius:9px; border:1px solid #bcd; margin-bottom:16px; font-size:1.1em;}
        button {width:100%; background:linear-gradient(90deg,#3579f8,#43e3c1); color:#fff; border:0; border-radius:9px; font-size:1.12em; font-weight:700; padding:14px; transition:.15s;}
        button:hover {filter:brightness(.97);}
        .toast {color:#e9435b; font-weight:700; margin-top:12px;}
        @media(max-width:600px) {.login-card{padding:18px 8px;}}
      </style>
    </head>
    <body>
      <form class="login-card" method=post>
        <h2>OpenConnect<br>Admin</h2>
        <input name=username placeholder="admin" required>
        <input name=password type=password placeholder="password" required>
        <button>Login</button>
        <div class="toast">{% with messages = get_flashed_messages(with_categories=true) %}
            {% for cat,msg in messages %}{% if cat=='error' %}{{msg}}{% endif %}{% endfor %}{% endwith %}</div>
      </form>
    </body>
    </html>
    ''')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('admin'):
        return redirect(url_for('login'))
    users = get_users()
    admin = load_admin()
    server_ip = get_ip()
    edit = request.args.get('edit') == '1'
    return render_template_string('''
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>OpenConnect Admin</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@700;900&display=swap" rel="stylesheet">
      <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
      <style>
        body {background: linear-gradient(120deg,#232e47 0%, #447cfb 100%); min-height:100vh; margin:0;}
        .main-wrap {max-width:420px; margin:0 auto 0 auto; padding:24px 0;}
        .header {font-size:2.1em; color:#fff; font-weight:900; letter-spacing:-1px; margin-bottom:24px; text-align:center;}
        .card {background:#fff; border-radius:18px; box-shadow:0 6px 32px #0002; margin-bottom:21px; padding:22px 18px; display:flex; flex-direction:column;}
        .row {display:flex;align-items:center;gap:14px;margin-bottom:10px;}
        .icon-btn {background:#edf3fd;border-radius:9px;border:0;padding:8px 11px;cursor:pointer;font-size:1.35em;vertical-align:middle;display:inline-flex;align-items:center;position:relative;}
        .icon-btn:active{background:#cbe0fc;}
        .ip-port {font-size:1.13em; color:#2263db; font-weight:800;}
        .adduser-input {flex:1;}
        .user-table {width:100%; margin-top:10px; border-collapse:collapse;}
        .user-table th, .user-table td {padding:10px 6px;text-align:left;}
        .user-table th {background:#f2f7ff;}
        .user-table tr:nth-child(even) {background:#f7fafd;}
        .user-delete-btn {background:#ffebee; color:#e9435b; border-radius:9px; border:0; font-size:1.1em; cursor:pointer; padding:5px 10px;}
        .user-delete-btn:active {background:#f9bbbe;}
        .admin-row {display:flex;align-items:center;justify-content:space-between;}
        .admin-label {color:#888;font-size:.97em;}
        .admin-value {font-size:1.04em;}
        .edit-btn {background:none; border:0; color:#3579f8; font-size:1.24em; cursor:pointer; margin-left:8px;}
        .edit-btn:active {color:#1e2c7d;}
        .panel-info {color:#115; font-size:1.01em;}
        .copy-cmd-box {display:flex;align-items:center;gap:10px;margin-top:6px;}
        .copy-cmd-inp {flex:1; font-size:1em; padding:8px 9px; border-radius:8px; border:1px solid #cce;}
        .copy-cmd-icon {background:#edf3fd;border-radius:8px;border:0;padding:8px 11px;cursor:pointer;font-size:1.35em;vertical-align:middle;display:inline-flex;align-items:center;position:relative;}
        .copy-cmd-icon:active{background:#cbe0fc;}
        .save-btn {margin-top:12px;width:100%;background:linear-gradient(90deg,#3579f8,#43e3c1); color:#fff; border:0; border-radius:9px; font-size:1.09em; font-weight:700; padding:13px;}
        .save-btn:active {filter:brightness(.97);}
        .dashboard-links {display:flex;gap:15px;margin-bottom:15px;}
        .dashboard-links a {background:#232e47;color:#fff;border-radius:8px;padding:8px 18px;text-decoration:none;font-weight:700;font-size:1em;transition:.1s;}
        .dashboard-links a:hover {background:#447cfb;}
        @media(max-width:480px) {
            .main-wrap {padding:8px 2vw;}
            .card {padding:14px 4vw;}
        }
      </style>
    </head>
    <body>
    <div class="main-wrap">
      <div class="header">OpenConnect Admin</div>
      <div class="dashboard-links">
        <a href="{{ url_for('logs') }}">VPN Logs</a>
        <a href="{{ url_for('sessions') }}">Connected Users</a>
      </div>
      <!-- rest of dashboard cards... -->
      <!-- [KEEP THE REST OF YOUR DASHBOARD CARDS HERE, UNCHANGED] -->
      <!-- ... -->
      <form method="post" action="{{ url_for('logout') }}">
        <button class="save-btn" style="margin:26px auto 0 auto;width:100%;">Logout</button>
      </form>
    </div>
    </body>
    </html>
    ''', users=users, admin=admin, server_ip=server_ip, vpn_port=VPN_PORT, MAX_USERS=MAX_USERS, edit=edit)

@app.route('/logs')
def logs():
    if not session.get('admin'):
        return redirect(url_for('login'))
    logs = ''
    try:
        with open(LOG_FILE) as f:
            logs = f.read()[-10000:]  # Last 10,000 chars
    except Exception as e:
        logs = f"Error reading log: {e}"
    return render_template_string('''
    <html><head><title>OpenConnect Logs</title></head>
    <body style="background:#191f2a;color:#fafafa;">
    <h2>OpenConnect VPN Logs</h2>
    <a href="{{ url_for('dashboard') }}">← Back to Dashboard</a>
    <pre style="white-space:pre-wrap;background:#232e47;color:#90ee90;padding:15px;border-radius:12px;">{{ logs }}</pre>
    </body></html>
    ''', logs=logs)

@app.route('/sessions')
def sessions():
    if not session.get('admin'):
        return redirect(url_for('login'))
    try:
        sessions = subprocess.check_output(['occtl', 'show', 'users'], text=True)
    except Exception as e:
        sessions = f"Error running occtl: {e}"
    return render_template_string('''
    <html><head><title>OpenConnect Active Sessions</title></head>
    <body style="background:#191f2a;color:#fafafa;">
    <h2>Active VPN Sessions</h2>
    <a href="{{ url_for('dashboard') }}">← Back to Dashboard</a>
    <pre style="white-space:pre-wrap;background:#232e47;color:#50e3ff;padding:15px;border-radius:12px;">{{ sessions }}</pre>
    </body></html>
    ''', sessions=sessions)

# [Your existing add_user, del_user, edit_admin, logout routes remain unchanged]

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PANEL_PORT)
EOF

cat > /usr/local/bin/get_admin_info <<EOF
#!/bin/bash
cat $ADMIN_INFO
EOF
chmod +x /usr/local/bin/get_admin_info

cat > $PANEL_DIR/README.txt <<EOF
Access panel: http://<your-ip>:8080
Admin user: $ADMIN_USER
Admin pass: $ADMIN_PASS
Recover admin: sudo get_admin_info
EOF

cat > /etc/systemd/system/ocserv-admin.service <<EOF
[Unit]
Description=OpenConnect Admin Panel
After=network.target

[Service]
User=root
WorkingDirectory=$PANEL_DIR
ExecStart=$PANEL_DIR/venv/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Sudoers for occtl for panel
if ! grep -q "occtl show users" /etc/sudoers; then
  echo "root ALL=(ALL) NOPASSWD: /usr/bin/occtl show users" >> /etc/sudoers
fi

systemctl daemon-reload
systemctl enable --now ocserv
systemctl restart ocserv
systemctl enable --now ocserv-admin
systemctl restart ocserv-admin

IP=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')
echo "========================================="
echo "✅ OpenConnect VPN Server + Admin Panel Installed!"
echo "Admin Panel: http://$IP:$PANEL_PORT"
echo "VPN Connect to: $IP:$VPN_PORT"
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASS"
echo "Recover admin: sudo get_admin_info"
echo "========================================="

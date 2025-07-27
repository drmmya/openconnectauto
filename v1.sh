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
LOG_FILE="/var/log/syslog"  # change to /var/log/ocserv.log if needed

echo "[*] Installing dependencies..."
apt update
apt install -y python3 python3-pip python3-venv ocserv curl openssl pwgen iproute2 iptables-persistent socat

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

cat > $PANEL_DIR/app.py <<"EOF"
import os, json, subprocess, csv, socket
from flask import Flask, render_template_string, request, redirect, url_for, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
CSV_FILE = '/root/vpn_users.csv'
USER_FILE = '/etc/ocserv/ocpasswd'
MAX_USERS = 6000
PANEL_PORT = 8080
VPN_PORT = 4443
SOCKET_FILE = '/run/ocserv.socket'
LOG_FILE = '/var/log/syslog'  # Change if you have custom ocserv log

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

def get_active_sessions():
    try:
        # Use socat to send commands to ocserv socket
        cmd = ['socat', 'unix-connect:' + SOCKET_FILE, '-']
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = proc.communicate(input='show-sessions\nquit\n', timeout=3)
        sessions = []
        for line in out.splitlines():
            if line.startswith("session:"):
                parts = line.split()[1:]  # skip "session:"
                session_info = {}
                for p in parts:
                    if '=' in p:
                        k,v = p.split('=',1)
                        session_info[k] = v
                sessions.append(session_info)
        return sessions
    except Exception as e:
        return []

def get_vpn_logs(lines=50):
    try:
        with open(LOG_FILE, 'r') as f:
            return f.readlines()[-lines:]
    except:
        return []

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
        body {background: linear-gradient(120deg,#232e47 0%,#447cfb 100%); min-height:100vh; margin:0;}
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
        a {color:#3579f8; text-decoration:none; font-weight:700; margin-top:12px;}
        a:hover {text-decoration:underline;}
        @media(max-width:480px) {
            .main-wrap {padding:8px 2vw;}
            .card {padding:14px 4vw;}
        }
      </style>
    </head>
    <body>
    <div class="main-wrap">
      <div class="header">OpenConnect Admin</div>
      <!-- Card 1: Server Info -->
      <div class="card">
        <div class="row">
          <span class="ip-port">Server IP:</span>
          <span class="copy-value" id="serverip">{{server_ip}}</span>
          <button class="icon-btn" onclick="copyVal('serverip',this)" title="Copy IP"><span class="material-icons">content_copy</span></button>
        </div>
        <div class="row">
          <span class="ip-port">VPN Port:</span>
          <span class="copy-value" id="vpnport">{{vpn_port}}</span>
          <button class="icon-btn" onclick="copyVal('vpnport',this)" title="Copy Port"><span class="material-icons">content_copy</span></button>
        </div>
      </div>

      <a href="{{ url_for('sessions') }}" class="card" style="background:#e3f7ff; padding:16px; border-radius:16px; font-weight:700; text-align:center;">View Active Sessions</a>
      <a href="{{ url_for('logs') }}" class="card" style="background:#e3f7ff; padding:16px; border-radius:16px; font-weight:700; text-align:center;">View VPN Logs</a>

      <!-- Card 2: Add User -->
      <div class="card">
        <div style="font-weight:700; font-size:1.13em; margin-bottom:16px;">Add New User</div>
        <form method="post" action="{{ url_for('add_user') }}" style="display:flex; flex-direction:column; gap:12px;">
          <input class="adduser-input" name="username" placeholder="Username" required minlength=2 style="width:100%;"/>
          <input class="adduser-input" name="password" placeholder="Password" required minlength=3 style="width:100%;"/>
          <button type="submit" style="width:100%;background:linear-gradient(90deg,#3579f8,#43e3c1);color:#fff;border:0;border-radius:9px;font-size:1.12em;font-weight:700;padding:14px;margin-top:8px;transition:.15s;">
            Add User
          </button>
        </form>
      </div>
      <!-- Card 3: Users List -->
      <div class="card">
        <div style="font-weight:700;margin-bottom:10px;">All VPN Users</div>
        <table class="user-table">
          <tr><th>Username</th><th>Password</th><th>Delete</th></tr>
          {% for user in users %}
          <tr>
            <td>{{user.username}}</td>
            <td>{{user.password}}</td>
            <td>
              <form method="post" action="{{ url_for('del_user') }}" style="display:inline;">
                <input type="hidden" name="username" value="{{user.username}}">
                <button class="user-delete-btn" title="Delete"><span class="material-icons" style="font-size:1.09em;">delete</span></button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </table>
      </div>
      <!-- Card 4: Admin Info -->
      <div class="card">
        {% if not edit %}
        <div class="admin-row">
          <div>
            <div class="admin-label">Admin Username:</div>
            <div class="admin-value">{{admin.username}}</div>
            <div class="admin-label" style="margin-top:7px;">Admin Password:</div>
            <div class="admin-value">{{admin.password}}</div>
          </div>
          <form method="get" action="{{ url_for('dashboard') }}">
            <input type="hidden" name="edit" value="1">
            <button class="edit-btn" title="Edit"><span class="material-icons">edit</span></button>
          </form>
        </div>
        {% else %}
        <form method="post" action="{{ url_for('edit_admin') }}">
          <input name="username" placeholder="New Username" required minlength=2 value="{{admin.username}}" style="margin-bottom:9px;">
          <input name="password" placeholder="New Password" required minlength=3 value="{{admin.password}}">
          <button class="save-btn">Save</button>
        </form>
        {% endif %}
      </div>
      <!-- Card 5: Panel Details -->
      <div class="card">
        <div class="panel-info">
          <b>Max Users:</b> {{MAX_USERS}}<br>
          <b>Recover admin:</b>
          <div class="copy-cmd-box">
            <input class="copy-cmd-inp" id="cmdinp" value="sudo get_admin_info" readonly>
            <button class="copy-cmd-icon" onclick="copyVal('cmdinp',this)" title="Copy Command"><span class="material-icons">content_copy</span></button>
          </div>
        </div>
      </div>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for cat,msg in messages %}
          <div class="card" style="background:#e0f8ee; color:#06765e; font-weight:700; text-align:center;">{{msg}}</div>
        {% endfor %}
      {% endwith %}
      <form method="post" action="{{ url_for('logout') }}">
        <button class="save-btn" style="margin:26px auto 0 auto;width:100%;">Logout</button>
      </form>
    </div>
    <script>
      function copyVal(elemId, btn) {
        let val = document.getElementById(elemId).innerText || document.getElementById(elemId).value;
        navigator.clipboard.writeText(val);
        let tip = document.createElement('span');
        tip.textContent = 'Copied!';
        tip.style.position = 'absolute';
        tip.style.background = '#22c55e';
        tip.style.color = '#fff';
        tip.style.padding = '3px 12px';
        tip.style.borderRadius = '8px';
        tip.style.fontWeight = '700';
        tip.style.fontSize = '0.97em';
        tip.style.left = '50%';
        tip.style.top = '-28px';
        tip.style.transform = 'translateX(-50%)';
        tip.style.boxShadow = '0 1px 7px #0003';
        tip.style.zIndex = '1000';
        btn.style.position = 'relative';
        btn.appendChild(tip);
        setTimeout(() => { btn.removeChild(tip); }, 1000);
      }
    </script>
    </body>
    </html>
    ''', users=users, admin=admin, server_ip=server_ip, vpn_port=VPN_PORT, MAX_USERS=MAX_USERS, edit=edit)

@app.route('/sessions')
def sessions():
    if not session.get('admin'):
        return redirect(url_for('login'))
    sessions = get_active_sessions()
    return render_template_string('''
    <html><head>
      <title>Active VPN Sessions</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@700;900&display=swap" rel="stylesheet">
      <style>
        body {background:#f5f9ff; font-family: 'Inter', sans-serif; margin:20px;}
        table {width:100%; border-collapse: collapse; margin-bottom: 20px;}
        th, td {border: 1px solid #ccc; padding: 8px; text-align: left;}
        th {background:#e0eaff;}
        a {text-decoration:none; color:#3579f8; font-weight:700;}
        a:hover {text-decoration:underline;}
      </style>
    </head><body>
    <h2>Active VPN Sessions</h2>
    {% if sessions %}
    <table>
      <tr><th>Username</th><th>IP</th><th>Bytes In</th><th>Bytes Out</th><th>Start Time</th></tr>
      {% for s in sessions %}
      <tr>
        <td>{{ s.get('username', '') }}</td>
        <td>{{ s.get('ip', '') }}</td>
        <td>{{ s.get('bytes-in', '') }}</td>
        <td>{{ s.get('bytes-out', '') }}</td>
        <td>{{ s.get('start-time', '') }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p>No active sessions found.</p>
    {% endif %}
    <a href="{{ url_for('dashboard') }}">Back to Dashboard</a>
    </body></html>
    ''', sessions=sessions)

@app.route('/logs')
def logs():
    if not session.get('admin'):
        return redirect(url_for('login'))
    logs = get_vpn_logs()
    return render_template_string('''
    <html><head>
      <title>VPN Logs</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter&display=swap" rel="stylesheet">
      <style>
        body {background:#111; color:#eee; font-family: monospace; white-space: pre-wrap; margin:20px;}
        a {color:#3579f8; font-weight:700; text-decoration:none;}
        a:hover {text-decoration:underline;}
        .log-container {background:#222; padding:15px; border-radius:10px; max-height:70vh; overflow-y:auto; font-size:0.85em;}
      </style>
    </head><body>
      <h2>VPN Log (last 50 lines)</h2>
      <div class="log-container">{{ logs | join('') }}</div>
      <a href="{{ url_for('dashboard') }}">Back to Dashboard</a>
    </body></html>
    ''', logs=logs)

@app.route('/add_user', methods=['POST'])
def add_user():
    if not session.get('admin'):
        return redirect(url_for('login'))
    uname = request.form['username'].strip()
    pword = request.form['password'].strip()
    if not uname or not pword:
        flash('Username and password required.', 'error')
        return redirect(url_for('dashboard'))
    subprocess.call(f"echo '{pword}\n{pword}' | ocpasswd -g default {uname}", shell=True)
    exists = False
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE) as f:
            for row in csv.reader(f):
                if row and row[0] == uname:
                    exists = True
    if not exists:
        with open(CSV_FILE, 'a') as f:
            f.write(f"{uname},{pword}\n")
        flash('User added!', 'success')
        subprocess.call("systemctl restart ocserv", shell=True)
    else:
        flash('User already exists.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/del_user', methods=['POST'])
def del_user():
    if not session.get('admin'):
        return redirect(url_for('login'))
    uname = request.form['username']
    subprocess.call(f"ocpasswd -d {uname}", shell=True)
    rows = []
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE) as f:
            for row in csv.reader(f):
                if row and row[0] != uname and row[0] != "username":
                    rows.append(row)
        with open(CSV_FILE, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password"])
            writer.writerows(rows)
    flash(f'User {uname} deleted.', 'success')
    subprocess.call("systemctl restart ocserv", shell=True)
    return redirect(url_for('dashboard'))

@app.route('/edit_admin', methods=['POST'])
def edit_admin():
    if not session.get('admin'):
        return redirect(url_for('login'))
    new_user = request.form['username'].strip()
    new_pass = request.form['password'].strip()
    if new_user and new_pass:
        save_admin({'username': new_user, 'password': new_pass})
        flash('Admin info updated!', 'success')
    else:
        flash('Both fields required.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return redirect(url_for('login'))

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

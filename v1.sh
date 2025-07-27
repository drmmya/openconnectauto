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

echo "[*] Installing dependencies..."
apt update
apt install -y python3 python3-pip python3-venv ocserv curl openssl pwgen iproute2 iptables-persistent

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
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>OpenConnect Admin Login</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@700;900&display=swap" rel="stylesheet">
      <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
      <style>
        body {background: linear-gradient(135deg, #232e47 0%, #447cfb 100%); min-height:100vh; font-family: 'Inter',sans-serif;}
        .card {max-width:400px; margin:90px auto; border-radius:18px; box-shadow:0 8px 32px #0002;}
        .brand {font-size:2.2em; color:#2354be; font-weight:900;}
        @media(max-width:600px) {.card{padding:12px;}}
      </style>
    </head>
    <body>
      <div class="container py-5">
        <div class="card p-5">
          <div class="text-center brand mb-4"><span class="material-icons" style="font-size:2em;vertical-align:bottom;">vpn_key</span> OpenConnect</div>
          <form method="post">
            <div class="mb-3">
              <input class="form-control" name="username" placeholder="Username" required autofocus>
            </div>
            <div class="mb-3">
              <input class="form-control" name="password" type="password" placeholder="Password" required>
            </div>
            <button class="btn btn-primary w-100">Login</button>
            {% with messages = get_flashed_messages(with_categories=true) %}
            {% for cat,msg in messages %}{% if cat=='error' %}
            <div class="alert alert-danger mt-3" role="alert">{{msg}}</div>
            {% endif %}{% endfor %}{% endwith %}
          </form>
        </div>
      </div>
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
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenConnect Admin Dashboard</title>
    <!-- Bootstrap and fonts -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <style>
      body {font-family:'Inter',sans-serif;}
      .sidebar {
        min-height: 100vh;
        background: linear-gradient(135deg,#232e47,#447cfb);
        color: #fff;
      }
      .sidebar .nav-link.active, .sidebar .nav-link:hover {
        background: #fff2;
        color: #fff !important;
      }
      .avatar {width: 38px; height: 38px; border-radius: 50%; background:#fff4; display:inline-block;}
      .bg-card {background:#fff; border-radius:18px; box-shadow:0 2px 16px #0001;}
      .table th, .table td {vertical-align:middle;}
      @media (max-width: 768px) {
        .sidebar {min-height:auto; padding:8px;}
        .bg-card {margin-top: 10px;}
      }
    </style>
</head>
<body>
<div class="container-fluid">
  <div class="row flex-nowrap">
    <div class="col-auto col-md-3 col-xl-2 px-3 sidebar d-flex flex-column justify-content-between">
      <div>
        <h2 class="mt-4 mb-4 text-center"><span class="material-icons align-middle">admin_panel_settings</span> Admin</h2>
        <ul class="nav nav-pills flex-column mb-auto">
          <li class="nav-item">
            <a href="#" class="nav-link text-white active" aria-current="page">
              <span class="material-icons align-middle">dashboard</span> Dashboard
            </a>
          </li>
        </ul>
      </div>
      <div class="mb-3 text-center">
        <span class="avatar"><span class="material-icons" style="line-height:38px;">account_circle</span></span>
        <div class="mt-2 small">{{ admin.username }}</div>
      </div>
    </div>
    <div class="col py-3 px-4">
      <div class="d-flex justify-content-between align-items-center">
        <h3 class="fw-bold">Dashboard</h3>
        <form method="post" action="{{ url_for('logout') }}">
          <button class="btn btn-outline-secondary">Logout</button>
        </form>
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for cat,msg in messages %}
        <div class="alert alert-{{'danger' if cat=='error' else 'success'}} alert-dismissible fade show mt-3" role="alert">
          {{msg}}
          <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        {% endfor %}
      {% endwith %}

      <!-- Server Info -->
      <div class="row g-3 mt-2">
        <div class="col-md-4">
          <div class="bg-card p-4">
            <h5><span class="material-icons">computer</span> Server</h5>
            <div><b>IP:</b> <code>{{server_ip}}</code></div>
            <div><b>VPN Port:</b> <code>{{vpn_port}}</code></div>
            <div class="mt-2 small"><b>Max users:</b> {{MAX_USERS}}</div>
          </div>
        </div>
        <div class="col-md-8">
          <!-- Add User -->
          <div class="bg-card p-4 mb-3">
            <h6 class="mb-3"><span class="material-icons align-middle">person_add</span> Add User</h6>
            <form class="row g-2" method="post" action="{{ url_for('add_user') }}">
              <div class="col-auto flex-grow-1">
                <input class="form-control" name="username" placeholder="Username" required minlength=2 />
              </div>
              <div class="col-auto flex-grow-1">
                <input class="form-control" name="password" placeholder="Password" required minlength=3 />
              </div>
              <div class="col-auto">
                <button class="btn btn-primary px-4">Add</button>
              </div>
            </form>
          </div>
          <!-- User Table -->
          <div class="bg-card p-4">
            <h6><span class="material-icons align-middle">group</span> Users</h6>
            <div class="table-responsive">
              <table class="table table-striped align-middle mt-2">
                <thead><tr><th>Username</th><th>Password</th><th>Action</th></tr></thead>
                <tbody>
                  {% for user in users %}
                  <tr>
                    <td>{{ user.username }}</td>
                    <td>{{ user.password }}</td>
                    <td>
                      <form method="post" action="{{ url_for('del_user') }}">
                        <input type="hidden" name="username" value="{{user.username}}">
                        <button class="btn btn-danger btn-sm"><span class="material-icons" style="font-size:1em;">delete</span></button>
                      </form>
                    </td>
                  </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- Admin Info Card -->
      <div class="row g-3 mt-3">
        <div class="col-md-6">
          <div class="bg-card p-4">
            <h6><span class="material-icons align-middle">manage_accounts</span> Admin Info</h6>
            <form method="post" action="{{ url_for('edit_admin') }}">
              <div class="mb-2"><label class="form-label">Username</label>
                <input class="form-control" name="username" required minlength=2 value="{{admin.username}}">
              </div>
              <div class="mb-2"><label class="form-label">Password</label>
                <input class="form-control" name="password" required minlength=3 value="{{admin.password}}">
              </div>
              <button class="btn btn-outline-primary">Update Admin</button>
            </form>
          </div>
        </div>
        <div class="col-md-6">
          <div class="bg-card p-4">
            <h6><span class="material-icons align-middle">settings</span> Panel Info</h6>
            <div><b>Recover admin:</b> <code>sudo get_admin_info</code></div>
            <div class="mt-2"><b>Docs:</b> <a href="#" class="link-primary">Readme</a></div>
          </div>
        </div>
      </div>

      <footer class="mt-5 text-muted small text-center">OpenConnect Admin Panel &copy; 2025</footer>
    </div>
  </div>
</div>
</body>
</html>
''', users=users, admin=admin, server_ip=server_ip, vpn_port=VPN_PORT, MAX_USERS=MAX_USERS)

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

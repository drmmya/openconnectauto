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
    echo "username,password,created" > "$CSV_FILE"
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
import os, json, subprocess, csv, socket, datetime
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
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("username"):
                    users.append({
                        'username': row["username"],
                        'password': row.get("password", ""),
                        'created': row.get("created", "Unknown")
                    })
    return users

def add_user_csv(username, password):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    users = get_users()
    exists = any(u["username"] == username for u in users)
    if not exists:
        with open(CSV_FILE, 'a') as f:
            f.write(f"{username},{password},{now}\n")
        return True
    return False

def del_user_csv(username):
    users = get_users()
    with open(CSV_FILE, 'w') as f:
        f.write("username,password,created\n")
        for user in users:
            if user["username"] != username:
                f.write(f"{user['username']},{user['password']},{user['created']}\n")

# ---------- TEMPLATES ----------
TEMPLATE_BASE = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ title or 'Admin Panel' }}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&display=swap" rel="stylesheet">
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <style>
    body {font-family:'Inter',sans-serif;}
    .avatar {width: 38px; height: 38px; border-radius: 50%; background:#fff4; display:inline-block;}
    .sidebar-gradient {background: linear-gradient(135deg,#232e47,#447cfb); color:#fff;}
    .bg-card {background:#fff; border-radius:18px; box-shadow:0 2px 16px #0001;}
    .table th, .table td {vertical-align:middle;}
    @media (min-width: 992px) {
      #sidebarMenu {position:fixed; top:0; left:0; height:100vh; width:230px; z-index:1045;}
      .main-content {margin-left:230px;}
    }
    @media (max-width: 991.98px) {
      #sidebarMenu {width: 70vw; min-width: 180px;}
      .main-content {margin-left:0;}
    }
  </style>
</head>
<body>
<div class="offcanvas-lg offcanvas-start sidebar-gradient d-flex flex-column" tabindex="-1" id="sidebarMenu" aria-labelledby="sidebarMenuLabel">
  <div class="offcanvas-header d-lg-none">
    <h5 class="offcanvas-title" id="sidebarMenuLabel">OpenConnect Admin</h5>
    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="offcanvas" data-bs-target="#sidebarMenu"></button>
  </div>
  <div class="offcanvas-body px-3 d-flex flex-column flex-grow-1">
    <div>
      <h2 class="mt-4 mb-4 text-center d-none d-lg-block"><span class="material-icons align-middle">admin_panel_settings</span> Admin</h2>
      <ul class="nav nav-pills flex-column mb-auto">
        <li class="nav-item">
          <a href="{{ url_for('dashboard') }}" class="nav-link text-white {% if page=='dashboard' %}active bg-primary{% endif %}">
            <span class="material-icons align-middle">dns</span> Dashboard
          </a>
        </li>
        <li class="nav-item">
          <a href="{{ url_for('users') }}" class="nav-link text-white {% if page=='users' %}active bg-primary{% endif %}">
            <span class="material-icons align-middle">group</span> Users
          </a>
        </li>
        <li class="nav-item">
          <a href="{{ url_for('admin_info') }}" class="nav-link text-white {% if page=='admin' %}active bg-primary{% endif %}">
            <span class="material-icons align-middle">manage_accounts</span> Admin Info
          </a>
        </li>
        <li class="nav-item">
          <a href="{{ url_for('panel_info') }}" class="nav-link text-white {% if page=='panel' %}active bg-primary{% endif %}">
            <span class="material-icons align-middle">settings</span> Panel Info
          </a>
        </li>
      </ul>
    </div>
    <div class="mb-3 text-center mt-auto">
      <span class="avatar"><span class="material-icons" style="line-height:38px;">account_circle</span></span>
      <div class="mt-2 small">{{ admin.username }}</div>
    </div>
  </div>
</div>
<div class="main-content">
  <nav class="navbar navbar-light bg-white px-3 border-bottom">
    <div class="d-flex align-items-center">
      <button class="btn d-lg-none me-2" type="button" data-bs-toggle="offcanvas" data-bs-target="#sidebarMenu" aria-controls="sidebarMenu">
        <span class="material-icons">menu</span>
      </button>
      <span class="navbar-brand mb-0 h4">{{ navtitle or 'Dashboard' }}</span>
    </div>
    <form class="d-inline" method="post" action="{{ url_for('logout') }}">
      <button class="btn btn-outline-secondary btn-sm">Logout</button>
    </form>
  </nav>
  <div class="container-fluid py-4 px-3 px-lg-5">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for cat,msg in messages %}
      <div class="alert alert-{{'danger' if cat=='error' else 'success'}} alert-dismissible fade show mt-3" role="alert">
        {{msg}}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
      </div>
      {% endfor %}
    {% endwith %}
    {{ content | safe }}
    <footer class="mt-5 text-muted small text-center">OpenConnect Admin Panel &copy; 2025</footer>
  </div>
</div>
</body>
</html>
'''

TEMPLATE_LOGIN = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
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
'''

# ---------- ROUTES ----------
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
    return render_template_string(TEMPLATE_LOGIN)

def render_page(content, page, navtitle=None, title=None):
    admin = load_admin()
    return render_template_string(
        TEMPLATE_BASE,
        admin=admin, content=content, page=page, navtitle=navtitle, title=title
    )

@app.route('/dashboard')
def dashboard():
    if not session.get('admin'):
        return redirect(url_for('login'))
    server_ip = get_ip()
    content = f'''
    <div class="row g-3">
      <div class="col-lg-5 col-md-7">
        <div class="bg-card p-4">
          <h5><span class="material-icons align-middle">computer</span> Server</h5>
          <div><b>IP:</b> <code style="color:#ec4899">{server_ip}</code></div>
          <div><b>VPN Port:</b> <code style="color:#ec4899">{VPN_PORT}</code></div>
          <div class="mt-2 small"><b>Max users:</b> {MAX_USERS}</div>
        </div>
      </div>
    </div>
    '''
    return render_page(content, page="dashboard", navtitle="Dashboard", title="Dashboard")

@app.route('/users', methods=['GET', 'POST'])
def users():
    if not session.get('admin'):
        return redirect(url_for('login'))
    users = get_users()
    content = '''
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h5><span class="material-icons align-middle">group</span> Users</h5>
      <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addUserModal"><span class="material-icons align-middle">person_add</span> Add User</button>
    </div>
    <div class="table-responsive bg-card p-3">
      <table class="table align-middle">
        <thead><tr>
          <th>Username</th>
          <th>Password</th>
          <th>Created</th>
          <th>Action</th>
        </tr></thead>
        <tbody>
    '''
    for user in users:
        content += f'''
        <tr>
          <td>{user['username']}</td>
          <td>{user['password']}</td>
          <td>{user['created']}</td>
          <td>
            <form method="post" action="{url_for('del_user')}" style="display:inline;">
              <input type="hidden" name="username" value="{user['username']}">
              <button class="btn btn-danger btn-sm"><span class="material-icons" style="font-size:1em;">delete</span></button>
            </form>
          </td>
        </tr>
        '''
    content += '''
        </tbody>
      </table>
    </div>
    <!-- Add User Modal -->
    <div class="modal fade" id="addUserModal" tabindex="-1" aria-labelledby="addUserModalLabel" aria-hidden="true">
      <div class="modal-dialog modal-dialog-centered">
        <form method="post" class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="addUserModalLabel">Add User</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <input class="form-control mb-3" name="username" placeholder="Username" required minlength=2>
            <input class="form-control" name="password" placeholder="Password" required minlength=3>
          </div>
          <div class="modal-footer">
            <button class="btn btn-primary" type="submit">Add</button>
          </div>
        </form>
      </div>
    </div>
    '''
    if request.method == 'POST':
        uname = request.form['username'].strip()
        pword = request.form['password'].strip()
        if not uname or not pword:
            flash('Username and password required.', 'error')
            return redirect(url_for('users'))
        subprocess.call(f"echo '{pword}\n{pword}' | ocpasswd -g default {uname}", shell=True)
        if add_user_csv(uname, pword):
            flash('User added!', 'success')
            subprocess.call("systemctl restart ocserv", shell=True)
        else:
            flash('User already exists.', 'error')
        return redirect(url_for('users'))
    return render_page(content, page="users", navtitle="Users", title="Users")

@app.route('/del_user', methods=['POST'])
def del_user():
    if not session.get('admin'):
        return redirect(url_for('login'))
    uname = request.form['username']
    subprocess.call(f"ocpasswd -d {uname}", shell=True)
    del_user_csv(uname)
    flash(f'User {uname} deleted.', 'success')
    subprocess.call("systemctl restart ocserv", shell=True)
    return redirect(url_for('users'))

@app.route('/admin', methods=['GET', 'POST'])
def admin_info():
    if not session.get('admin'):
        return redirect(url_for('login'))
    admin = load_admin()
    content = f'''
    <div class="bg-card p-4" style="max-width:430px;">
      <h6><span class="material-icons align-middle">manage_accounts</span> Admin Info</h6>
      <form method="post" class="mt-3">
        <div class="mb-2"><label class="form-label">Username</label>
          <input class="form-control" name="username" required minlength=2 value="{admin['username']}">
        </div>
        <div class="mb-2"><label class="form-label">Password</label>
          <input class="form-control" name="password" required minlength=3 value="{admin['password']}">
        </div>
        <button class="btn btn-outline-primary mt-2">Update Admin</button>
      </form>
    </div>
    '''
    if request.method == 'POST':
        new_user = request.form['username'].strip()
        new_pass = request.form['password'].strip()
        if new_user and new_pass:
            save_admin({'username': new_user, 'password': new_pass})
            flash('Admin info updated!', 'success')
        else:
            flash('Both fields required.', 'error')
        return redirect(url_for('admin_info'))
    return render_page(content, page="admin", navtitle="Admin Info", title="Admin Info")

@app.route('/panel')
def panel_info():
    if not session.get('admin'):
        return redirect(url_for('login'))
    content = '''
    <div class="bg-card p-4" style="max-width:430px;">
      <h6><span class="material-icons align-middle">settings</span> Panel Info</h6>
      <div><b>Recover admin:</b> <code style="color:#ec4899">sudo get_admin_info</code></div>
      <div class="mt-2"><b>Docs:</b> <a href="#" class="link-primary">Readme</a></div>
      <div class="mt-2 small text-muted">OpenConnect Admin Panel by <b>YOU!</b></div>
    </div>
    '''
    return render_page(content, page="panel", navtitle="Panel Info", title="Panel Info")

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
echo "✅ OpenConnect VPN Server + Pro Admin Panel Installed!"
echo "Admin Panel: http://$IP:$PANEL_PORT"
echo "VPN Connect to: $IP:$VPN_PORT"
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASS"
echo "Recover admin: sudo get_admin_info"
echo "========================================="

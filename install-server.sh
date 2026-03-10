#!/bin/bash
echo "Starting Peta Server..."

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

if [ ! -f /etc/os-release ]; then
  echo "/etc/os-release missing, cannot determine OS"
  exit 1
fi

. /etc/os-release

case "$ID" in
  debian|ubuntu|pve|proxmox)
    UPDATE_CMD="apt-get update"
    INSTALL_CMD="apt-get install -y git curl nano mariadb-server openssl"
    ;;
  arch)
    UPDATE_CMD="pacman -Sy"
    INSTALL_CMD="pacman -S --needed --noconfirm git curl nano mariadb openssl"
    ;;
  alpine)
    UPDATE_CMD="apk update"
    INSTALL_CMD="apk add --no-cache git curl nano mariadb mariadb-client openssl"
    ;;
  *)
    echo "Unsupported OS detected: $ID"
    exit 1
    ;;
esac

echo "Installing dependencies..."
$UPDATE_CMD
$INSTALL_CMD

echo "Configuring MariaDB..."
if [ "$ID" = "alpine" ]; then
    mysql_install_db --user=mysql --datadir=/var/lib/mysql
    rc-service mariadb start
elif [ "$ID" = "arch" ]; then
    if [ ! -d "/var/lib/mysql/mysql" ]; then
        mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
    fi
    systemctl enable --now mariadb
else
    systemctl enable --now mariadb
fi

DB_NAME="petastorage"
DB_USER="petauser"
DB_PASS=$(openssl rand -base64 24)

mysql -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME};"
mysql -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
mysql -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

if ! command -v /root/.local/bin/uv &>/dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi
source /root/.local/bin/env

cd /
if [ ! -d "petaserver" ]; then
    git clone https://github.com/lspm-pkg/petaserver.git
fi

cd /petaserver
cp -n example-env .env

S_SECRET=$(openssl rand -hex 32)
E_KEY=$(openssl rand -hex 32)
DB_URL="mysql://${DB_USER}:${DB_PASS}@127.0.0.1:3306/${DB_NAME}"

sed -i "s|^SESSION_SECRET=.*|SESSION_SECRET=${S_SECRET}|" .env
sed -i "s|^ENCRYPTION_KEY=.*|ENCRYPTION_KEY=${E_KEY}|" .env
sed -i "s|^MARIADB_URL=.*|MARIADB_URL=${DB_URL}|" .env

echo "Please edit /petaserver/config.toml to set your Channel ID & /petaserver/.env to set your Discord Bot Token."
read -p "Press Enter to open nano..."
nano /petaserver/.env /petaserver/config.toml

if command -v systemctl &>/dev/null; then
    INIT_SYSTEM="systemd"
elif command -v rc-status &>/dev/null || [ -f /sbin/openrc ]; then
    INIT_SYSTEM="openrc"
else
    INIT_SYSTEM="sysv"
fi

case "$INIT_SYSTEM" in
    systemd)
        cat <<EOF >/etc/systemd/system/petaserver.service
[Unit]
Description=Peta Server
After=network.target mariadb.service

[Service]
ExecStart=/root/.local/bin/uv run -m petabytestorage
WorkingDirectory=/petaserver
User=root
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now petaserver.service
        ;;
    openrc)
        cat <<'EOF' >/etc/init.d/petaserver
#!/sbin/openrc-run
description="Peta Server"
depend() {
    need net mariadb
}
command="/root/.local/bin/uv"
command_args="run -m petabytestorage"
directory="/petaserver"
user="root"
background="yes"
pidfile="/run/petaserver.pid"
EOF
        chmod +x /etc/init.d/petaserver
        rc-update add petaserver default
        rc-service petaserver start
        ;;
    sysv)
        cat <<'EOF' >/etc/init.d/petaserver
#!/bin/sh
### BEGIN INIT INFO
# Provides:          petaserver
# Required-Start:    $network $mysql
# Required-Stop:     $network $mysql
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INIT INFO
DAEMON=/root/.local/bin/uv
DAEMON_ARGS="run -m petabytestorage"
WORKDIR=/petaserver
PIDFILE=/var/run/petaserver.pid

case "$1" in
    start)
        start-stop-daemon --start --background --make-pidfile --pidfile $PIDFILE --chdir $WORKDIR --exec $DAEMON -- $DAEMON_ARGS
        ;;
    stop)
        start-stop-daemon --stop --pidfile $PIDFILE
        ;;
    *) echo "Usage: $0 {start|stop}" ;;
esac
EOF
        chmod +x /etc/init.d/petaserver
        update-rc.d petaserver defaults
        service petaserver start
        ;;
esac

echo "Deployment finished. 12x Uvicorn workers are now live."

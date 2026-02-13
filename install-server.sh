#!/bin/bash
echo "Starting Peta Server setup..."

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
    INSTALL_CMD="apt-get install -y git curl nano"
    ;;
  arch)
    UPDATE_CMD="pacman -Sy"
    INSTALL_CMD="pacman -S --needed --noconfirm git curl nano"
    ;;
  alpine)
    UPDATE_CMD="apk update"
    INSTALL_CMD="apk add --no-cache git curl nano"
    ;;
  *)
    echo "Unsupported OS detected: $ID"
    echo "This installer supports Debian, Ubuntu, Proxmox, Arch, or Alpine"
    exit 1
    ;;
esac
if command -v systemctl &>/dev/null; then
    INIT_SYSTEM="systemd"
elif command -v rc-status &>/dev/null || [ -f /sbin/openrc ]; then
    INIT_SYSTEM="openrc"
elif command -v service &>/dev/null; then
    INIT_SYSTEM="sysv"
else
    INIT_SYSTEM="unknown"
fi

echo "Detected init system: $INIT_SYSTEM"
if ! command -v /root/.local/bin/uv &>/dev/null; then
    echo "uv not found, installing via Astral..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi

source /root/.local/bin/env

echo "Updating package database..."
$UPDATE_CMD
echo "Installing dependencies..."
$INSTALL_CMD

cd /
if [ ! -d "petaserver" ]; then
    git clone https://github.com/lspm-pkg/petaserver.git
else
    echo "petaserver already exists, skipping clone"
fi

cd /petaserver
cp -n config.example.toml config.toml
cp -n example-env .env
echo "Please edit /petaserver/config.toml and /petaserver/.env with your settings."
echo "Press Enter to continue..."
read
nano /petaserver/config.toml /petaserver/.env
sleep 1

case "$INIT_SYSTEM" in
    systemd)
        cat <<EOF >/etc/systemd/system/petaserver.service
[Unit]
Description=Peta Server

[Service]
ExecStart=/root/.local/bin/uv run -m petabytestorage
WorkingDirectory=/petaserver
User=root

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

command="/root/.local/bin/uv"
command_args="run -m petabytestorage"
pidfile="/run/petaserver.pid"
directory="/petaserver"
user="root"
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
# Required-Start:    $remote_fs $network
# Required-Stop:     $remote_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Peta Server
### END INIT INFO

DAEMON=/root/.local/bin/uv
DAEMON_ARGS="run -m petabytestorage"
NAME=petaserver
PIDFILE=/var/run/$NAME.pid
WORKDIR=/petaserver

start() {
    echo "Starting $NAME..."
    start-stop-daemon --start --background --make-pidfile --pidfile $PIDFILE --chdir $WORKDIR --exec $DAEMON -- $DAEMON_ARGS
}

stop() {
    echo "Stopping $NAME..."
    start-stop-daemon --stop --pidfile $PIDFILE
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    status)
        if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
            echo "$NAME is running"
        else
            echo "$NAME is not running"
        fi
        ;;
    *) echo "Usage: $0 {start|stop|restart|status}" ;;
esac
exit 0
EOF
        chmod +x /etc/init.d/petaserver
        update-rc.d petaserver defaults
        service petaserver start
        ;;
    *)
        echo "Unknown init system, cannot configure service automatically."
        ;;
esac

echo "Peta Server setup complete."
echo "Check service status with:"
if [ "$INIT_SYSTEM" = "systemd" ]; then
    echo "systemctl status petaserver.service"
else
    echo "service petaserver status"
fi

echo
echo "You can now start configuring the client using install-client.sh included in the repo."

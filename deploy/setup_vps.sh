#!/usr/bin/env bash
# kkj-watch VPS初期構築(Ubuntu 22.04/24.04想定)
# 使い方: リポジトリを /opt/kkj-watch に配置してから  sudo bash deploy/setup_vps.sh
set -euo pipefail

APP_DIR=/opt/kkj-watch
id -u kkj &>/dev/null || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin kkj
mkdir -p "$APP_DIR/data"
chown -R kkj:kkj "$APP_DIR"

# ANTHROPIC_API_KEY は /etc/kkj-watch.env に置く(例: ANTHROPIC_API_KEY=sk-ant-...)
touch /etc/kkj-watch.env
chmod 600 /etc/kkj-watch.env

install -m 644 "$APP_DIR/deploy/kkj-api.service" /etc/systemd/system/
install -m 644 "$APP_DIR/deploy/kkj-poll.service" /etc/systemd/system/
install -m 644 "$APP_DIR/deploy/kkj-poll.timer" /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now kkj-api.service kkj-poll.timer
systemctl status kkj-api --no-pager || true
echo "OK: API=:8787 (リバースプロキシ例は deploy/Caddyfile), 巡回=3時間おき"

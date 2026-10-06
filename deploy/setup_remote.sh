#!/usr/bin/env bash
# 在 ECS 上以 root 执行。前置条件：
#   1) 本机文件已 rsync 到 /opt/agentbi（含 deploy/、web/、batch.json）
#   2) 阿里云安全组已放行 TCP 80 / 443（控制台操作，脚本改不了）
#   3) agentbi.tech 与 www.agentbi.tech 的 DNS 已指向本机
set -euo pipefail

APP=/opt/agentbi
export DEBIAN_FRONTEND=noninteractive

# 1) 依赖：检测器需要 requests
# 注意：本机已有失效的第三方 PPA（jarun），apt-get update 会非 0 退出，不能让它中断部署
apt-get update -qq || echo "  (apt update 部分失败，忽略：已有失效的外部源)"
apt-get install -y -qq python3 python3-requests curl gnupg

# 2) Caddy（官方源，自动签证书）
if ! command -v caddy >/dev/null 2>&1; then
    # 优先官方源（最新版）；国内机拉不动 cloudsmith 时退回 Ubuntu universe 的 caddy 2.6
    if curl -1sLf --max-time 20 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null \
      && curl -1sLf --max-time 20 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null; then
        apt-get update -qq && apt-get install -y -qq caddy || true
    fi
    command -v caddy >/dev/null 2>&1 || apt-get install -y -qq caddy
fi
caddy version

# 3) 让出 80/443：现在被 nginx 默认站占着
systemctl stop nginx 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true

# 4) 运行用户（非 root）
id -u agentbi >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin agentbi
chown -R agentbi:agentbi "$APP"

# 5) 服务与反代配置
install -m 644 "$APP/deploy/agentbi.service" /etc/systemd/system/agentbi.service
install -m 644 "$APP/deploy/Caddyfile" /etc/caddy/Caddyfile
mkdir -p /var/log/caddy && chown caddy:caddy /var/log/caddy

# 6) 本机防火墙（若启用）；安全组仍需控制台放行
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 80/tcp
    ufw allow 443/tcp
fi

systemctl daemon-reload
systemctl enable --now agentbi
systemctl restart caddy

sleep 3
systemctl --no-pager status agentbi caddy | sed -n '1,30p'
echo
echo "=== 本机自检 ==="
curl -s -o /dev/null -w "  /            %{http_code}\n" http://127.0.0.1:8000/
curl -s -o /dev/null -w "  /about       %{http_code}\n" http://127.0.0.1:8000/about
curl -s -o /dev/null -w "  /leaderboard %{http_code}\n" http://127.0.0.1:8000/leaderboard

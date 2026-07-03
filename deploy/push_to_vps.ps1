# One-command deploy from Windows
# Usage:  powershell -File deploy\push_to_vps.ps1 -Ip <SERVER_IP> [-ApiKey sk-ant-...]
param(
    [Parameter(Mandatory=$true)][string]$Ip,
    [string]$ApiKey = $env:ANTHROPIC_API_KEY,
    [string]$SshKey = "$env:USERPROFILE\.ssh\id_ed25519"
)
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent

Write-Host "[1/5] transfer code (excluding data/ and DB)"
ssh -i $SshKey -o StrictHostKeyChecking=accept-new root@$Ip "mkdir -p /opt/kkj-watch"
scp -i $SshKey -r "$repo\kkj" "$repo\deploy" "$repo\README.md" "$repo\server.json" root@${Ip}:/opt/kkj-watch/

Write-Host "[2/5] run setup"
ssh -i $SshKey root@$Ip "sed -i 's/\r$//' /opt/kkj-watch/deploy/*.sh /opt/kkj-watch/deploy/*.service /opt/kkj-watch/deploy/*.timer; bash /opt/kkj-watch/deploy/setup_vps.sh"

if ($ApiKey) {
    Write-Host "[3/5] set ANTHROPIC_API_KEY (enables extraction)"
    ssh -i $SshKey root@$Ip "echo ANTHROPIC_API_KEY=$ApiKey > /etc/kkj-watch.env; chmod 600 /etc/kkj-watch.env; systemctl restart kkj-api"
} else {
    Write-Host "[3/5] no API key given: extraction stays disabled (set later in /etc/kkj-watch.env)"
}

Write-Host "[4/5] install Caddy reverse proxy (port 80 until a domain is set)"
ssh -i $SshKey root@$Ip "apt-get update -qq && apt-get install -y -qq caddy > /dev/null && printf ':80 {\n    reverse_proxy 127.0.0.1:8787\n}\n' > /etc/caddy/Caddyfile && systemctl restart caddy"

Write-Host "[5/5] first poll + health check"
ssh -i $SshKey root@$Ip "systemctl start kkj-poll.service; curl -s http://127.0.0.1:8787/stats"
Write-Host "`nDONE. Public URL: http://${Ip}/  (after a domain: edit /etc/caddy/Caddyfile for auto-HTTPS)"

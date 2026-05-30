# Single-Host Dev Deployment

## Prerequisites
- Python 3.11+
- PostgreSQL 15+
- pip packages: `pip install -r requirements.txt`

## 1. Database Setup
```
sudo systemctl start postgresql
sudo -u postgres createdb watercat
sudo -u postgres psql -c "CREATE USER watercat WITH PASSWORD 'watercat';"
sudo -u postgres psql -c "GRANT ALL ON DATABASE watercat TO watercat;"
```

## 2. Environment
```bash
export DATABASE_URL=postgresql://watercat:watercat@localhost:5432/watercat
export HTTP_DEV_INSECURE_TLS=true
```

## 3. Start Services
```bash
# DNS (port 53 needs root or capability)
sudo HTTP_ROLE=dns python3 -m dns.server
# App Backend A (port 8081)
HTTP_ROLE=app HTTP_PORT=8081 HTTP_NODE_ID=app-a python3 -m server.main &
# App Backend B (port 8082)
HTTP_ROLE=app HTTP_PORT=8082 HTTP_NODE_ID=app-b python3 -m server.main &
# Gateway (HTTPS on 8443, proxies to app backends)
HTTP_ROLE=gateway HTTP_BACKENDS=localhost:8081,localhost:8082 python3 -m server.main &
# VPN Tunnel
python3 -m vpn.vpn_server &
# Browser
python3 -m browser &
```

## 4. All-in-One
```bash
python3 start.py
```

## Verification
- DNS: `dig @localhost -p 53 myweb.local`
- Gateway: `curl -k https://localhost:8443/health`
- Status: `curl -k https://localhost:8443/status`
- App: `curl http://localhost:8081/health`

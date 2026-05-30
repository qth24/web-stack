# Multi-Host Production Deployment

## Architecture
| Host | Role                      | Ports           |
|------|---------------------------|-----------------|
| 1    | DNS + Gateway + VPN       | 53, 443, 9443   |
| 2    | App Backend A             | 8081            |
| 3    | App Backend B             | 8082            |
| 4    | PostgreSQL                | 5432            |

## Host 1: DNS + Gateway + VPN
```
sudo systemctl enable --now dns gateway vpn
```

## Host 2: App Backend A
```
sudo systemctl enable --now app@1
```

## Host 3: App Backend B
```
sudo systemctl enable --now app@2
```

## Host 4: PostgreSQL
```
sudo apt install postgresql
sudo -u postgres createdb watercat
sudo -u postgres psql -c "CREATE USER watercat WITH PASSWORD 'watercat';"
sudo -u postgres psql -c "GRANT ALL ON DATABASE watercat TO watercat;"
# Edit pg_hba.conf to allow remote connections from app hosts
sudo systemctl restart postgresql
```

## TLS Certificates
```
sudo certbot certonly --standalone -d example.com
# Certificates will be at:
# /etc/letsencrypt/live/example.com/fullchain.pem
# /etc/letsencrypt/live/example.com/privkey.pem
```

## Verification
```
curl https://gateway.example.com/status
```

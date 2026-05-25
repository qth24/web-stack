# VPN Server

Mini VPN is an application-layer tunnel for the custom browser. It is not a kernel-level VPN: it does not create a TUN/TAP interface or change the operating system routing table.

The browser sends a raw HTTP request to the VPN server in a JSON-line frame. The VPN server opens the upstream TCP/TLS connection, forwards the request, reads the raw HTTP response, and returns it to the browser.

## Run

From the repo root:

```bash
python3 vpn/vpn_server.py
```

Default local address:

```text
0.0.0.0:9443
```

## Protocol

Request frame:

```json
{"version":"v1","id":"req-1","op":"connect","token":"demo-token","target_host":"127.0.0.1","target_port":8000,"use_tls":false,"server_name":"myweb.local","payload":"base64 raw HTTP request"}
```

Response frame:

```json
{"version":"v1","id":"req-1","status":"OK","via":"mini-vpn","payload":"base64 raw HTTP response"}
```

## Config

```env
VPN_BIND_HOST=0.0.0.0
VPN_PORT=9443
VPN_TOKEN=demo-token
VPN_CONNECT_TIMEOUT=5.0
VPN_READ_TIMEOUT=10.0
VPN_BUFFER_SIZE=4096
VPN_MAX_FRAME_BYTES=2097152
VPN_ALLOW_PRIVATE_TARGETS=true
```

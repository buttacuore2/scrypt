#!/bin/bash

# CONFIGURE THIS:
YOUR_DOMAIN="web.andotv.ggff.net"

# Auto Install Script: OpenVPN + WebSocket + Nginx + SSL
set -e

if [ "$EUID" -ne 0 ]; then
  echo "❌ Run as root"
  exit 1
fi

echo "Updating system..."
apt update && apt upgrade -y

echo "Installing dependencies..."
apt install openvpn easy-rsa nginx python3 python3-pip certbot python3-certbot-nginx ufw curl -y
pip3 install websockify

echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

echo "Setting up EasyRSA PKI..."
make-cadir ~/openvpn-ca
cd ~/openvpn-ca
./easyrsa init-pki
echo | ./easyrsa build-ca nopass
echo | ./easyrsa gen-req server nopass
echo -e "yes\n" | ./easyrsa sign-req server server
./easyrsa gen-dh
openvpn --genkey --secret ta.key

cp pki/ca.crt pki/private/server.key pki/issued/server.crt ta.key pki/dh.pem /etc/openvpn

echo "Creating OpenVPN server.conf..."
cat > /etc/openvpn/server.conf <<EOF
port 1194
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA256
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log-append /var/log/openvpn.log
verb 3
explicit-exit-notify 1
EOF

echo "Configuring UFW..."
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "Starting OpenVPN..."
systemctl enable openvpn@server
systemctl start openvpn@server

echo "Setting up Certbot SSL for $YOUR_DOMAIN..."
nginx -t && systemctl restart nginx
certbot --nginx -d $YOUR_DOMAIN --non-interactive --agree-tos -m admin@$YOUR_DOMAIN

echo "Configuring Nginx reverse proxy for WebSocket..."
cat > /etc/nginx/sites-available/openvpn_ws <<EOF
server {
    listen 80;
    server_name $YOUR_DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $YOUR_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$YOUR_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$YOUR_DOMAIN/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:2082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

ln -s /etc/nginx/sites-available/openvpn_ws /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

echo "Creating systemd service for Websockify on port 2082..."
cat > /etc/systemd/system/ws-openvpn.service <<EOF
[Unit]
Description=WebSocket to OpenVPN
After=network.target

[Service]
ExecStart=/usr/local/bin/websockify --web=/usr/share/novnc 2082 localhost:1194
Restart=always
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ws-openvpn
systemctl start ws-openvpn

echo ""
echo "✅ Installation complete!"
echo "🌐 WebSocket available over:"
echo "   - ws://$YOUR_DOMAIN (redirects to WSS)"
echo "   - wss://$YOUR_DOMAIN (secure)"
echo "📡 OpenVPN TCP is tunneled over WebSocket on port 443."
echo "📁 You still need to generate client .ovpn file with proxy payload or injector."

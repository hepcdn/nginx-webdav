#!/bin/bash

# Set defaults
SERVER_NAME=${SERVER_NAME:-localhost}
PORT=${PORT:-8080}
USE_SSL=${USE_SSL:-false}
SSL_HOST_CERT=${SSL_HOST_CERT:-/etc/grid-security/hostcert.pem}
SSL_HOST_KEY=${SSL_HOST_KEY:-/etc/grid-security/hostkey.pem}
SSL_CERT_DIR=${SSL_CERT_DIR:-/etc/grid-security/certificates}
IPV4ONLY=${IPV4ONLY:-false}
DEBUG=${DEBUG:-false}

if [ "$USE_SSL" == "true" ]; then
  # If $SERVER_ADDRESS is not set, autogenerate it with a guess
  if [ -z "$SERVER_ADDRESS" ]; then
    export SERVER_ADDRESS="https://${SERVER_NAME}:$PORT/"
  fi
  cat <<EOF > /etc/nginx/conf.d/site.conf
server {
    listen              $PORT ssl;
    listen              [::]:$PORT ssl;
    server_name         $SERVER_NAME;
    ssl_certificate     $SSL_HOST_CERT;
    ssl_certificate_key $SSL_HOST_KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    include /etc/nginx/conf.d/include/locations.conf;
}
EOF
else
  # If $SERVER_ADDRESS is not set, autogenerate it with a guess
  if [ -z "$SERVER_ADDRESS" ]; then
    export SERVER_ADDRESS="http://${SERVER_NAME}:$PORT/"
  fi
  cat <<EOF > /etc/nginx/conf.d/site.conf
server {
    listen              $PORT;
    listen              [::]:$PORT;
    server_name         $SERVER_NAME;

    include /etc/nginx/conf.d/include/locations.conf;
}
EOF
fi

if [ "$DEBUG" == "true" ]; then
  cat <<EOF >> /etc/nginx/conf.d/site.conf
error_log stderr notice;

server {
    lua_code_cache off;
}
EOF
  echo "Debug mode enabled"
else
  cat <<EOF >> /etc/nginx/conf.d/site.conf
error_log stderr warn;
EOF
fi

export SSL_CERT_DIR=$SSL_CERT_DIR

# Start a dns server (just for respecting /etc/hosts)
# use a non-standard port in case we are not running as root
# if we are ipv4 only, filter AAAA records
if [ "$IPV4ONLY" == "true" ]; then
  dnsmasq -kd -p 5353 --filter-AAAA &
else
  dnsmasq -kd -p 5353 &
fi

# Run target executable (probably nginx)
exec "$@"

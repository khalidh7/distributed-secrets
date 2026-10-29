#!/bin/sh
set -eu

output=${1:-dev/certs}
mkdir -p "$output"

openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
  -subj '/CN=distributed-secrets development CA' \
  -keyout "$output/ca-key.pem" -out "$output/ca.pem"

for node in node1 node2 node3; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$node.cluster.local" \
    -keyout "$output/$node-key.pem" -out "$output/$node.csr"
  printf 'subjectAltName=DNS:%s.cluster.local,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' "$node" > "$output/$node.ext"
  openssl x509 -req -days 825 -sha256 -in "$output/$node.csr" \
    -CA "$output/ca.pem" -CAkey "$output/ca-key.pem" -CAcreateserial \
    -extfile "$output/$node.ext" -out "$output/$node.pem"
  rm "$output/$node.csr" "$output/$node.ext"
done
chmod 600 "$output"/*-key.pem
echo "Development certificates written to $output"


#!/bin/sh
# The supervisor owns three independent server processes and stops them on exit.
set -eu
cd "$(dirname "$0")/.."
run_dir=${SECRETS_CLUSTER_DIR:-/tmp/distributed-secrets-cluster-playground}
mkdir -p "$run_dir"
chmod 700 "$run_dir"
if [ ! -f "$run_dir/certs/node3.pem" ]; then
  ./scripts/dev-certs.sh "$run_dir/certs" > "$run_dir/certs.log" 2>&1
fi
export GOCACHE=${GOCACHE:-/tmp/distributed-secrets-go-cache}
export GOPATH=${GOPATH:-/tmp/distributed-secrets-gopath}
mkdir -p bin
go build -o bin/secrets-server ./cmd/server
go build -o bin/secrets-playground ./cmd/playground
printf '\nRaft lab: http://127.0.0.1:3000\nNodes: HTTPS ports 8441–8443; mTLS Raft ports 7441–7443\nDisposable lab state and credentials: %s\n\n' "$run_dir"
exec ./bin/secrets-playground --cluster-dir="$run_dir" --ca="$run_dir/certs/ca.pem"

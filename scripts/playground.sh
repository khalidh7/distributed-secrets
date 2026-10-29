#!/bin/sh
# Starts an isolated local service and its UI. Ctrl-C stops both.
set -eu
cd "$(dirname "$0")/.."
run_dir=${SECRETS_PLAYGROUND_DIR:-/tmp/distributed-secrets-playground}
mkdir -p "$run_dir"
chmod 700 "$run_dir"
if [ ! -f "$run_dir/certs/node1.pem" ]; then
  ./scripts/dev-certs.sh "$run_dir/certs" > "$run_dir/certs.log" 2>&1
fi
export GOCACHE=${GOCACHE:-/tmp/distributed-secrets-go-cache}
export GOPATH=${GOPATH:-/tmp/distributed-secrets-gopath}
mkdir -p bin
go build -o bin/secrets-server ./cmd/server
go build -o bin/secrets-playground ./cmd/playground
./bin/secrets-server --addr=127.0.0.1:8443 --data-dir="$run_dir/data" --tls-cert="$run_dir/certs/node1.pem" --tls-key="$run_dir/certs/node1-key.pem" &
service_pid=$!
ui_pid=
cleanup() {
  trap - EXIT INT TERM
  if [ -n "$ui_pid" ]; then kill "$ui_pid" 2>/dev/null || true; fi
  kill "$service_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM
./bin/secrets-playground --addr=127.0.0.1:3000 --service=https://127.0.0.1:8443 --ca="$run_dir/certs/ca.pem" &
ui_pid=$!
printf '\nUI: http://127.0.0.1:3000\nService: https://127.0.0.1:8443\nData: %s/data\nPress Ctrl-C to stop both.\n\n' "$run_dir"
while kill -0 "$service_pid" 2>/dev/null && kill -0 "$ui_pid" 2>/dev/null; do sleep 1; done
exit 1

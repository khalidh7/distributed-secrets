# Distributed Secrets

A Vault-inspired secrets manager written in Go that explores the parts of
secrets infrastructure that are more interesting than encrypted CRUD:
consensus, encryption key management, identity, leases, rotation, durable
recovery, and failure handling.

The project can run as one process for local development or as a three-node
cluster. In cluster mode, secret writes are accepted only after a majority of
nodes agree on the same encrypted command. If the leader stops, the remaining
nodes elect a replacement and continue once they still have quorum.

## Demo

[▶ Watch the 75-second distributed secrets demo](demo.mp4)

The recording walks through initialization, threshold unsealing, encrypted
secret operations, and the three-node Raft failure lab.


## Interactive Raft failure lab

```sh
make cluster-playground
```

Open <http://127.0.0.1:3000>. This starts **three real server processes**, with
independent encrypted state and Raft WALs, HTTPS APIs on ports 8441–8443, and
mutually authenticated Raft connections on ports 7441–7443. Stop the single-node
playground first if it is using port 3000 or 8443.

The left panel sends real secret requests and automatically routes them to the
current leader. The right panel shows observed roles, terms, votes, election
timeouts, commit/applied indexes, the last twelve log positions, and a bounded
history of actual Raft events. Status is sampled every 200 ms; heartbeat pulses
are based on received AppendEntries timestamps. Lines are schematic, not packet
captures. Election timeouts are intentionally 1.6–2.8 seconds with 300 ms
heartbeats so failover is easier to follow.

Try this sequence:

1. Write a sample secret and watch all three logs advance.
2. Click **Drop current leader**. The supervisor abruptly kills only that lab
   process. After missed heartbeats, the survivors request votes and elect a
   replacement in a higher term.
3. Write another version while the old leader is down.
4. Click **Restart node** on the stopped node. Its persistent log is recovered,
   and the new leader brings it up to date.
5. Stop two nodes. Without two of three nodes, writes are blocked. A surviving
   node may still report itself as leader; that does not give it quorum.
6. Click **Restart all stopped nodes** to restore availability.

The lab simulates whole-process crashes, not network partitions. The proxy
rejects writes when observed quorum is absent and does not automatically retry
writes across an election. If a node fails during a submitted write, its outcome
can be uncertain; inspect version history before retrying. Reads may be stale
when no leader is available. Successful writes still require the actual Raft
majority, irrespective of UI state.

This is a **disposable local development lab**, not a production deployment.
It auto-initializes a shared seal, seeds identity state, stores its recovery kit
with mode 0600 at `/tmp/distributed-secrets-cluster-playground/recovery.json`,
and auto-unseals restarted processes. Its local UI receives the demo root token
(valid for 24 hours). Use sample secrets only. Set `SECRETS_CLUSTER_DIR` to use
another lab directory. Your existing single-node data is preserved. Ctrl-C
stops the supervisor and all three children; data is kept for the next run.

Run the end-to-end failover check against the running lab:

```sh
python3 scripts/test-cluster-playground.py
```

It checks replication, leader replacement, continued reads/writes, catch-up,
and quorum loss, then restores all three nodes. It writes a sample secret under
`sandbox/raft-test-*`.

## Interactive local playground

Start the UI and an isolated single-node HTTPS service together:

```sh
make playground
```

Open <http://127.0.0.1:3000>. The service listens on
<https://127.0.0.1:8443>. On first launch, choose **Initialize local vault**;
the UI fills in the root token and lets you download the recovery kit.
Save that kit before closing the tab. Tokens and recovery shares are held only
in page memory, and the initial root token expires after 24 hours.

Write sample key/value pairs on the left, read a specific version, or inspect
version history. The right panel animates an explanation of the implemented
request flow after a successful API response. Playback is illustrative, not
per-step telemetry. This launcher uses single-node storage, so it does not
simulate Raft replication. The response panel shows actual API output.

The UI is bound to loopback and proxies API calls over TLS using the generated
development CA. Certificates and persistent data live in
`/tmp/distributed-secrets-playground`; set `SECRETS_PLAYGROUND_DIR` to use a
different directory. Existing project data is untouched. Ctrl-C stops both
processes. After a restart, submit three recovery shares and paste your saved
access token into the UI. For existing vaults, use the CLI to issue a fresh
token before the old one expires.

To connect the UI to an independently started service:

```sh
go run ./cmd/playground --service=https://127.0.0.1:8443 --ca=/path/to/ca.pem
```

## The 60-second explanation

An application authenticates to the HTTPS API with an expiring token. The
server maps that token to a principal, evaluates path-based policies, and either
denies the request or processes it.

Secret values are never written directly to disk. Every version gets a new
random data-encryption key. That key encrypts the secret with AES-256-GCM and is
then wrapped by a higher-level key-encryption key. In cluster mode, the leader
places only this encrypted record into a Raft log and replicates it to the other
nodes. The write becomes visible after a majority has persisted it.

The key-encryption key is itself protected by a root key. The root key is split
into Shamir shares, so a restarted server begins sealed and cannot decrypt data
until enough operators provide shares. The reconstructed root key is used only
to unlock the key-encryption key in memory.

The same replicated state machine also drives version history, token and policy
changes, leases, and lease expiration. PostgreSQL integration can create
short-lived roles or rotate a stored role's password through a durable workflow
that can resume after partial failure.

## Architecture

```mermaid
flowchart TB
    Client["CLI / Application"]
    API["HTTPS API"]
    Identity["Authentication + Policy"]

    Client -->|"TLS + bearer token"| API
    API --> Identity

    subgraph Cluster["Secrets cluster"]
        N1["Node 1<br/>Leader or follower"]
        N2["Node 2<br/>Leader or follower"]
        N3["Node 3<br/>Leader or follower"]

        N1 <-->|"Raft over mTLS"| N2
        N2 <-->|"Raft over mTLS"| N3
        N3 <-->|"Raft over mTLS"| N1
    end

    Identity --> N1
    Identity --> N2
    Identity --> N3

    N1 --> D1["Encrypted state<br/>WAL + snapshots"]
    N2 --> D2["Encrypted state<br/>WAL + snapshots"]
    N3 --> D3["Encrypted state<br/>WAL + snapshots"]

    N1 -.->|"Dynamic credentials / rotation"| PG["PostgreSQL"]
```

Clients may contact any node, but mutations must go through the current leader.
Followers return a leader hint rather than independently committing a write.
Reads from followers are currently allowed and may be stale.

## What happens during a write

```mermaid
sequenceDiagram
    participant C as Client
    participant L as Raft leader
    participant F1 as Follower 1
    participant F2 as Follower 2
    participant S as State machine

    C->>L: PUT secret over HTTPS
    L->>L: Authenticate and authorize
    L->>L: Envelope-encrypt new version
    L->>L: Append encrypted command to WAL and fsync
    par Replicate
        L->>F1: AppendEntries
        L->>F2: AppendEntries
    end
    F1-->>L: Persisted
    Note over L,F1: Leader + one follower form a majority
    L->>S: Mark committed and apply
    L-->>C: Write succeeded
    L->>F1: Advance commit index
    L->>F2: Retry until caught up
```

The response is not successful merely because the leader wrote to its own disk.
It succeeds after a quorum has persisted the log entry. A node outside the
quorum cannot declare conflicting writes committed.

## What Raft is

Raft is a consensus algorithm for keeping a replicated log in the same order on
multiple machines. This project implements a scoped version directly rather
than importing an existing Raft package.

Every node is in one of three roles:

- A follower accepts log entries from the current leader.
- A candidate asks for votes after an election timeout.
- A leader coordinates writes and replication for its term.

An election works like this:

1. Followers wait for regular leader heartbeats.
2. A follower whose randomized timeout expires becomes a candidate.
3. It increments the term, votes for itself, and requests votes from peers.
4. A majority vote makes it leader.
5. The leader sends heartbeats and starts replicating log entries.

Each entry contains an index, term, encrypted command, and checksum. Followers
reject an append whose previous index and term do not match their log. The
leader backs up and retries until the logs agree. An entry is committed only
when replicated to a majority and, for leader safety, belongs to the leader's
current term.

If the leader dies in a three-node cluster, two surviving nodes still form a
majority. They elect a replacement and resume writes. A single isolated node
cannot form a majority, so it cannot accept committed writes independently.

The implementation includes:

- randomized leader elections;
- `RequestVote`, `AppendEntries`, and `InstallSnapshot` RPCs;
- log conflict repair;
- quorum-based commit advancement;
- checksummed, `fsync`ed WAL entries;
- persisted term, vote, and commit index;
- committed-entry replay after restart;
- state-machine snapshots and WAL compaction;
- snapshot transfer to lagging followers.

The main implementation is in
[`internal/raft/node.go`](internal/raft/node.go), with persistence in
[`internal/raft/wal.go`](internal/raft/wal.go).

## Sealing and unsealing

Encryption at rest is not enough if a server can always find every decryption
key beside the ciphertext. This project therefore starts in a sealed state.

```mermaid
flowchart TD
    Root["Random root key"]
    Shares["Shamir shares<br/>Example: 5 shares, threshold 3"]
    KEK["Key-encryption key (KEK)"]
    Wrapped["Wrapped KEK on disk"]
    DEK["Random data key per secret version"]
    Secret["AES-256-GCM ciphertext"]

    Root --> Shares
    Root -->|"wraps"| KEK
    KEK --> Wrapped
    KEK -->|"wraps"| DEK
    DEK -->|"encrypts"| Secret
```

During initialization:

1. The server generates a random root key and a random key-encryption key.
2. The root key encrypts the key-encryption key.
3. The root key is split into Shamir shares.
4. Only the wrapped key-encryption key and Shamir parameters are stored.
5. The shares and initial root API token are returned once to the operator.

After a restart:

1. The process serves health and unseal endpoints but cannot open secret state.
2. Operators submit distinct shares.
3. Once the threshold is met, the shares reconstruct the root key.
4. The root key unwraps the key-encryption key.
5. The root key is cleared and the key-encryption key remains only in memory.
6. The encrypted store and Raft state can now be recovered.

Sealing again clears in-memory encryption and token-fingerprint keys and closes
the decrypted state-machine interfaces. The ciphertext remains safely on disk.

Implementation: [`internal/seal/manager.go`](internal/seal/manager.go) and
[`internal/secretcrypto/shamir.go`](internal/secretcrypto/shamir.go).

## Envelope encryption

The project does not encrypt every secret directly with one master key. Every
secret version uses envelope encryption:

```text
secret JSON
  -> random 256-bit data-encryption key (DEK)
  -> AES-256-GCM ciphertext + nonce

DEK
  -> encrypted by key-encryption key (KEK)
  -> encrypted DEK + separate nonce
```

Authenticated additional data binds ciphertext to its secret path and version.
Moving ciphertext from one path or version to another causes authentication to
fail. A fresh DEK and nonce are generated for every write, including two writes
with identical values.

This hierarchy allows future KEK rotation without requiring one global key to
encrypt every secret value directly. Cryptographic primitives come from Go's
standard library; the project does not implement AES itself.

Implementation:
[`internal/secretcrypto/envelope.go`](internal/secretcrypto/envelope.go).

## Security and identity model

### Versioned secrets

Writes never overwrite an existing version. A path can contain versions 1, 2,
3, and so on. Historical versions remain addressable, while deletion records a
soft-delete timestamp rather than erasing ciphertext.

### API tokens

Tokens are random credentials with creation and expiration times. The server
persists a keyed HMAC fingerprint, not the raw token. The CLI stores the raw
token in a mode-`0600` client file because it must present it on later requests.

### Policies

Principals have named policies with path patterns and capabilities such as
`create`, `read`, `delete`, `rotate`, and `sudo`. An explicit matching deny
always wins over an allow.

### Audit log

Security-sensitive operations append an event containing who acted, what they
did, which path was involved, whether it succeeded, and a request ID. Secret
values and raw tokens are never logged.

Each event contains the previous event's hash. Editing, deleting, or reordering
an older line breaks verification of the chain. The log is tamper-evident, not
encrypted or remotely anchored.

## Leases and dynamic credentials

A static lease grants a principal access to a secret until an expiration time.
It can be renewed or revoked by its owner. Expiration is a replicated state
transition: only the leader decides that a lease expired and submits that
transition through Raft. Followers do not independently mutate state based on
their local clocks.

The PostgreSQL dynamic provider goes further. It can create a random temporary
login tied to a lease. On revoke or expiration, the leader drops that role.
This turns the service from a passive secret store into a broker for short-lived
credentials.

Implementation: [`internal/leases/manager.go`](internal/leases/manager.go) and
[`internal/dynamic/postgres.go`](internal/dynamic/postgres.go).

## Rotation and partial failure

Changing an external password and updating the secret store cannot be one
ordinary database transaction. A crash could happen after PostgreSQL accepts
the new password but before the secrets cluster stores it.

Rotation is therefore a durable workflow:

```mermaid
stateDiagram-v2
    [*] --> PENDING
    PENDING --> EXTERNAL_UPDATED: PostgreSQL password changed
    EXTERNAL_UPDATED --> SECRET_UPDATED: New secret version committed
    SECRET_UPDATED --> COMPLETE: Workflow finalized
    PENDING --> PENDING: External failure, retry
    EXTERNAL_UPDATED --> EXTERNAL_UPDATED: Store failure, retry same password
```

The pending password is envelope-encrypted in `rotations.json`. If the external
update fails, retry reuses it. If PostgreSQL changed successfully but the secret
write failed, retry skips generating or applying another password and continues
from `EXTERNAL_UPDATED`. That makes the workflow idempotent across partial
failure.

Implementation: [`internal/rotation/engine.go`](internal/rotation/engine.go).

## Quick start

Go 1.23 or newer is required.

```sh
make build
make test
make race
make vet
```

Generate development certificates outside the repository:

```sh
mkdir -p /tmp/distributed-secrets-demo
./scripts/dev-certs.sh /tmp/distributed-secrets-demo/certs
```

Start a sealed single-node server:

```sh
./bin/secrets-server \
  --addr=127.0.0.1:8443 \
  --data-dir=/tmp/distributed-secrets-demo/data \
  --tls-cert=/tmp/distributed-secrets-demo/certs/node1.pem \
  --tls-key=/tmp/distributed-secrets-demo/certs/node1-key.pem
```

In another terminal:

```sh
export SECRETS_ADDR=https://127.0.0.1:8443
export SECRETS_CA_CERT=/tmp/distributed-secrets-demo/certs/ca.pem
export SECRETS_TOKEN_FILE=/tmp/distributed-secrets-demo/client-token

./bin/secretsctl init 5 3
./bin/secretsctl login 'dst_...'
```

Save the returned unseal shares somewhere separate from the data directory. The
initialization response is the only time the root token and shares are returned.

Create and read immutable versions:

```sh
./bin/secretsctl put prod/database username=app password=abc123
./bin/secretsctl put prod/database username=app password=def456
./bin/secretsctl get prod/database
./bin/secretsctl get prod/database 1
./bin/secretsctl versions prod/database
./bin/secretsctl delete prod/database 1
```

After sealing or restarting, submit any threshold number of shares:

```sh
./bin/secretsctl unseal SHARE_1
./bin/secretsctl unseal SHARE_3
./bin/secretsctl unseal SHARE_5
```

## Policies and tokens

Create a path-scoped policy:

```sh
./bin/secretsctl policy payments-reader examples/payments-reader.json
```

Issue an expiring token for a service principal:

```sh
./bin/secretsctl token service-payments 1h payments-reader
```

Log in with the returned token to test what that identity can and cannot access:

```sh
./bin/secretsctl login 'dst_...'
./bin/secretsctl get prod/payments/database
./bin/secretsctl get prod/admin/root
```

The second request is denied by the example policy.

## PostgreSQL rotation demo

Start a disposable PostgreSQL instance:

```sh
docker run --detach \
  --name distributed-secrets-postgres \
  --env POSTGRES_PASSWORD=development-only \
  --publish 55432:5432 \
  postgres:17-alpine
```

Create a role with a known initial password:

```sh
PGPASSWORD=development-only psql \
  --host=127.0.0.1 \
  --port=55432 \
  --username=postgres \
  --dbname=postgres \
  --set=ON_ERROR_STOP=1 \
  --command="CREATE ROLE rotation_demo LOGIN PASSWORD 'initial-password'"
```

Stop the earlier server and restart it with the PostgreSQL provider. If you are
using an existing initialized data directory, submit the unseal threshold again
after it starts. Alternatively, include `--postgres-url` on the first launch.

```sh
./bin/secrets-server \
  --addr=127.0.0.1:8443 \
  --data-dir=/tmp/distributed-secrets-demo/data \
  --tls-cert=/tmp/distributed-secrets-demo/certs/node1.pem \
  --tls-key=/tmp/distributed-secrets-demo/certs/node1-key.pem \
  --postgres-url='postgres://postgres:development-only@127.0.0.1:55432/postgres?sslmode=disable'
```

Store the matching credential and rotate it:

```sh
./bin/secretsctl put prod/database \
  username=rotation_demo \
  password=initial-password

./bin/secretsctl rotate prod/database
./bin/secretsctl get prod/database
./bin/secretsctl versions prod/database
```

The newest secret version contains the generated password. Use it with `psql`
to verify that the new password succeeds and `initial-password` fails.

To demonstrate recovery, stop PostgreSQL, request another rotation, inspect the
persisted `PENDING` record, restart PostgreSQL, and continue it:

```sh
docker stop distributed-secrets-postgres
./bin/secretsctl rotate prod/database
jq . /tmp/distributed-secrets-demo/data/rotations.json

docker start distributed-secrets-postgres
./bin/secretsctl rotation-retry ROTATION_ID
```

## Three-node cluster

Development certificates and a Compose topology are included. Keep the `dev/`
runtime directory out of Git:

```sh
printf '/dev/\n' >> .git/info/exclude
mkdir -p dev/certs dev/seal dev/node1 dev/node2 dev/node3
make certs
```

Bootstrap once in single-node mode with `--data-dir=dev/node1` and
`--seal-dir=dev/seal`, initialize it, save the shares and root token, then stop
it. Copy the initial identity state to the joining nodes:

```sh
cp dev/node1/auth.json dev/node2/auth.json
cp dev/node1/auth.json dev/node3/auth.json
```

Supply three unseal shares and start the cluster:

```sh
export SECRETS_UNSEAL_KEYS='SHARE_1,SHARE_3,SHARE_5'
docker compose up --build
```

Public endpoints are:

```text
https://localhost:8441
https://localhost:8442
https://localhost:8443
```

Raft traffic remains inside the Compose network on ports 7001-7003 and requires
mutual TLS. To demonstrate failover, identify the leader by attempting a write,
stop its container, wait for an election, and repeat the write against either
surviving node.

## Data on disk

```text
data/
  seal.json             wrapped KEK and Shamir parameters
  secrets.db            envelope-encrypted immutable secret versions
  auth.json             token fingerprints, principals, and policies
  leases.json           replicated lease state
  rotations.json        durable rotation workflow state
  audit.log             append-only hash chain
  raft/
    hard-state.json     current term, vote, and commit index
    raft.wal            checksummed replicated commands
    snapshot.json       compact state and last included index/term
```

Secret paths, version numbers, timestamps, principal IDs, lease metadata, and
rotation workflow metadata are visible operational metadata. Secret field names
and values are encrypted in `secrets.db`, the Raft WAL, and snapshots. Raw API
tokens are not persisted by the server.

Useful inspection commands:

```sh
jq . /tmp/distributed-secrets-demo/data/secrets.db
jq . /tmp/distributed-secrets-demo/data/auth.json
jq -s . /tmp/distributed-secrets-demo/data/audit.log
jq -c . /tmp/distributed-secrets-demo/data/raft/raft.wal
```

## Repository layout

```text
cmd/
  server/               process and dependency wiring
  secretsctl/           end-user CLI
internal/
  api/                  HTTPS routes and orchestration
  audit/                tamper-evident event chain
  auth/                 principals and token fingerprints
  cluster/              node mutual TLS
  dynamic/              PostgreSQL dynamic credentials
  leases/               replicated lease state
  policy/               authorization evaluation
  raft/                 consensus, transport, WAL, snapshots
  rotation/             durable external rotation workflow
  seal/                 sealed-state lifecycle
  secretcrypto/         AES-GCM envelopes and Shamir sharing
  storage/              immutable encrypted secret state
```

## Tests and failure cases

```sh
make test
make race
make vet
```

The test suite covers:

- ciphertext persistence and restart recovery;
- unique envelope keys and authentication failure with the wrong key;
- Shamir threshold reconstruction;
- token leakage prevention and expiration;
- explicit policy deny precedence;
- audit-log tampering detection;
- immutable versions and soft deletion;
- lease issue, renew, revoke, and expiration;
- Raft election and replicated writes;
- leader failure followed by re-election and resumed writes;
- WAL corruption detection;
- snapshot creation and recovery;
- PostgreSQL command construction;
- rotation completion, encrypted workflow state, and retry.





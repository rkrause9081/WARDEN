# WARDEN

## Rust Industrial Intrusion Detection System

WARDEN is a multi-threaded Rust intrusion detection and forensic evidence platform designed for MQTT and CoAP industrial/IoT traffic.

Features include:

* real-time packet inspection
* automated mitigation
* JSONL forensic logging
* SHA-256 evidence verification
* Ethereum blockchain anchoring
* live dashboard monitoring

---

# Current System Capabilities

## Detection Engine

* sliding-window PPS analysis
* MQTT flood detection
* CoAP flood detection
* cooldown logic
* IP whitelist support

## Mitigation

* iptables integration
* dry-run mode
* timed bans

## Forensics

* JSONL evidence logs
* SHA-256 evidence hashing
* tamper verification

## Blockchain

* Solidity evidence registry
* Hardhat deployment
* immutable forensic anchoring

## Dashboard

* live packet feed
* alert tracking
* ban tracking
* blockchain evidence visibility

---

# Architecture

```text
┌──────────┐
│ Sniffer  │
└────┬─────┘
     ↓
┌──────────┐
│ Engine   │
└────┬─────┘
     ↓
┌──────────┐
│Mitigator │
└────┬─────┘
     ↓
┌──────────┐
│ JSONL    │
│ Logging  │
└────┬─────┘
     ↓
┌──────────┐
│Blockchain│
│ Anchoring│
└────┬─────┘
     ↓
┌──────────┐
│Verifier  │
└────┬─────┘
     ↓
┌──────────┐
│Dashboard │
└──────────┘
```

---

# Running WARDEN

## Build

```bash
cargo build
```

## Run Dashboard

```bash
sudo -E ./target/debug/WARDEN dashboard
```

Dashboard URL:

```text
http://127.0.0.1:5000
```

---

# Attack Simulation

```bash
for i in {1..100}; do
  mosquitto_pub -h localhost -t icu/test -m attack &
done
wait
```

---

# Verification

```bash
./target/debug/WARDEN verify logs/alerts.jsonl
```

---

# Blockchain Deployment

## Start Hardhat node

```bash
npx hardhat node
```

## Deploy contracts

```bashnpx h
hardhat run scripts/deploy.js --network localhost
```

## Export environment variables

```bash
export WARDEN_BLOCKCHAIN_ENABLED=true
export WARDEN_RPC_URL=http://127.0.0.1:8545
export WARDEN_CHAIN_ID=31337
export WARDEN_FACTORY_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3
export WARDEN_EVIDENCE_ADDRESS=0xa16E02E87b7454126E5E10d957A927A7F5B5d2be
export WARDEN_PRIVATE_KEY=0x70997970c51812dc3a010c7d01b50e0d17dc79c8
```

---

# Tech Stack

* Rust
* Tokio
* Axum
* Libpcap
* iptables
* Solidity
* Hardhat
* Ethereum
* SHA-256

---

# Resume Positioning

Built a multi-threaded intrusion detection pipeline in Rust capable of:

* real-time MQTT/CoAP traffic inspection
* automated mitigation
* forensic JSONL logging
* SHA-256 evidence verification
* Ethereum blockchain anchoring using Solidity smart contracts

---

# Final Phase — Dashboard & Portfolio Polish

## Goal

Turn WARDEN from:

> “cool Rust IDS experiment”

into:

> “junior security engineer portfolio centerpiece”

---

# Final Phase Deliverables

## 1. Real-Time Dashboard Refresh

Add:

* auto-refresh every 1s
* live attack feed
* live packet counter
* live bans list
* live blockchain tx hashes

Result:

* feels like a real SOC console

---

## 2. Visual Threat Intelligence

Add charts:

* packets/sec
* alerts over time
* MQTT vs CoAP traffic
* top attacker IPs

Suggested library:

* Chart.js

---

## 3. Incident Timeline Panel

Example:

```text
03:14:22  MQTT flood detected
03:14:23  Mitigation applied
03:14:24  Evidence anchored on-chain
03:14:25  Evidence verification successful
```

---

## 4. Blockchain Verification Panel

Show:

* evidence hash
* tx hash
* registry address
* verification status
* anchored on-chain indicator

---

## 5. Verification UI

Add:

* upload alerts.jsonl
* click Verify
* show:

  * Valid
  * Tampered
  * Missing hash

---

## 6. Architecture Diagram

Add:

* system flow diagram
* pipeline diagram
* dashboard screenshot
* verifier screenshot
* blockchain transaction screenshot

---

# Suggested Final Timeline

## Day 1

* clean dashboard layout
* add charts
* add live feed

## Day 2

* add blockchain panel
* add verification UI
* polish CSS

## Day 3

* architecture diagram
* screenshots
* GIF demo
* README rewrite

## Day 4

* final cleanup
* GitHub polish
* resume updates
* LinkedIn project post

---

# Final Recommendation

Do not endlessly add phases.

At this point:

* UI polish
* documentation
* screenshots
* architecture clarity
* deployment quality

matter more than adding new subsystems.

WARDEN is already strong enough to function as a standout portfolio project for:

* security engineering
* backend engineering
* systems programming
* blockchain infrastructure roles
* SOC tooling
* Rust development

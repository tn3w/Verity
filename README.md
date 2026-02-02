# Verity

High-performance IP reputation lookup service built with Rust and Axum.

## Features

- Fast IP lookup against 144 threat intelligence feeds
- Automatic data updates every 24 hours from IPBlocklist
- Memory-efficient with RwLock for concurrent reads
- Sub-2ms search time after loading
- 8.7M+ IPs and CIDR ranges from multiple threat intelligence sources
- Reputation scoring with category-based threat analysis

## API Endpoints

- `GET /` - Redirects to GitHub repository
- `GET /me` - Check your own IP reputation (includes IP in response)
- `GET /:ip` - Check IP reputation, returns score, matching feeds, and flags

## Response Format

```json
{
  "score": 0.75,
  "lists": ["feodotracker", "emerging_compromised"],
  "is_malware": true,
  "is_botnet": true,
  "is_c2_server": true
}
```

## Deployment

### Docker on Ubuntu

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Clone and build
git clone https://github.com/tn3w/Verity.git
cd Verity
docker build -t verity:latest .

# Create network
docker network create webnet

# Run multiple instances
docker run -d --name verity_1 --network webnet verity:latest
docker run -d --name verity_2 --network webnet verity:latest
docker run -d --name verity_3 --network webnet verity:latest

# Configure nginx/caddy for load balancing
```

### Local

```bash
cargo run --release
```

Server runs on `http://0.0.0.0:3000`

## Data Source

Verity uses the [IPBlocklist](https://github.com/tn3w/IPBlocklist) dataset, which aggregates threat intelligence from 144 security feeds including:

- Malware C&C servers and botnets
- Spam networks and compromised hosts
- VPN providers and Tor nodes
- Datacenter/hosting ASNs
- Web attackers and scanners

The data is automatically downloaded from `https://raw.githubusercontent.com/tn3w/IPBlocklist/master/data.json` and updated every 24 hours.

## Structure

```
├── src/main.rs    # API service
├── Cargo.toml     # Dependencies
└── Dockerfile     # Container config
```

# Verity

High-performance IP reputation lookup service built with Rust and Axum.

## Features

- Fast IP lookup against 70+ threat intelligence lists
- Automatic list updates every 24 hours via GitHub Actions
- Memory-efficient with RwLock for concurrent reads
- Sub-2ms search time after loading

## API Endpoints

- `GET /` - Redirects to GitHub repository
- `GET /:ip` - Check IP reputation, returns list of matching threat lists

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

## Manual List Update

```bash
python update_lists.py
```

## Structure

```
├── .github/workflows/update-lists.yml  # Auto-update workflow
├── src/main.rs                         # API service
├── Cargo.toml
├── sources.json                        # List sources config
├── lists.json                          # Processed lists (50MB)
└── update_lists.py                     # List updater script
```

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

### Railway

1. Connect repository to Railway
2. Railway auto-detects Rust and deploys
3. Lists update automatically via GitHub Actions

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

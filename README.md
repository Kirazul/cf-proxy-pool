# CF Proxy Pool

A Cloudflare Worker that deploys and manages a pool of proxy workers for request routing with automatic IP rotation via X-Forwarded-For spoofing.

## Features

-  Deploy multiple proxy workers via Cloudflare API
-  Automatic request routing through proxy pool
-  X-Forwarded-For header spoofing (random IPs)
-  API key authentication for admin endpoints
-  Pool status and health monitoring
-  Bulk cleanup of deployed workers

## Quick Start

```bash
# Clone and deploy
git clone https://github.com/Kirazul/cf-proxy-pool.git
cd cf-proxy-pool
npm install -g wrangler
wrangler deploy

# Set secrets
wrangler secret put CF_API_TOKEN    # Your CF API token
wrangler secret put CF_ACCOUNT_ID   # Your CF account ID  
wrangler secret put API_KEY         # Admin password
```

## API Endpoints

### Public

| Endpoint | Description |
|----------|-------------|
| `GET /` | API info and available endpoints |
| `GET /ip` | Check worker's egress IP |
| `GET /pool` | Pool status (proxy count, IPs) |
| `GET /proxy?url=URL` | Proxy request through random pool worker |
| `GET /direct?url=URL` | Proxy request directly (no pool) |

### Admin (requires `X-API-Key` header)

| Endpoint | Description |
|----------|-------------|
| `GET /create?count=N` | Deploy N new proxy workers |
| `GET /list` | List all deployed proxy workers |
| `GET /delete?name=X` | Delete specific proxy worker |
| `GET /cleanup` | Delete all proxy workers |
| `GET /test` | Test all proxies and show IPs |

## Usage Examples

```bash
# Create 10 proxy workers
curl "https://cf-proxy-pool.YOUR.workers.dev/create?count=10" \
  -H "X-API-Key: your-secret"

# Proxy a request (auto-rotates through pool)
curl "https://cf-proxy-pool.YOUR.workers.dev/proxy?url=https://httpbin.org/ip"

# Check pool status
curl "https://cf-proxy-pool.YOUR.workers.dev/pool"

# Test all proxies
curl "https://cf-proxy-pool.YOUR.workers.dev/test" \
  -H "X-API-Key: your-secret"

# Cleanup all workers
curl "https://cf-proxy-pool.YOUR.workers.dev/cleanup" \
  -H "X-API-Key: your-secret"
```

## Setup

### 1. Get Cloudflare Credentials

**Account ID**: Found in your dashboard URL `dash.cloudflare.com/ACCOUNT_ID/...`

**API Token**:
1. Go to [API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Create Token → "Edit Cloudflare Workers" template
3. Account Resources: All accounts
4. Zone Resources: All zones

### 2. Deploy

```bash
wrangler deploy
```

### 3. Set Secrets

```bash
wrangler secret put CF_API_TOKEN    # Paste your API token
wrangler secret put CF_ACCOUNT_ID   # Paste your account ID
wrangler secret put API_KEY         # Choose admin password
```

## How It Works

1. **Create**: Deploys lightweight proxy workers via CF API
2. **Route**: `/proxy` randomly selects a worker from the pool
3. **Spoof**: Each proxy adds a random `X-Forwarded-For` header
4. **Manage**: List, test, and cleanup workers via admin endpoints

## Important Notes

⚠️ **Same Account = Same Egress IP**: All workers in the same Cloudflare account share the same TCP egress IP. The X-Forwarded-For spoofing works for ~60-70% of sites that trust this header.

For true IP rotation, you need:
- Multiple Cloudflare accounts
- External proxy services (residential proxies, Tor)
- Cloudflare One dedicated egress IPs (Enterprise)

## License

MIT

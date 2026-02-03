# DNS Threat Simulator

Advanced DNS traffic generator for security testing and monitoring validation. Generates realistic, diverse DNS traffic patterns including normal queries, suspicious domains, DGA (Domain Generation Algorithm) patterns, and blocked domain requests.

## Features

- **Multiple Traffic Profiles**: Enterprise, Infected, Developer, Mixed
- **Realistic DGA Generation**: Variable complexity domain generation algorithms
- **Burst Traffic**: Random traffic bursts for anomaly detection testing
- **Diverse Query Types**: A, AAAA, MX, TXT, CNAME, NS with realistic weights
- **Multi-Server Deployment**: Deploy unique profiles to multiple servers
- **Statistics Tracking**: Real-time query statistics and reporting

## Quick Start

```bash
# Deploy to all servers
./deploy.sh deploy

# Start all simulators
./deploy.sh start

# Check status
./deploy.sh status

# View logs
./deploy.sh logs

# Stop all simulators
./deploy.sh stop
```

## Server Profiles

| Server | Profile | Description |
|--------|---------|-------------|
| 10.50.0.108 | `enterprise` | Heavy normal traffic (60%), CDN (25%), minimal threats |
| 10.50.0.109 | `infected` | High DGA (35%), suspicious (30%), malware (8%) |
| 10.50.0.110 | `developer` | Mixed traffic with varied patterns |

## Traffic Profiles

### Enterprise Profile
- 60% Normal domains (google.com, microsoft.com, etc.)
- 25% CDN traffic (cloudflare, jsdelivr, etc.)
- 8% Ad networks
- 5% Tracking services
- 1.5% Suspicious domains
- 0.5% DGA/Malware

### Infected Profile
- 35% DGA domains (algorithmically generated)
- 30% Suspicious domains (phishing-like)
- 20% Normal domains
- 8% Malware domains
- 5% CDN
- 2% Ads/Tracking

### Developer Profile
- 45% Normal domains
- 30% CDN (npm, jsdelivr, etc.)
- 10% Tracking (analytics)
- 5% Suspicious
- 5% Ads
- 5% DGA/Malware

## Manual Usage

```bash
# Run with specific profile
python3 dns_simulator.py -p enterprise -s 10.50.0.30

# Run batch of queries
python3 dns_simulator.py -p infected -c 100

# Run for specific duration (seconds)
python3 dns_simulator.py -p developer -d 300
```

### Options

| Option | Description |
|--------|-------------|
| `-s, --server` | DNS server IP (default: 10.50.0.30) |
| `-p, --profile` | Traffic profile: enterprise, infected, developer, mixed |
| `-c, --count` | Number of queries (0 for continuous) |
| `-d, --duration` | Duration in seconds (0 for unlimited) |

## Legacy Bash Simulator

The original bash-based simulator is still available:

```bash
# Run specific pattern
./simulator.sh --pattern normal --count 100
./simulator.sh --pattern suspicious --count 50
./simulator.sh --pattern mixed --duration 300

# Multi-server control
./control.sh start
./control.sh status
./control.sh stop
```

## DGA Generation

The simulator generates DGA-like domains with varying complexity:

- **Low**: Simple random strings (8-12 chars)
- **Medium**: Consonant-vowel patterns with numbers
- **High**: MD5 hashes, base64-like strings, complex patterns

Example generated domains:
- `xkjh2sd9f3kdm.xyz`
- `a3b7c9d2e5f8.com`
- `vowelcons123mix.net`

## Domain Categories

| Category | Examples |
|----------|----------|
| Normal | google.com, github.com, microsoft.com |
| CDN | cloudflare.com, jsdelivr.net, akamai.net |
| Suspicious | free-prize-winner.com, urgent-update.net |
| Malware | malware.testcategory.com |
| Ads | doubleclick.net, googlesyndication.com |
| Tracking | google-analytics.com, mixpanel.com |

## Requirements

- Python 3.6+
- `dig` command (bind-utils / dnsutils)
- SSH access to target servers

## Installation

### Prerequisites

```bash
# RHEL/CentOS
sudo yum install -y bind-utils python3

# Ubuntu/Debian
sudo apt-get install -y dnsutils python3
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| DNS_SERVER | 10.50.0.30 | Target DNS server |
| SSH_USER | tempu | SSH username |

## Output

```
[16:30:00] Starting DNS Simulator
  Profile: infected
  DNS Server: 10.50.0.30
  Weights: {'normal': 20, 'cdn': 5, 'suspicious': 30, 'dga': 35, ...}
--------------------------------------------------
[16:30:05] BURST: 25 queries
[16:30:10] Queries: 100 (18.5 q/s)
[16:30:15] Queries: 200 (19.2 q/s)
...

==================================================
DNS Simulator Statistics
==================================================
Profile: infected
Duration: 120.5 seconds
Total Queries: 2500
Queries/Second: 20.75
--------------------------------------------------
  normal      :    512 ( 20.5%)
  suspicious  :    745 ( 29.8%)
  dga         :    892 ( 35.7%)
  malware     :    198 (  7.9%)
  cdn         :    153 (  6.1%)
==================================================
```

## Architecture

```
dns-threat-simulator/
├── dns_simulator.py      # Python-based simulator (v2.0)
├── deploy.sh             # Multi-server deployment
├── simulator.sh          # Legacy bash simulator
├── control.sh            # Legacy multi-server control
├── config/
│   └── servers.conf      # Server configuration
└── README.md
```

## Related Projects

- [CortexDNS](https://github.com/e2esolutions-tech/cortexdns) - Enterprise DNS Management Platform
- [Batin Intelligence](https://github.com/e2esolutions-tech/batin) - Domain Classification & DGA Detection

## License

MIT License - E2E Solutions 2026

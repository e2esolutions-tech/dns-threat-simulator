# DNS Threat Simulator

A professional DNS traffic simulation tool for testing and validating DNS security solutions. Generates realistic, diverse DNS traffic patterns including normal queries, suspicious domains, DGA (Domain Generation Algorithm) patterns, and blocked domain requests.

## Features

- **Multiple Traffic Patterns**: Normal, suspicious, DGA, burst, CDN, and blocked traffic
- **Realistic Distribution**: Weighted random distributions mimicking real-world traffic
- **Multi-Server Support**: Deploy and control simulators across multiple clients
- **Configurable Parameters**: Adjustable query rates, patterns, and target servers
- **Professional Logging**: Detailed logs for analysis and debugging
- **Systemd Integration**: Run as a background service

## Traffic Patterns

| Pattern | Description | Use Case |
|---------|-------------|----------|
| `normal` | Popular domains (Google, Microsoft, etc.) | Baseline traffic |
| `business` | Enterprise SaaS domains | Corporate environment simulation |
| `suspicious` | Phishing, malware-like domains | Threat detection testing |
| `dga` | Algorithmically generated domains | DGA detection testing |
| `blocked` | Known ad/tracking domains | Blocklist testing |
| `burst` | High-frequency short bursts | Spike detection testing |
| `cdn` | CDN and static content domains | CDN traffic patterns |
| `mixed` | Combination of all patterns | Comprehensive testing |

## Quick Start

### Single Server

```bash
# Clone the repository
git clone https://github.com/e2esolutions-tech/dns-threat-simulator.git
cd dns-threat-simulator

# Make executable
chmod +x simulator.sh

# Run with default settings (mixed traffic for 60 seconds)
./simulator.sh

# Run specific pattern
./simulator.sh --pattern normal --count 100
./simulator.sh --pattern suspicious --count 50
./simulator.sh --pattern mixed --duration 300
```

### Multi-Server Deployment

```bash
# Edit config file with your servers
cp config/servers.example.conf config/servers.conf
vim config/servers.conf

# Deploy to all servers
./deploy.sh

# Start simulators on all servers
./control.sh start

# Check status
./control.sh status

# Stop all
./control.sh stop
```

## Installation

### Prerequisites

- Linux (RHEL/CentOS/Ubuntu/Debian)
- `dig` command (bind-utils or dnsutils package)
- SSH access for multi-server deployment

### Install Dependencies

```bash
# RHEL/CentOS
sudo yum install -y bind-utils

# Ubuntu/Debian
sudo apt-get install -y dnsutils
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_SERVER` | `10.50.0.30` | Target DNS server IP |
| `LOG_FILE` | `/var/log/dns-simulator.log` | Log file path |
| `QUERY_INTERVAL` | `1.0` | Base interval between queries (seconds) |

### Server Configuration

Edit `config/servers.conf`:

```ini
[servers]
client1 = 10.50.0.108
client2 = 10.50.0.109
client3 = 10.50.0.110

[patterns]
client1 = heavy_normal
client2 = mixed_suspicious
client3 = burst_cdn

[ssh]
user = tempu
key_path = ~/.ssh/id_rsa
```

## Usage Examples

### Generate Normal Traffic
```bash
./simulator.sh --pattern normal --count 1000 --server 10.50.0.30
```

### Simulate DGA Attack
```bash
./simulator.sh --pattern dga --count 500 --interval 0.5
```

### Continuous Mixed Traffic
```bash
./simulator.sh --pattern continuous
```

### Custom Domain List
```bash
./simulator.sh --pattern custom --domains-file /path/to/domains.txt
```

## Systemd Service

Install as a system service:

```bash
sudo ./install-service.sh

# Start service
sudo systemctl start dns-simulator

# Enable on boot
sudo systemctl enable dns-simulator

# Check status
sudo systemctl status dns-simulator
```

## Output and Logging

### Log Format
```
2026-02-02 01:30:45 A google.com 0 OK 12ms
2026-02-02 01:30:46 AAAA facebook.com 0 OK 8ms
2026-02-02 01:30:47 A xk7jm9qw2p.tk 0 BLOCKED 3ms
```

### Statistics
```bash
# View real-time statistics
./simulator.sh --stats

# Generate report
./simulator.sh --report
```

## Architecture

```
dns-threat-simulator/
├── simulator.sh          # Main simulator script
├── control.sh            # Multi-server control
├── deploy.sh             # Deployment script
├── install-service.sh    # Systemd installer
├── config/
│   ├── servers.conf      # Server configuration
│   ├── domains/          # Domain lists by category
│   │   ├── popular.txt
│   │   ├── business.txt
│   │   ├── suspicious.txt
│   │   ├── dga.txt
│   │   └── blocked.txt
│   └── patterns/         # Traffic pattern definitions
├── lib/
│   ├── common.sh         # Common functions
│   ├── patterns.sh       # Pattern generators
│   └── distributions.sh  # Statistical distributions
└── logs/                 # Log files
```

## Traffic Distribution

The simulator uses weighted random distributions to create realistic traffic patterns:

### Normal Traffic (default weights)
- Popular domains: 50%
- Business domains: 25%
- Tech/API domains: 15%
- CDN domains: 10%

### Query Types (default weights)
- A records: 75%
- AAAA records: 15%
- Other (MX, TXT, etc.): 10%

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Related Projects

- [CortexDNS](https://github.com/e2esolutions-tech/cortexdns) - Enterprise DNS Management Platform
- [Batin Intelligence](https://github.com/e2esolutions-tech/batin) - Domain Classification & DGA Detection

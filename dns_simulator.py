#!/usr/bin/env python3
"""
DNS Threat Simulator - Advanced Traffic Generator
Generates diverse DNS traffic patterns for security testing

Author: E2E Solutions
Version: 2.0.0
"""

import subprocess
import random
import time
import string
import argparse
import signal
import sys
import hashlib
from datetime import datetime
from typing import List, Dict, Tuple
import json

# Configuration
DNS_SERVER = "10.50.0.30"

# Domain categories with realistic examples
DOMAINS = {
    "normal": [
        "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
        "linkedin.com", "github.com", "stackoverflow.com", "reddit.com", "amazon.com",
        "microsoft.com", "apple.com", "netflix.com", "spotify.com", "dropbox.com",
        "slack.com", "zoom.us", "salesforce.com", "adobe.com", "oracle.com",
        "ibm.com", "intel.com", "nvidia.com", "amd.com", "cisco.com",
        "vmware.com", "docker.com", "kubernetes.io", "terraform.io", "ansible.com",
        "python.org", "nodejs.org", "golang.org", "rust-lang.org", "java.com",
        "wikipedia.org", "bbc.com", "cnn.com", "nytimes.com", "theguardian.com",
        "weather.com", "maps.google.com", "drive.google.com", "docs.google.com",
        "outlook.com", "office.com", "teams.microsoft.com", "onedrive.com"
    ],
    "cdn": [
        "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "cdn.bootcdn.net",
        "ajax.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
        "cloudflare.com", "akamai.net", "fastly.net", "cloudfront.net",
        "azureedge.net", "edgecastcdn.net", "stackpath.com", "cdn77.com",
        "bunnycdn.com", "keycdn.com", "jsdelivr.net", "staticfile.org"
    ],
    "suspicious": [
        "free-prize-winner.com", "claim-your-reward.net", "urgent-update-required.com",
        "security-alert-login.com", "account-verify-now.net", "password-reset-urgent.com",
        "lottery-winner-2024.com", "free-iphone-giveaway.net", "click-here-money.com",
        "crypto-doubler-fast.com", "investment-guaranteed.net", "quick-loan-approve.com",
        "dating-singles-near.com", "weight-loss-miracle.net", "anti-aging-secret.com"
    ],
    "malware": [
        "malware.testcategory.com", "virus-download.evil.com", "trojan-payload.bad.net",
        "ransomware-c2.malicious.org", "botnet-controller.dark.com", "keylogger-drop.hack.net",
        "cryptominer-pool.mine.com", "exploit-kit.attack.org", "phishing-kit.steal.net"
    ],
    "ads": [
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "adsserver.com", "adservice.google.com", "pagead2.googlesyndication.com",
        "ads.facebook.com", "ads.twitter.com", "advertising.com", "adnxs.com",
        "moatads.com", "adsrvr.org", "pubmatic.com", "rubiconproject.com"
    ],
    "tracking": [
        "google-analytics.com", "analytics.google.com", "facebook.com/tr",
        "hotjar.com", "mixpanel.com", "segment.io", "amplitude.com",
        "heap.io", "fullstory.com", "mouseflow.com", "crazyegg.com"
    ]
}

# TLDs for DGA generation
DGA_TLDS = [".com", ".net", ".org", ".xyz", ".top", ".info", ".biz", ".tk", ".cc", ".pw"]

# Query types with weights
QUERY_TYPES = {
    "A": 70,
    "AAAA": 15,
    "MX": 5,
    "TXT": 5,
    "CNAME": 3,
    "NS": 2
}

class DNSSimulator:
    """Advanced DNS Traffic Simulator"""

    def __init__(self, dns_server: str = DNS_SERVER, profile: str = "mixed"):
        self.dns_server = dns_server
        self.profile = profile
        self.running = True
        self.stats = {
            "total_queries": 0,
            "normal": 0,
            "suspicious": 0,
            "dga": 0,
            "malware": 0,
            "cdn": 0,
            "ads": 0,
            "tracking": 0
        }
        self.start_time = datetime.now()

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Profile configurations - completely different for each server
        self.profiles = {
            # Server 1: Enterprise workstation - heavy normal traffic, some CDN
            "enterprise": {
                "weights": {"normal": 60, "cdn": 25, "ads": 8, "tracking": 5, "suspicious": 1.5, "dga": 0.3, "malware": 0.2},
                "query_interval": (0.1, 0.5),  # Fast, steady
                "burst_probability": 0.05,
                "burst_size": (5, 15),
                "dga_complexity": "low"
            },
            # Server 2: Infected workstation - high suspicious/DGA traffic
            "infected": {
                "weights": {"normal": 20, "cdn": 5, "suspicious": 30, "dga": 35, "malware": 8, "ads": 1, "tracking": 1},
                "query_interval": (0.05, 0.3),  # Very fast, erratic
                "burst_probability": 0.2,
                "burst_size": (10, 50),
                "dga_complexity": "high"
            },
            # Server 3: Developer workstation - mixed with lots of variety
            "developer": {
                "weights": {"normal": 45, "cdn": 30, "ads": 5, "tracking": 10, "suspicious": 5, "dga": 3, "malware": 2},
                "query_interval": (0.2, 1.0),  # Variable pace
                "burst_probability": 0.15,
                "burst_size": (3, 20),
                "dga_complexity": "medium"
            },
            # Mixed profile
            "mixed": {
                "weights": {"normal": 40, "cdn": 20, "suspicious": 15, "dga": 10, "malware": 5, "ads": 5, "tracking": 5},
                "query_interval": (0.1, 0.8),
                "burst_probability": 0.1,
                "burst_size": (5, 25),
                "dga_complexity": "medium"
            }
        }

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Shutting down...")
        self.running = False
        self._print_stats()
        sys.exit(0)

    def _print_stats(self):
        """Print statistics"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        qps = self.stats["total_queries"] / elapsed if elapsed > 0 else 0

        print("\n" + "="*50)
        print("DNS Simulator Statistics")
        print("="*50)
        print(f"Profile: {self.profile}")
        print(f"Duration: {elapsed:.1f} seconds")
        print(f"Total Queries: {self.stats['total_queries']}")
        print(f"Queries/Second: {qps:.2f}")
        print("-"*50)
        for category, count in self.stats.items():
            if category != "total_queries" and count > 0:
                pct = (count / self.stats["total_queries"] * 100) if self.stats["total_queries"] > 0 else 0
                print(f"  {category:12}: {count:6} ({pct:5.1f}%)")
        print("="*50)

    def generate_dga_domain(self, complexity: str = "medium") -> str:
        """Generate a DGA-like domain"""
        if complexity == "low":
            # Simple random string
            length = random.randint(8, 12)
            name = ''.join(random.choices(string.ascii_lowercase, k=length))
        elif complexity == "high":
            # More sophisticated - mix of patterns
            patterns = [
                lambda: ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(10, 20))),
                lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:random.randint(12, 16)],
                lambda: ''.join([random.choice(string.ascii_lowercase) + random.choice(string.digits) for _ in range(random.randint(6, 10))]),
                lambda: base64_like_string(random.randint(12, 18))
            ]
            name = random.choice(patterns)()
        else:
            # Medium complexity
            consonants = 'bcdfghjklmnpqrstvwxz'
            vowels = 'aeiou'
            length = random.randint(10, 16)
            name = ''.join([random.choice(consonants if i % 2 == 0 else vowels) for i in range(length)])
            # Add some randomness
            if random.random() > 0.5:
                name = name[:random.randint(3, 6)] + str(random.randint(0, 999)) + name[random.randint(6, 10):]

        tld = random.choice(DGA_TLDS)
        return name + tld

    def get_random_domain(self, category: str) -> str:
        """Get a random domain from category or generate one"""
        if category == "dga":
            config = self.profiles.get(self.profile, self.profiles["mixed"])
            return self.generate_dga_domain(config.get("dga_complexity", "medium"))
        elif category in DOMAINS:
            return random.choice(DOMAINS[category])
        else:
            return random.choice(DOMAINS["normal"])

    def get_query_type(self) -> str:
        """Get weighted random query type"""
        types = list(QUERY_TYPES.keys())
        weights = list(QUERY_TYPES.values())
        return random.choices(types, weights=weights, k=1)[0]

    def select_category(self) -> str:
        """Select a category based on profile weights"""
        config = self.profiles.get(self.profile, self.profiles["mixed"])
        weights = config["weights"]

        categories = list(weights.keys())
        probs = list(weights.values())
        total = sum(probs)
        probs = [p/total for p in probs]

        return random.choices(categories, weights=probs, k=1)[0]

    def send_query(self, domain: str, query_type: str = "A") -> bool:
        """Send a DNS query"""
        try:
            cmd = ["dig", f"@{self.dns_server}", domain, query_type, "+short", "+time=2", "+tries=1"]
            subprocess.run(cmd, capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def run_continuous(self):
        """Run continuous traffic generation"""
        config = self.profiles.get(self.profile, self.profiles["mixed"])

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting DNS Simulator")
        print(f"  Profile: {self.profile}")
        print(f"  DNS Server: {self.dns_server}")
        print(f"  Weights: {config['weights']}")
        print("-" * 50)

        while self.running:
            try:
                # Check for burst
                if random.random() < config["burst_probability"]:
                    burst_size = random.randint(*config["burst_size"])
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] BURST: {burst_size} queries")
                    for _ in range(burst_size):
                        if not self.running:
                            break
                        category = self.select_category()
                        domain = self.get_random_domain(category)
                        qtype = self.get_query_type()
                        self.send_query(domain, qtype)
                        self.stats["total_queries"] += 1
                        self.stats[category] = self.stats.get(category, 0) + 1
                        time.sleep(random.uniform(0.01, 0.05))
                else:
                    # Normal query
                    category = self.select_category()
                    domain = self.get_random_domain(category)
                    qtype = self.get_query_type()

                    self.send_query(domain, qtype)
                    self.stats["total_queries"] += 1
                    self.stats[category] = self.stats.get(category, 0) + 1

                # Log progress every 100 queries
                if self.stats["total_queries"] % 100 == 0:
                    elapsed = (datetime.now() - self.start_time).total_seconds()
                    qps = self.stats["total_queries"] / elapsed
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Queries: {self.stats['total_queries']} ({qps:.1f} q/s)")

                # Wait interval
                interval = random.uniform(*config["query_interval"])
                time.sleep(interval)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(1)

        self._print_stats()

    def run_batch(self, count: int):
        """Run a batch of queries"""
        config = self.profiles.get(self.profile, self.profiles["mixed"])

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending {count} queries (profile: {self.profile})")

        for i in range(count):
            if not self.running:
                break

            category = self.select_category()
            domain = self.get_random_domain(category)
            qtype = self.get_query_type()

            self.send_query(domain, qtype)
            self.stats["total_queries"] += 1
            self.stats[category] = self.stats.get(category, 0) + 1

            if (i + 1) % 50 == 0:
                print(f"  Progress: {i+1}/{count}")

            time.sleep(random.uniform(0.02, 0.1))

        self._print_stats()


def base64_like_string(length: int) -> str:
    """Generate a base64-like random string"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length)).lower()


def main():
    parser = argparse.ArgumentParser(description="DNS Threat Simulator")
    parser.add_argument("-s", "--server", default=DNS_SERVER, help="DNS server IP")
    parser.add_argument("-p", "--profile", default="mixed",
                       choices=["enterprise", "infected", "developer", "mixed"],
                       help="Traffic profile")
    parser.add_argument("-c", "--count", type=int, default=0,
                       help="Number of queries (0 for continuous)")
    parser.add_argument("-d", "--duration", type=int, default=0,
                       help="Duration in seconds (0 for unlimited)")

    args = parser.parse_args()

    simulator = DNSSimulator(dns_server=args.server, profile=args.profile)

    if args.count > 0:
        simulator.run_batch(args.count)
    else:
        if args.duration > 0:
            # Run with duration limit
            def timeout_handler(signum, frame):
                simulator.running = False
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(args.duration)

        simulator.run_continuous()


if __name__ == "__main__":
    main()

#!/bin/bash
#===============================================================================
# DNS Threat Simulator
# Professional DNS traffic simulation for security testing
#
# Author: E2E Solutions
# Version: 1.0.0
# License: MIT
#===============================================================================

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DNS_SERVER="${DNS_SERVER:-10.50.0.30}"
LOG_DIR="${LOG_DIR:-${SCRIPT_DIR}/logs}"
LOG_FILE="${LOG_FILE:-${LOG_DIR}/dns-simulator.log}"
STATS_FILE="${LOG_DIR}/stats.json"
PID_FILE="/tmp/dns-simulator.pid"

# Default parameters
DEFAULT_COUNT=100
DEFAULT_DURATION=60
DEFAULT_INTERVAL=1.0
VERBOSE=false

# Colors
declare -A COLORS=(
    [RED]='\033[0;31m'
    [GREEN]='\033[0;32m'
    [YELLOW]='\033[1;33m'
    [BLUE]='\033[0;34m'
    [CYAN]='\033[0;36m'
    [MAGENTA]='\033[0;35m'
    [NC]='\033[0m'
)

# Statistics
declare -A STATS
STATS[total]=0
STATS[success]=0
STATS[failed]=0
STATS[blocked]=0
STATS[dga]=0

#===============================================================================
# Domain Categories
#===============================================================================

# Popular domains - high traffic, legitimate
POPULAR_DOMAINS=(
    "google.com" "www.google.com" "mail.google.com" "drive.google.com"
    "youtube.com" "www.youtube.com" "facebook.com" "www.facebook.com"
    "amazon.com" "www.amazon.com" "twitter.com" "x.com"
    "instagram.com" "linkedin.com" "netflix.com" "microsoft.com"
    "apple.com" "github.com" "stackoverflow.com" "reddit.com"
    "wikipedia.org" "yahoo.com" "bing.com" "zoom.us"
    "slack.com" "dropbox.com" "spotify.com" "twitch.tv"
    "cloudflare.com" "aws.amazon.com" "azure.microsoft.com"
)

# Business/Enterprise domains
BUSINESS_DOMAINS=(
    "outlook.office365.com" "teams.microsoft.com" "sharepoint.com"
    "salesforce.com" "workday.com" "servicenow.com" "zendesk.com"
    "hubspot.com" "mailchimp.com" "intercom.io" "drift.com"
    "atlassian.net" "jira.atlassian.com" "confluence.atlassian.com"
    "notion.so" "monday.com" "asana.com" "trello.com" "airtable.com"
    "docusign.com" "adobe.com" "canva.com" "figma.com"
)

# Technology/Developer domains
TECH_DOMAINS=(
    "api.github.com" "registry.npmjs.org" "pypi.org" "rubygems.org"
    "hub.docker.com" "kubernetes.io" "terraform.io" "ansible.com"
    "jenkins.io" "gitlab.com" "bitbucket.org" "circleci.com"
    "travis-ci.org" "codecov.io" "sonarqube.org" "snyk.io"
    "newrelic.com" "datadog.com" "grafana.com" "prometheus.io"
    "elastic.co" "splunk.com" "sumologic.com" "loggly.com"
)

# CDN and Static Content domains
CDN_DOMAINS=(
    "cdn.jsdelivr.net" "cdnjs.cloudflare.com" "unpkg.com"
    "ajax.googleapis.com" "fonts.googleapis.com" "fonts.gstatic.com"
    "static.cloudflareinsights.com" "cdn.segment.com"
    "d1.awsstatic.com" "images-na.ssl-images-amazon.com"
    "static.xx.fbcdn.net" "i.ytimg.com" "s.yimg.com"
    "akamaized.net" "fastly.net" "edgecastcdn.net"
)

# Suspicious/Phishing-like domains (for testing detection)
SUSPICIOUS_DOMAINS=(
    "free-money-now.tk" "urgent-update-required.ml"
    "account-verify-now.ga" "security-alert-login.cf"
    "password-reset-urgent.gq" "lottery-winner-claim.tk"
    "free-iphone-winner.ml" "crypto-investment-profit.ga"
    "bank-security-update.cf" "paypal-verify-account.tk"
    "amazon-order-problem.ml" "apple-id-suspended.ga"
    "netflix-payment-failed.cf" "microsoft-virus-alert.gq"
)

# DGA-like domains (algorithmically generated looking)
DGA_PATTERNS=(
    "xk7jm9qw2p" "a8h3kd9x2m" "q9w2e4r6t8" "zx8cv7bn5m"
    "lk4jh3gf2d" "po0iu9yt8r" "mn7bv6cx5z" "qw3er4ty5u"
    "as9df8gh7j" "pl2ok3ij4u" "zx0cv1bn2m" "qw8er9ty0u"
    "jk5lm6np7q" "rt2yu3io4p" "fg6hj7kl8z" "bn3mc4vx5z"
)

DGA_TLDS=("tk" "ml" "ga" "cf" "gq" "xyz" "top" "club" "online" "site")

# Known blocked/ad domains (for blocklist testing)
BLOCKED_DOMAINS=(
    "ads.google.com" "pagead2.googlesyndication.com"
    "ad.doubleclick.net" "googleadservices.com"
    "facebook-tracking.com" "pixel.facebook.com"
    "analytics.google.com" "www.google-analytics.com"
    "telemetry.microsoft.com" "vortex.data.microsoft.com"
    "tracking.analytics.com" "metrics.icloud.com"
)

# DNS Query Types
QUERY_TYPES=("A" "AAAA" "MX" "TXT" "CNAME" "NS" "SOA" "PTR" "SRV" "CAA")

#===============================================================================
# Utility Functions
#===============================================================================

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local color="${COLORS[NC]}"

    case $level in
        INFO)  color="${COLORS[BLUE]}" ;;
        OK)    color="${COLORS[GREEN]}" ;;
        WARN)  color="${COLORS[YELLOW]}" ;;
        ERROR) color="${COLORS[RED]}" ;;
        DGA)   color="${COLORS[MAGENTA]}" ;;
        BLOCK) color="${COLORS[CYAN]}" ;;
    esac

    if $VERBOSE; then
        echo -e "${color}[${level}]${COLORS[NC]} ${message}"
    fi

    echo "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"
}

get_random_element() {
    local arr=("$@")
    echo "${arr[$RANDOM % ${#arr[@]}]}"
}

get_random_float() {
    local min=$1
    local max=$2
    awk -v min="$min" -v max="$max" 'BEGIN{srand(); printf "%.2f", min+rand()*(max-min)}'
}

generate_dga_domain() {
    local length=$((RANDOM % 8 + 8))  # 8-15 characters
    local chars="abcdefghijklmnopqrstuvwxyz0123456789"
    local domain=""

    for ((i=0; i<length; i++)); do
        domain+="${chars:RANDOM % ${#chars}:1}"
    done

    local tld=$(get_random_element "${DGA_TLDS[@]}")
    echo "${domain}.${tld}"
}

#===============================================================================
# DNS Query Functions
#===============================================================================

dns_query() {
    local domain=$1
    local qtype=${2:-A}
    local start_time=$(date +%s%N)

    local result
    result=$(dig @${DNS_SERVER} ${domain} ${qtype} +short +time=2 +tries=1 2>/dev/null)
    local status=$?
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))  # milliseconds

    ((STATS[total]++))

    if [ $status -eq 0 ]; then
        if [ -z "$result" ] || [[ "$result" == *"NXDOMAIN"* ]] || [[ "$result" == *"SERVFAIL"* ]]; then
            ((STATS[blocked]++))
            log "BLOCK" "${qtype} ${domain} - ${duration}ms"
        else
            ((STATS[success]++))
            log "OK" "${qtype} ${domain} - ${duration}ms"
        fi
    else
        ((STATS[failed]++))
        log "ERROR" "${qtype} ${domain} - FAILED"
    fi
}

#===============================================================================
# Traffic Pattern Generators
#===============================================================================

generate_normal_traffic() {
    local count=${1:-$DEFAULT_COUNT}
    log "INFO" "Generating normal traffic (${count} queries)"

    for ((i=1; i<=count; i++)); do
        local rand=$((RANDOM % 100))
        local domain qtype

        # Distribution: 50% popular, 25% business, 15% tech, 10% cdn
        if [ $rand -lt 50 ]; then
            domain=$(get_random_element "${POPULAR_DOMAINS[@]}")
        elif [ $rand -lt 75 ]; then
            domain=$(get_random_element "${BUSINESS_DOMAINS[@]}")
        elif [ $rand -lt 90 ]; then
            domain=$(get_random_element "${TECH_DOMAINS[@]}")
        else
            domain=$(get_random_element "${CDN_DOMAINS[@]}")
        fi

        # Query type distribution: 75% A, 15% AAAA, 10% other
        rand=$((RANDOM % 100))
        if [ $rand -lt 75 ]; then
            qtype="A"
        elif [ $rand -lt 90 ]; then
            qtype="AAAA"
        else
            qtype=$(get_random_element "${QUERY_TYPES[@]}")
        fi

        dns_query "$domain" "$qtype"
        sleep $(get_random_float 0.5 2.0)
    done
}

generate_suspicious_traffic() {
    local count=${1:-$DEFAULT_COUNT}
    log "INFO" "Generating suspicious traffic (${count} queries)"

    for ((i=1; i<=count; i++)); do
        local rand=$((RANDOM % 100))
        local domain

        # Distribution: 60% suspicious, 40% DGA
        if [ $rand -lt 60 ]; then
            domain=$(get_random_element "${SUSPICIOUS_DOMAINS[@]}")
        else
            domain=$(generate_dga_domain)
            ((STATS[dga]++))
        fi

        dns_query "$domain" "A"
        sleep $(get_random_float 0.3 1.5)
    done
}

generate_dga_traffic() {
    local count=${1:-$DEFAULT_COUNT}
    log "INFO" "Generating DGA traffic (${count} queries)"

    for ((i=1; i<=count; i++)); do
        local domain

        # 70% random generated, 30% from patterns
        if [ $((RANDOM % 100)) -lt 70 ]; then
            domain=$(generate_dga_domain)
        else
            local pattern=$(get_random_element "${DGA_PATTERNS[@]}")
            local tld=$(get_random_element "${DGA_TLDS[@]}")
            domain="${pattern}.${tld}"
        fi

        ((STATS[dga]++))
        dns_query "$domain" "A"
        sleep $(get_random_float 0.1 0.8)
    done
}

generate_blocked_traffic() {
    local count=${1:-$DEFAULT_COUNT}
    log "INFO" "Generating blocked domain traffic (${count} queries)"

    for ((i=1; i<=count; i++)); do
        local domain=$(get_random_element "${BLOCKED_DOMAINS[@]}")
        dns_query "$domain" "A"
        sleep $(get_random_float 0.5 1.5)
    done
}

generate_burst_traffic() {
    local count=${1:-$DEFAULT_COUNT}
    log "INFO" "Generating burst traffic (${count} queries)"

    local domains=("${POPULAR_DOMAINS[@]}" "${CDN_DOMAINS[@]}")

    for ((i=1; i<=count; i++)); do
        local domain=$(get_random_element "${domains[@]}")
        dns_query "$domain" "A"
        sleep 0.05  # Very fast - burst
    done
}

generate_cdn_traffic() {
    local count=${1:-$DEFAULT_COUNT}
    log "INFO" "Generating CDN traffic (${count} queries)"

    for ((i=1; i<=count; i++)); do
        local domain=$(get_random_element "${CDN_DOMAINS[@]}")
        local qtype=$(get_random_element "A" "AAAA" "CNAME")
        dns_query "$domain" "$qtype"
        sleep $(get_random_float 0.1 0.5)
    done
}

generate_mixed_traffic() {
    local duration=${1:-$DEFAULT_DURATION}
    local end_time=$(($(date +%s) + duration))

    log "INFO" "Generating mixed traffic for ${duration} seconds"

    while [ $(date +%s) -lt $end_time ]; do
        local rand=$((RANDOM % 100))

        # Weighted distribution of traffic types
        if [ $rand -lt 45 ]; then
            # Normal traffic (45%)
            generate_normal_traffic 5
        elif [ $rand -lt 65 ]; then
            # CDN traffic (20%)
            generate_cdn_traffic 3
        elif [ $rand -lt 80 ]; then
            # Burst traffic (15%)
            generate_burst_traffic 10
        elif [ $rand -lt 92 ]; then
            # Suspicious traffic (12%)
            generate_suspicious_traffic 3
        elif [ $rand -lt 97 ]; then
            # DGA traffic (5%)
            generate_dga_traffic 2
        else
            # Blocked traffic (3%)
            generate_blocked_traffic 2
        fi

        sleep $(get_random_float 1.0 3.0)
    done
}

generate_continuous_traffic() {
    log "INFO" "Starting continuous traffic generation (Ctrl+C to stop)"

    # Save PID for control script
    echo $$ > "${PID_FILE}"

    trap 'log "INFO" "Stopping continuous simulation"; rm -f "${PID_FILE}"; exit 0' SIGINT SIGTERM

    while true; do
        generate_mixed_traffic 300  # 5-minute cycles
        sleep 5
    done
}

#===============================================================================
# Statistics and Reporting
#===============================================================================

print_stats() {
    echo ""
    echo -e "${COLORS[CYAN]}========================================${COLORS[NC]}"
    echo -e "${COLORS[CYAN]}  DNS Simulator Statistics${COLORS[NC]}"
    echo -e "${COLORS[CYAN]}========================================${COLORS[NC]}"
    echo ""
    echo -e "Total Queries:    ${COLORS[BLUE]}${STATS[total]}${COLORS[NC]}"
    echo -e "Successful:       ${COLORS[GREEN]}${STATS[success]}${COLORS[NC]}"
    echo -e "Failed:           ${COLORS[RED]}${STATS[failed]}${COLORS[NC]}"
    echo -e "Blocked:          ${COLORS[YELLOW]}${STATS[blocked]}${COLORS[NC]}"
    echo -e "DGA Domains:      ${COLORS[MAGENTA]}${STATS[dga]}${COLORS[NC]}"
    echo ""

    # Save stats to JSON
    cat > "${STATS_FILE}" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "total": ${STATS[total]},
    "success": ${STATS[success]},
    "failed": ${STATS[failed]},
    "blocked": ${STATS[blocked]},
    "dga": ${STATS[dga]},
    "dns_server": "${DNS_SERVER}"
}
EOF
}

#===============================================================================
# Main
#===============================================================================

print_banner() {
    echo -e "${COLORS[CYAN]}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║           DNS Threat Simulator v1.0.0                     ║"
    echo "║           Professional DNS Traffic Testing                ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${COLORS[NC]}"
}

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -p, --pattern PATTERN    Traffic pattern (default: mixed)"
    echo "  -c, --count COUNT        Number of queries (default: 100)"
    echo "  -d, --duration SECONDS   Duration for timed patterns (default: 60)"
    echo "  -s, --server IP          Target DNS server (default: 10.50.0.30)"
    echo "  -v, --verbose            Verbose output"
    echo "  -h, --help               Show this help"
    echo ""
    echo "Patterns:"
    echo "  normal       Normal/legitimate traffic"
    echo "  suspicious   Suspicious/phishing domains"
    echo "  dga          DGA-like domains"
    echo "  blocked      Known blocked domains"
    echo "  burst        High-frequency burst traffic"
    echo "  cdn          CDN and static content"
    echo "  mixed        Combination of all patterns"
    echo "  continuous   Run continuously (Ctrl+C to stop)"
    echo ""
    echo "Examples:"
    echo "  $0 -p normal -c 100"
    echo "  $0 -p mixed -d 300"
    echo "  $0 -p dga -c 50 -v"
    echo "  $0 -p continuous -s 10.50.0.30"
}

main() {
    local pattern="mixed"
    local count=$DEFAULT_COUNT
    local duration=$DEFAULT_DURATION

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--pattern)
                pattern="$2"
                shift 2
                ;;
            -c|--count)
                count="$2"
                shift 2
                ;;
            -d|--duration)
                duration="$2"
                shift 2
                ;;
            -s|--server)
                DNS_SERVER="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done

    print_banner

    # Create log directory
    mkdir -p "${LOG_DIR}"

    echo -e "Target DNS Server: ${COLORS[BLUE]}${DNS_SERVER}${COLORS[NC]}"
    echo -e "Pattern: ${COLORS[YELLOW]}${pattern}${COLORS[NC]}"
    echo -e "Log File: ${COLORS[CYAN]}${LOG_FILE}${COLORS[NC]}"
    echo ""

    # Check dig command
    if ! command -v dig &> /dev/null; then
        echo -e "${COLORS[RED]}[ERROR]${COLORS[NC]} 'dig' command not found."
        echo "Install with: sudo yum install bind-utils (RHEL) or sudo apt install dnsutils (Debian)"
        exit 1
    fi

    # Run selected pattern
    case $pattern in
        normal)
            generate_normal_traffic $count
            ;;
        suspicious)
            generate_suspicious_traffic $count
            ;;
        dga)
            generate_dga_traffic $count
            ;;
        blocked)
            generate_blocked_traffic $count
            ;;
        burst)
            generate_burst_traffic $count
            ;;
        cdn)
            generate_cdn_traffic $count
            ;;
        mixed)
            generate_mixed_traffic $duration
            ;;
        continuous)
            generate_continuous_traffic
            ;;
        *)
            echo -e "${COLORS[RED]}[ERROR]${COLORS[NC]} Unknown pattern: $pattern"
            print_usage
            exit 1
            ;;
    esac

    print_stats
}

main "$@"

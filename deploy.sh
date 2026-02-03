#!/bin/bash
#===============================================================================
# DNS Threat Simulator - Deployment Script
# Deploys Python-based simulator to multiple servers with unique profiles
#
# Author: E2E Solutions
# Version: 2.0.0
#===============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIMULATOR_SCRIPT="${SCRIPT_DIR}/dns_simulator.py"

# Server configuration with unique profiles
declare -A SERVER_PROFILES=(
    ["10.50.0.108"]="enterprise"    # Heavy normal traffic
    ["10.50.0.109"]="infected"      # High DGA/suspicious traffic
    ["10.50.0.110"]="developer"     # Mixed developer traffic
)

DNS_SERVER="${DNS_SERVER:-10.50.0.30}"
SSH_USER="${SSH_USER:-tempu}"
SSH_OPTIONS="-o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    local level=$1
    shift
    local color=$NC
    case $level in
        INFO)  color=$BLUE ;;
        OK)    color=$GREEN ;;
        WARN)  color=$YELLOW ;;
        ERROR) color=$RED ;;
    esac
    echo -e "${color}[${level}]${NC} $*"
}

print_header() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║      DNS Threat Simulator - Deployment Tool v2.0          ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

ssh_exec() {
    local server=$1
    shift
    ssh ${SSH_OPTIONS} ${SSH_USER}@${server} "$@" 2>/dev/null
}

scp_file() {
    local src=$1
    local server=$2
    local dest=$3
    scp ${SSH_OPTIONS} -q "$src" ${SSH_USER}@${server}:"$dest" 2>/dev/null
}

test_connection() {
    local server=$1
    if ssh_exec "$server" "echo 'OK'" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

deploy_to_server() {
    local server=$1
    local profile=${SERVER_PROFILES[$server]:-"mixed"}

    log "INFO" "Deploying to ${server} (profile: ${profile})..."

    if ! test_connection "$server"; then
        log "ERROR" "Cannot connect to ${server}"
        return 1
    fi

    # Copy simulator script
    scp_file "$SIMULATOR_SCRIPT" "$server" "/tmp/dns_simulator.py"

    # Setup environment
    ssh_exec "$server" "
        chmod +x /tmp/dns_simulator.py
        mkdir -p /tmp/dns-simulator-logs

        # Check Python3
        if ! command -v python3 &>/dev/null; then
            echo 'Installing Python3...'
            sudo yum install -y python3 2>/dev/null || sudo apt-get install -y python3 2>/dev/null
        fi

        # Check dig
        if ! command -v dig &>/dev/null; then
            echo 'Installing bind-utils...'
            sudo yum install -y bind-utils 2>/dev/null || sudo apt-get install -y dnsutils 2>/dev/null
        fi
    "

    log "OK" "Deployed to ${server}"
    return 0
}

start_on_server() {
    local server=$1
    local profile=${SERVER_PROFILES[$server]:-"mixed"}

    log "INFO" "Starting simulator on ${server} (profile: ${profile})..."

    ssh_exec "$server" "
        # Stop existing
        pkill -f 'dns_simulator.py' 2>/dev/null || true
        sleep 1

        # Start simulator in background
        nohup python3 /tmp/dns_simulator.py -s ${DNS_SERVER} -p ${profile} > /tmp/dns-simulator-logs/simulator.log 2>&1 &
        echo \$! > /tmp/dns-simulator.pid
        sleep 2

        # Verify
        if ps -p \$(cat /tmp/dns-simulator.pid 2>/dev/null) > /dev/null 2>&1; then
            echo 'STARTED'
        else
            echo 'FAILED'
            cat /tmp/dns-simulator-logs/simulator.log 2>/dev/null | tail -20
        fi
    "

    log "OK" "Started on ${server}"
}

stop_on_server() {
    local server=$1

    log "INFO" "Stopping simulator on ${server}..."

    ssh_exec "$server" "
        if [ -f /tmp/dns-simulator.pid ]; then
            pid=\$(cat /tmp/dns-simulator.pid)
            kill \$pid 2>/dev/null || true
            rm -f /tmp/dns-simulator.pid
        fi
        pkill -f 'dns_simulator.py' 2>/dev/null || true
    "

    log "OK" "Stopped on ${server}"
}

check_status() {
    local server=$1
    local profile=${SERVER_PROFILES[$server]:-"unknown"}

    if ! test_connection "$server"; then
        echo -e "${RED}[X]${NC} ${server}: UNREACHABLE"
        return
    fi

    local status
    status=$(ssh_exec "$server" "
        if [ -f /tmp/dns-simulator.pid ] && ps -p \$(cat /tmp/dns-simulator.pid 2>/dev/null) > /dev/null 2>&1; then
            echo 'RUNNING'
        else
            echo 'STOPPED'
        fi
    ")

    if [ "$status" = "RUNNING" ]; then
        echo -e "${GREEN}[*]${NC} ${server}: RUNNING (profile: ${profile})"
    else
        echo -e "${YELLOW}[-]${NC} ${server}: STOPPED"
    fi
}

get_logs() {
    local server=$1
    local lines=${2:-20}

    echo -e "${BLUE}[LOG]${NC} Last ${lines} lines from ${server}:"
    echo "----------------------------------------"
    ssh_exec "$server" "tail -${lines} /tmp/dns-simulator-logs/simulator.log 2>/dev/null || echo 'No logs found'"
    echo "----------------------------------------"
}

deploy_all() {
    print_header
    log "INFO" "Deploying simulator to all servers..."
    echo ""

    for server in "${!SERVER_PROFILES[@]}"; do
        deploy_to_server "$server"
    done

    echo ""
    log "OK" "Deployment complete!"
    echo ""
    echo "Server profiles:"
    for server in "${!SERVER_PROFILES[@]}"; do
        echo "  - ${server}: ${SERVER_PROFILES[$server]}"
    done
    echo ""
    echo "Next: $0 start"
}

start_all() {
    print_header
    log "INFO" "Starting simulators on all servers..."
    echo ""

    for server in "${!SERVER_PROFILES[@]}"; do
        start_on_server "$server"
    done

    echo ""
    log "OK" "All simulators started!"
    echo ""
    echo "Traffic profiles:"
    for server in "${!SERVER_PROFILES[@]}"; do
        echo "  - ${server}: ${SERVER_PROFILES[$server]}"
    done
    echo ""
    echo "DNS Server: ${DNS_SERVER}"
}

stop_all() {
    print_header
    log "INFO" "Stopping simulators on all servers..."
    echo ""

    for server in "${!SERVER_PROFILES[@]}"; do
        stop_on_server "$server"
    done

    echo ""
    log "OK" "All simulators stopped!"
}

status_all() {
    print_header
    log "INFO" "Checking simulator status..."
    echo ""

    for server in "${!SERVER_PROFILES[@]}"; do
        check_status "$server"
    done
    echo ""
}

logs_all() {
    print_header
    for server in "${!SERVER_PROFILES[@]}"; do
        get_logs "$server" 15
        echo ""
    done
}

restart_all() {
    stop_all
    sleep 2
    start_all
}

print_usage() {
    echo "Usage: $0 COMMAND"
    echo ""
    echo "Commands:"
    echo "  deploy     Deploy simulator to all servers"
    echo "  start      Start simulators on all servers"
    echo "  stop       Stop simulators on all servers"
    echo "  restart    Restart all simulators"
    echo "  status     Check status of all simulators"
    echo "  logs       View logs from all servers"
    echo ""
    echo "Server Profiles:"
    echo "  10.50.0.108: enterprise  (heavy normal, CDN traffic)"
    echo "  10.50.0.109: infected    (high DGA, suspicious traffic)"
    echo "  10.50.0.110: developer   (mixed, varied traffic)"
    echo ""
    echo "Environment Variables:"
    echo "  DNS_SERVER    Target DNS server (default: 10.50.0.30)"
    echo "  SSH_USER      SSH user (default: tempu)"
}

main() {
    local command="${1:-help}"

    case $command in
        deploy)  deploy_all ;;
        start)   start_all ;;
        stop)    stop_all ;;
        restart) restart_all ;;
        status)  status_all ;;
        logs)    logs_all ;;
        -h|--help|help) print_header; print_usage ;;
        *)
            log "ERROR" "Unknown command: $command"
            print_usage
            exit 1
            ;;
    esac
}

main "$@"

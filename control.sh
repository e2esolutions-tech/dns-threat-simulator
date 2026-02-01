#!/bin/bash
#===============================================================================
# DNS Threat Simulator - Multi-Server Control Script
# Manages simulators across multiple client servers
#
# Author: E2E Solutions
# Version: 1.0.0
#===============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/servers.conf"
SIMULATOR_SCRIPT="${SCRIPT_DIR}/simulator.sh"

# Default configuration
DNS_SERVER="${DNS_SERVER:-10.50.0.30}"
SSH_USER="${SSH_USER:-tempu}"
SSH_OPTIONS="-o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no"

# Colors
declare -A COLORS=(
    [RED]='\033[0;31m'
    [GREEN]='\033[0;32m'
    [YELLOW]='\033[1;33m'
    [BLUE]='\033[0;34m'
    [CYAN]='\033[0;36m'
    [NC]='\033[0m'
)

# Server configuration
declare -A SERVER_PATTERNS=(
    ["10.50.0.108"]="heavy_normal"
    ["10.50.0.109"]="mixed_suspicious"
    ["10.50.0.110"]="burst_cdn"
)

#===============================================================================
# Utility Functions
#===============================================================================

print_header() {
    echo -e "${COLORS[CYAN]}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║         DNS Threat Simulator - Control Panel              ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${COLORS[NC]}"
}

log() {
    local level=$1
    shift
    local message="$*"
    local color="${COLORS[NC]}"

    case $level in
        INFO)   color="${COLORS[BLUE]}" ;;
        OK)     color="${COLORS[GREEN]}" ;;
        WARN)   color="${COLORS[YELLOW]}" ;;
        ERROR)  color="${COLORS[RED]}" ;;
    esac

    echo -e "${color}[${level}]${COLORS[NC]} ${message}"
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

#===============================================================================
# Server Management Functions
#===============================================================================

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

    log "INFO" "Deploying to ${server}..."

    if ! test_connection "$server"; then
        log "ERROR" "Cannot connect to ${server}"
        return 1
    fi

    # Copy simulator script
    scp_file "$SIMULATOR_SCRIPT" "$server" "/tmp/dns-simulator.sh"

    # Setup environment
    ssh_exec "$server" "
        chmod +x /tmp/dns-simulator.sh
        mkdir -p /tmp/dns-simulator-logs
        command -v dig &>/dev/null || {
            sudo yum install -y bind-utils 2>/dev/null || \
            sudo apt-get install -y dnsutils 2>/dev/null
        }
    "

    log "OK" "Deployed to ${server}"
    return 0
}

get_pattern_script() {
    local pattern=$1

    case $pattern in
        "heavy_normal")
            cat << 'EOF'
while true; do
    /tmp/dns-simulator.sh -p normal -c 50 -s DNS_SERVER
    sleep 5
    /tmp/dns-simulator.sh -p cdn -c 20 -s DNS_SERVER
    sleep 10
done
EOF
            ;;
        "mixed_suspicious")
            cat << 'EOF'
while true; do
    /tmp/dns-simulator.sh -p normal -c 30 -s DNS_SERVER
    sleep 3
    /tmp/dns-simulator.sh -p suspicious -c 10 -s DNS_SERVER
    sleep 5
    /tmp/dns-simulator.sh -p dga -c 5 -s DNS_SERVER
    sleep 5
    /tmp/dns-simulator.sh -p blocked -c 5 -s DNS_SERVER
    sleep 10
done
EOF
            ;;
        "burst_cdn")
            cat << 'EOF'
while true; do
    /tmp/dns-simulator.sh -p burst -c 100 -s DNS_SERVER
    sleep 30
    /tmp/dns-simulator.sh -p cdn -c 50 -s DNS_SERVER
    sleep 20
    /tmp/dns-simulator.sh -p normal -c 20 -s DNS_SERVER
    sleep 60
done
EOF
            ;;
        *)
            cat << 'EOF'
while true; do
    /tmp/dns-simulator.sh -p mixed -d 120 -s DNS_SERVER
    sleep 10
done
EOF
            ;;
    esac
}

start_on_server() {
    local server=$1
    local pattern=${SERVER_PATTERNS[$server]:-"mixed"}

    log "INFO" "Starting simulator on ${server} (pattern: ${pattern})..."

    # Generate runner script
    local runner_script=$(get_pattern_script "$pattern" | sed "s/DNS_SERVER/${DNS_SERVER}/g")

    ssh_exec "$server" "
        # Stop existing if running
        pkill -f 'dns-simulator' 2>/dev/null || true
        pkill -f 'dns-runner' 2>/dev/null || true
        sleep 1

        # Create runner script
        cat > /tmp/dns-runner.sh << 'RUNNER_EOF'
#!/bin/bash
${runner_script}
RUNNER_EOF
        chmod +x /tmp/dns-runner.sh

        # Start in background
        nohup /tmp/dns-runner.sh > /tmp/dns-simulator-logs/runner.log 2>&1 &
        echo \$! > /tmp/dns-simulator.pid
        sleep 2

        # Verify started
        if ps -p \$(cat /tmp/dns-simulator.pid 2>/dev/null) > /dev/null 2>&1; then
            echo 'STARTED'
        else
            echo 'FAILED'
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
            pkill -P \$pid 2>/dev/null || true
            kill \$pid 2>/dev/null || true
            rm -f /tmp/dns-simulator.pid
        fi
        pkill -f 'dns-simulator' 2>/dev/null || true
        pkill -f 'dns-runner' 2>/dev/null || true
    "

    log "OK" "Stopped on ${server}"
}

check_status() {
    local server=$1

    if ! test_connection "$server"; then
        echo -e "${COLORS[RED]}[X]${COLORS[NC]} ${server}: UNREACHABLE"
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

    local pattern=${SERVER_PATTERNS[$server]:-"unknown"}

    if [ "$status" = "RUNNING" ]; then
        echo -e "${COLORS[GREEN]}[*]${COLORS[NC]} ${server}: RUNNING (pattern: ${pattern})"
    else
        echo -e "${COLORS[YELLOW]}[-]${COLORS[NC]} ${server}: STOPPED"
    fi
}

get_logs() {
    local server=$1
    local lines=${2:-20}

    echo -e "${COLORS[BLUE]}[LOG]${COLORS[NC]} Last ${lines} lines from ${server}:"
    echo "----------------------------------------"
    ssh_exec "$server" "tail -${lines} /tmp/dns-simulator-logs/runner.log 2>/dev/null || echo 'No logs found'"
    echo "----------------------------------------"
    echo ""
}

get_stats() {
    local server=$1

    echo -e "${COLORS[CYAN]}[STATS]${COLORS[NC]} Statistics from ${server}:"
    ssh_exec "$server" "cat /tmp/dns-simulator-logs/stats.json 2>/dev/null || echo '{\"error\": \"No stats available\"}'"
    echo ""
}

#===============================================================================
# Batch Operations
#===============================================================================

deploy_all() {
    print_header
    log "INFO" "Deploying simulator to all servers..."
    echo ""

    for server in "${!SERVER_PATTERNS[@]}"; do
        deploy_to_server "$server"
    done

    echo ""
    log "OK" "Deployment complete!"
    echo ""
    echo "Next steps:"
    echo "  $0 start    - Start simulators on all servers"
    echo "  $0 status   - Check status"
}

start_all() {
    print_header
    log "INFO" "Starting simulators on all servers..."
    echo ""

    for server in "${!SERVER_PATTERNS[@]}"; do
        start_on_server "$server"
    done

    echo ""
    log "OK" "All simulators started!"
    echo ""
    echo "Traffic patterns:"
    for server in "${!SERVER_PATTERNS[@]}"; do
        echo "  - ${server}: ${SERVER_PATTERNS[$server]}"
    done
    echo ""
    echo "DNS Server: ${DNS_SERVER}"
}

stop_all() {
    print_header
    log "INFO" "Stopping simulators on all servers..."
    echo ""

    for server in "${!SERVER_PATTERNS[@]}"; do
        stop_on_server "$server"
    done

    echo ""
    log "OK" "All simulators stopped!"
}

status_all() {
    print_header
    log "INFO" "Checking simulator status..."
    echo ""

    for server in "${!SERVER_PATTERNS[@]}"; do
        check_status "$server"
    done

    echo ""
}

logs_all() {
    print_header

    for server in "${!SERVER_PATTERNS[@]}"; do
        get_logs "$server" 10
    done
}

stats_all() {
    print_header
    log "INFO" "Collecting statistics..."
    echo ""

    for server in "${!SERVER_PATTERNS[@]}"; do
        get_stats "$server"
    done
}

restart_all() {
    print_header
    log "INFO" "Restarting all simulators..."
    echo ""

    for server in "${!SERVER_PATTERNS[@]}"; do
        stop_on_server "$server"
    done

    sleep 2

    for server in "${!SERVER_PATTERNS[@]}"; do
        start_on_server "$server"
    done

    echo ""
    log "OK" "All simulators restarted!"
}

#===============================================================================
# Main
#===============================================================================

print_usage() {
    echo "Usage: $0 COMMAND [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  deploy       Deploy simulator to all servers"
    echo "  start        Start simulators on all servers"
    echo "  stop         Stop simulators on all servers"
    echo "  restart      Restart all simulators"
    echo "  status       Check status of all simulators"
    echo "  logs         View logs from all servers"
    echo "  stats        View statistics from all servers"
    echo ""
    echo "Options:"
    echo "  -s, --server IP    Target specific server"
    echo "  -h, --help         Show this help"
    echo ""
    echo "Environment Variables:"
    echo "  DNS_SERVER    Target DNS server (default: 10.50.0.30)"
    echo "  SSH_USER      SSH user (default: tempu)"
    echo ""
    echo "Examples:"
    echo "  $0 deploy"
    echo "  $0 start"
    echo "  $0 status"
    echo "  $0 logs -s 10.50.0.108"
}

main() {
    local command="${1:-help}"
    shift 2>/dev/null || true

    case $command in
        deploy)
            deploy_all
            ;;
        start)
            start_all
            ;;
        stop)
            stop_all
            ;;
        restart)
            restart_all
            ;;
        status)
            status_all
            ;;
        logs)
            logs_all
            ;;
        stats)
            stats_all
            ;;
        -h|--help|help)
            print_header
            print_usage
            ;;
        *)
            log "ERROR" "Unknown command: $command"
            print_usage
            exit 1
            ;;
    esac
}

main "$@"

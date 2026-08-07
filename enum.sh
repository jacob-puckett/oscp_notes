#!/usr/bin/env bash

set -euo pipefail

# ============================================================
# Usage
# ============================================================

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <network_or_ip> <lab_name> [options]"
    echo
    echo "Options:"
    echo "  --udp              Run UDP top ports scan"
    echo "  --udp-top <num>    Number of UDP top ports (default: 20)"
    echo "  --web              Run web enumeration"
    echo "  --smb              Run SMB enumeration"
    echo "  --snmp             Run SNMP enumeration"
    echo "  -j, --jobs <num>   Parallel jobs (default: 5)"
    echo "  -v, --verbose      Verbose output"
    echo
    exit 1
fi

network="$1"
lab_name="$2"

shift 2 || true

# ============================================================
# Defaults
# ============================================================

max_jobs=5
udp_top_ports=20
verbose=false

do_udp=false
do_web=false
do_smb=false
do_snmp=false

# ============================================================
# Arguments
# ============================================================

while [[ $# -gt 0 ]]; do
    case "$1" in

        --udp)
            do_udp=true
            ;;

        --web)
            do_web=true
            ;;

        --smb)
            do_smb=true
            ;;

        --snmp)
            do_snmp=true
            ;;

        -j|--jobs)
            if [[ $# -lt 2 ]]; then
                echo "[!] --jobs requires a value"
                exit 1
            fi

            max_jobs="$2"
            shift
            ;;

        --udp-top)
            if [[ $# -lt 2 ]]; then
                echo "[!] --udp-top requires a value"
                exit 1
            fi

            udp_top_ports="$2"
            shift
            ;;

        -v|--verbose)
            verbose=true
            ;;

        *)
            echo "[!] Unknown option: $1"
            exit 1
            ;;
    esac

    shift
done

# ============================================================
# Logging
# ============================================================

log() {
    echo "[*] $*"
}

success() {
    echo "[+] $*"
}

warn() {
    echo "[!] $*" >&2
}

# ============================================================
# Tool Checks
# ============================================================

check_tool() {
    command -v "$1" >/dev/null 2>&1
}

require_tool() {

    local tool="$1"

    if ! check_tool "$tool"; then
        warn "Required tool not found: $tool"
        exit 1
    fi
}

log "Checking dependencies..."

require_tool nmap
require_tool awk
require_tool grep
require_tool xargs

if [[ "$do_smb" == true ]]; then
    require_tool nxc
fi

if [[ "$do_snmp" == true ]]; then
    require_tool snmpwalk
fi

if [[ "$do_web" == true ]]; then

    if ! check_tool whatweb; then
        warn "whatweb not found. Technology fingerprinting will be skipped."
    fi

    if ! check_tool feroxbuster; then
        warn "feroxbuster not found. Directory enumeration will be skipped."
    fi

fi

success "Dependency check complete."

# ============================================================
# Lab Directory
# ============================================================

mkdir -p "$lab_name"/{scans,loot,bin}

cd "$lab_name"

BIN="bin"

# ============================================================
# Helper Tool Setup
# ============================================================

cat > tools.sh <<'EOF'
#!/usr/bin/env bash

set -euo pipefail

BIN="bin"

mkdir -p "$BIN"

echo "[*] Tool stash: $BIN"

# ============================================================
# Copy helper files if installed locally
# ============================================================

copy_if_exists() {

    local src="$1"
    local dst="$2"

    if [[ -f "$src" ]]; then

        cp -f "$src" "$dst"

        chmod +x "$dst" 2>/dev/null || true

        echo "[+] Copied $(basename "$src")"

    else

        echo "[-] Missing: $src"

    fi
}

# ============================================================
# Common Kali Resources
# ============================================================

echo "[*] Checking common Kali resources..."

copy_if_exists \
    "/usr/share/windows-resources/binaries/nc.exe" \
    "$BIN/nc.exe"

if [[ -d "/usr/share/seclists" ]]; then

    ln -sfn /usr/share/seclists "$BIN/seclists"

    echo "[+] Linked SecLists"

else

    echo "[-] SecLists not found at /usr/share/seclists"

fi

# ============================================================
# Chisel
# ============================================================

download_chisel() {

    local chisel_url
    local archive

    chisel_url="https://github.com/jpillora/chisel/releases/download/v1.11.5/chisel_1.11.5_windows_amd64.zip"

    archive="$BIN/chisel_windows_amd64.zip"

    if ! command -v curl >/dev/null 2>&1; then
        echo "[-] curl not installed. Skipping chisel download."
        return
    fi

    if ! command -v unzip >/dev/null 2>&1; then
        echo "[-] unzip not installed. Skipping chisel download."
        return
    fi

    echo "[*] Downloading chisel..."

    if curl -fL -o "$archive" "$chisel_url"; then

        unzip -o "$archive" -d "$BIN" >/dev/null

        chmod +x "$BIN/chisel.exe" 2>/dev/null || true

        rm -f "$archive"

        echo "[+] Downloaded chisel.exe"

    else

        echo "[-] Chisel download failed."

        rm -f "$archive"
    fi
}

download_chisel

echo
echo "[+] Tool setup complete."
echo "[+] Tool directory: $BIN"

ls -lah "$BIN"

EOF

chmod +x tools.sh

./tools.sh

# ============================================================
# DiskShadow Helper
# ============================================================

cat > "$BIN/ine.txt" <<'DSHADOW'
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias ine
create
expose %ine% E:
end backup
DSHADOW

success "Created $BIN/ine.txt"

# ============================================================
# Host Discovery
# ============================================================

log "Discovering live hosts..."

tmp_discovery="$(mktemp)"

trap 'rm -f "$tmp_discovery"' EXIT

{

    # Standard ping discovery
    nmap \
        -sn \
        -T4 \
        "$network" \
        -oG - \
        2>/dev/null |
        awk '/Status: Up/{print $2}'

    # TCP-based discovery for hosts blocking ICMP
    nmap \
        -sn \
        -n \
        -T4 \
        -PS21,22,80,135,139,443,445,3389,5985,8080 \
        -PA80,443,445 \
        "$network" \
        -oG - \
        2>/dev/null |
        awk '/Status: Up/{print $2}'

    # Always include a directly specified IPv4 host
    if [[ "$network" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "$network"
    fi

} | sort -u > "$tmp_discovery"

if [[ ! -s "$tmp_discovery" ]]; then

    warn "No hosts discovered."
    warn "Check VPN connectivity or network range."

    exit 1
fi

cp "$tmp_discovery" scans/hosts.txt

log "Hosts found:"

cat scans/hosts.txt

# ============================================================
# Host Enumeration
# ============================================================

scan_host() {

    local host="$1"

    local host_id
    local outdir
    local ports
    local web_ports
    local port
    local proto
    local url
    local scan_report
    local hostname
    local clean_name

    host_id="$(echo "$host" | awk -F. '{print $4}')"

    outdir="scans/$host_id"

    mkdir -p "$outdir"

    log "Scanning $host"

    # --------------------------------------------------------
    # Full TCP Scan
    # --------------------------------------------------------

    nmap \
        -Pn \
        -n \
        -p- \
        --min-rate 5000 \
        --max-retries 2 \
        -T4 \
        "$host" \
        -oN "$outdir/full_tcp.txt" \
        >/dev/null 2>&1 || true

    ports="$(
        grep -E '^[0-9]+/tcp[[:space:]]+open' \
            "$outdir/full_tcp.txt" \
            2>/dev/null |
        cut -d '/' -f1 |
        tr '\n' ',' |
        sed 's/,$//'
    )"

    # --------------------------------------------------------
    # Service Enumeration
    # --------------------------------------------------------

    if [[ -n "$ports" ]]; then

        log "$host open TCP ports: $ports"

        nmap \
            -Pn \
            -n \
            -sC \
            -sV \
            -p "$ports" \
            "$host" \
            -oN "$outdir/services.txt" \
            >/dev/null 2>&1 || true

        # ----------------------------------------------------
        # Hostname Detection
        # ----------------------------------------------------

        scan_report="$(
            grep -m1 \
                'Nmap scan report for' \
                "$outdir/services.txt" \
                2>/dev/null || true
        )"

        hostname=""

        if echo "$scan_report" | grep -q '('; then

            hostname="$(
                echo "$scan_report" |
                awk '{print $5}' |
                cut -d '.' -f1
            )"

        fi

        if [[ -n "$hostname" && "$hostname" != "$host" ]]; then

            clean_name="$(
                echo "$hostname" |
                tr '[:upper:]' '[:lower:]' |
                tr -cd 'a-z0-9._-'
            )"

            if [[ -n "$clean_name" &&
                  "$clean_name" != "192" &&
                  ! -e "scans/$clean_name" ]]; then

                mv "$outdir" "scans/$clean_name"

                outdir="scans/$clean_name"

            fi
        fi

    else

        warn "No TCP ports found on $host"

        touch "$outdir/services.txt"

    fi

    # --------------------------------------------------------
    # UDP Enumeration
    # --------------------------------------------------------

    if [[ "$do_udp" == true ]]; then

        log "UDP scan on $host"

        nmap \
            -Pn \
            -n \
            -sU \
            --top-ports "$udp_top_ports" \
            "$host" \
            -oN "$outdir/udp.txt" \
            >/dev/null 2>&1 || true

    fi

    # --------------------------------------------------------
    # SMB Enumeration
    # --------------------------------------------------------

    if [[ "$do_smb" == true ]]; then

        if grep -qE \
            '^(139|445)/tcp[[:space:]]+open' \
            "$outdir/services.txt" \
            2>/dev/null; then

            log "SMB enumeration on $host"

            nxc smb "$host" \
                > "$outdir/smb_basic.txt" \
                2>/dev/null || true

            nxc smb "$host" \
                -u '' \
                -p '' \
                --shares \
                > "$outdir/smb_null_shares.txt" \
                2>/dev/null || true

            nxc smb "$host" \
                -u guest \
                -p '' \
                --shares \
                > "$outdir/smb_guest_shares.txt" \
                2>/dev/null || true

        fi
    fi

    # --------------------------------------------------------
    # SNMP Enumeration
    # --------------------------------------------------------

    if [[ "$do_snmp" == true ]]; then

        log "SNMP enumeration on $host"

        snmpwalk \
            -v2c \
            -c public \
            "$host" \
            > "$outdir/snmp_public.txt" \
            2>/dev/null || true

    fi

    # --------------------------------------------------------
    # Web Enumeration
    # --------------------------------------------------------

    if [[ "$do_web" == true ]]; then

        web_ports="$(
            grep -E \
                '^[0-9]+/tcp[[:space:]]+open' \
                "$outdir/services.txt" \
                2>/dev/null |
            grep -Ei \
                'http|ssl|apache|nginx|iis|http-proxy|jetty|tomcat|gunicorn|werkzeug' |
            cut -d '/' -f1 |
            sort -u || true
        )"

        # Fall back to common web ports
        if [[ -z "$web_ports" ]]; then

            web_ports="$(
                grep -E \
                    '^(80|443|5000|8000|8008|8080|8081|8443|8888|9090|10000)/tcp[[:space:]]+open' \
                    "$outdir/services.txt" \
                    2>/dev/null |
                cut -d '/' -f1 |
                sort -u || true
            )"

        fi

        for port in $web_ports; do

            proto="http"

            if [[ "$port" == "443" ||
                  "$port" == "8443" ||
                  "$port" == "5986" ]]; then

                proto="https"

            fi

            url="$proto://$host:$port"

            log "Web enumeration on $url"

            # Technology fingerprinting
            if command -v whatweb >/dev/null 2>&1; then

                whatweb "$url" \
                    > "$outdir/whatweb_${port}.txt" \
                    2>/dev/null || true

            fi

            # Directory/content enumeration
            if command -v feroxbuster >/dev/null 2>&1; then

                feroxbuster \
                    -u "$url" \
                    -k \
                    -q \
                    -o "$outdir/ferox_${port}.txt" \
                    >/dev/null 2>&1 || true

            fi

        done
    fi

    log "Finished $host"
}

# ============================================================
# Export for parallel execution
# ============================================================

export -f scan_host
export -f log
export -f warn

export do_udp
export do_web
export do_smb
export do_snmp
export udp_top_ports
export verbose

# ============================================================
# Parallel Enumeration
# ============================================================

log "Starting enumeration with $max_jobs parallel jobs..."

xargs \
    -r \
    -a scans/hosts.txt \
    -I{} \
    -P "$max_jobs" \
    bash -c 'scan_host "$1"' _ {}

log "Done."

log "Results saved in: $(pwd)/scans"

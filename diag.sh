#!/bin/bash
# Quick health-check: is every service bound, does every endpoint answer,
# is the Python ↔ Go ↔ browser path intact. Run on the box where the
# stack lives (or over an SSH session). Output is terse and copy-paste
# friendly when something's broken.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { printf "${GREEN}  ok${NC}  %s\n" "$1"; }
warn() { printf "${YELLOW} warn${NC}  %s\n" "$1"; }
bad()  { printf "${RED} FAIL${NC}  %s\n" "$1"; }
head() { printf "\n${BOLD}== %s ==${NC}\n" "$1"; }

head "Listening sockets"
for port in 8000 8085 8091 8092 3128 3129; do
    pid_comm="$(ss -tlnp 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p {print $NF}' | sed -E 's/.*pid=([0-9]+),.*/\1/' | head -1)"
    if [ -n "$pid_comm" ]; then
        comm="$(ps -p "$pid_comm" -o comm= 2>/dev/null | awk '{print $1}')"
        ok "$port  pid=$pid_comm comm=${comm:-?}"
    else
        # on macOS/Alpine ss may not support -p; fall back to lsof
        lsof_line="$(lsof -iTCP:${port} -sTCP:LISTEN -nP 2>/dev/null | tail -n +2 | head -1)"
        if [ -n "$lsof_line" ]; then
            ok "$port  $(echo "$lsof_line" | awk '{print $1" pid="$2}')"
        else
            bad "$port  nothing bound"
        fi
    fi
done

head "Process tree"
for pat in 'backend\.run' '/\.local/mitm-proxies' 'headless_shell' 'playwright'; do
    count="$(pgrep -af "$pat" 2>/dev/null | wc -l | tr -d ' ')"
    if [ "$count" -gt 0 ]; then
        ok "$pat  ($count process(es))"
        pgrep -af "$pat" 2>/dev/null | sed 's/^/        /' | head -3
    else
        warn "$pat  not running"
    fi
done

head "HTTP endpoints (local loopback)"
probe() {  # probe <label> <url> <expected_substring>
    local label="$1" url="$2" needle="$3"
    local body
    body="$(curl -s --max-time 3 "$url" 2>/dev/null)"
    local rc=$?
    if [ $rc -ne 0 ] || [ -z "$body" ]; then
        bad "$label  ($url) — no response (curl rc=$rc)"
        return 1
    fi
    if [ -n "$needle" ] && ! echo "$body" | grep -q "$needle"; then
        warn "$label  ($url) — responded but missing expected body content '$needle'"
        return 1
    fi
    ok "$label  ($url)"
}

probe ":8091 health"    "http://127.0.0.1:8091/health"        "healthy"
probe ":8092 health"    "http://127.0.0.1:8092/health"        ""
probe ":8092 metrics"   "http://127.0.0.1:8092/api/metrics"   '"bus"'
probe ":8000 health"    "http://127.0.0.1:8000/health"        ""
probe ":8085 root"      "http://127.0.0.1:8085/"              ""

head "Proxy smoke tests"
probe "auth proxy :3128 plain-HTTP" "$(curl -s -x http://127.0.0.1:3128 -o /dev/null -w '%{http_code}' --max-time 5 http://example.com 2>/dev/null)" "200" >/dev/null
if curl -s -x http://127.0.0.1:3128 -o /dev/null --max-time 5 http://example.com 2>/dev/null | head -c1 >/dev/null; then
    code="$(curl -s -x http://127.0.0.1:3128 -o /dev/null -w '%{http_code}' --max-time 5 http://example.com 2>/dev/null)"
    [ "$code" = "200" ] && ok "auth proxy :3128 plain-HTTP (200 OK)" || warn "auth proxy :3128 plain-HTTP returned $code"
else
    bad "auth proxy :3128 plain-HTTP — connection failed"
fi
code="$(curl -sk -x http://127.0.0.1:3128 -o /dev/null -w '%{http_code}' --max-time 10 https://example.com 2>/dev/null)"
[ "$code" = "200" ] && ok "auth proxy :3128 HTTPS via MITM (200 OK)" || bad "auth proxy :3128 HTTPS returned $code (client CA not trusted is OK; connection failure is not)"
code="$(curl -sk -x http://127.0.0.1:3129 -o /dev/null -w '%{http_code}' --max-time 5 https://example.com 2>/dev/null)"
[ "$code" = "200" ] && ok "test proxy :3129 HTTPS (200 OK)" || bad "test proxy :3129 HTTPS returned $code"

head "Uvicorn recent errors"
# Look for crashes or tracebacks that would leave endpoints dark.
if [ -f /var/log/mitm-proxy.log ]; then
    tail -50 /var/log/mitm-proxy.log | grep -iE 'error|exception|traceback|fail' | tail -5 || ok "no recent errors in /var/log/mitm-proxy.log"
else
    warn "no /var/log/mitm-proxy.log — check journalctl -u mitm-proxy if you run via systemd, or the terminal that spawned run-local.sh"
fi

head "Quick client-path verification"
echo "If the above is all green but your browser still can't reach the page,"
echo "the break is between your browser and this box. Likely:"
echo "  - SSH tunnels died — on your laptop:  lsof -iTCP:8092 -sTCP:LISTEN | grep ssh"
echo "  - nginx down — on the box:  systemctl status nginx --no-pager | head -10"
echo "  - browser cached a broken dashboard — hard-reload (Cmd+Shift+R / Ctrl+F5)"

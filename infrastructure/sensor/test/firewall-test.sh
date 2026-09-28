#!/usr/bin/env bash
# Functional test of the sensor firewall, using two throwaway containers:
#   "sensor"   Ubuntu 24.04 with the real ruleset applied
#   "attacker" probes it from the same Docker network
# Checks: 22 reaches the honeypot port, the admin port is open, other ports are
# closed, and the sensor cannot open new outbound connections.
#
#   bash infrastructure/sensor/test/firewall-test.sh
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
net=sensor-fw-test
admin_port=45022
fail=0

cleanup() { docker rm -f fw-sensor fw-attacker >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create "$net" >/dev/null

check() { # name, expected (ok|blocked), command...
  local name=$1 want=$2; shift 2
  if "$@" >/dev/null 2>&1; then got=ok; else got=blocked; fi
  if [[ $got == "$want" ]]; then echo "PASS  $name ($got)"; else echo "FAIL  $name (expected $want, got $got)"; fail=1; fi
}

echo "starting containers..."
docker run -d --name fw-sensor --network "$net" --cap-add NET_ADMIN \
  -v "$here:/sensor:ro" ubuntu:24.04 sleep infinity >/dev/null
docker run -d --name fw-attacker --network "$net" curlimages/curl:latest sleep infinity >/dev/null

docker exec fw-sensor bash -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -yqq nftables curl python3 >/dev/null'
# Stand-in listeners: "honeypot" on 2222, "admin sshd" on the admin port, an unrelated service on 8080.
for port in 2222 "$admin_port" 8080; do
  docker exec -d fw-sensor python3 -m http.server "$port"
done
sleep 2

check "sensor egress before firewall (sanity)" ok docker exec fw-sensor curl -s --max-time 5 -o /dev/null http://1.1.1.1

docker exec fw-sensor bash -c "bash /sensor/render-nftables.sh $admin_port '192.0.2.1' > /tmp/rules.nft && nft -c -f /tmp/rules.nft && nft -f /tmp/rules.nft"
echo "ruleset applied"

check "attacker -> 22 redirected to honeypot" ok     docker exec fw-attacker curl -sf --max-time 5 -o /dev/null http://fw-sensor:22/
check "attacker -> admin port"               ok     docker exec fw-attacker curl -sf --max-time 5 -o /dev/null "http://fw-sensor:$admin_port/"
check "attacker -> 8080 (not allowed)"       blocked docker exec fw-attacker curl -sf --max-time 5 -o /dev/null http://fw-sensor:8080/
check "sensor -> internet by IP"             blocked docker exec fw-sensor curl -s --max-time 5 -o /dev/null http://1.1.1.1
check "sensor -> attacker (new connection)"  blocked docker exec fw-sensor curl -s --max-time 5 -o /dev/null http://fw-attacker:80/

# Maintenance window rules (the same ones egress-window adds) open and close egress.
docker exec fw-sensor nft add rule inet sensor maintenance 'tcp dport { 80, 443 } accept'
check "sensor -> internet during maintenance" ok     docker exec fw-sensor curl -s --max-time 5 -o /dev/null http://1.1.1.1
docker exec fw-sensor nft flush chain inet sensor maintenance
check "sensor -> internet after maintenance"  blocked docker exec fw-sensor curl -s --max-time 5 -o /dev/null http://1.1.1.1

exit $fail

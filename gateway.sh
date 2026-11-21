#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
case "${1:-}" in
  preflight) shift; exec python3 -B ./preflight.py "$@" ;;
  version)
    if [ "$#" -eq 1 ]; then exec sed -n '1p' VERSION; fi
    shift; exec python3 -B ./deployment_version.py "$@" ;;
  upgrade|rollback|upgrade-status) exec python3 -B ./upgrade.py "$@" ;;
  pairing) shift; exec python3 -B ./pairing.py "$@" ;;
esac
compose() { python3 -B ./upgrade.py compose "$@"; }
security_services() {
  # Keep missing core services in the check, and include running optional ones.
  # Discovery failures must not silently reduce coverage to the core topology.
  running="$(compose ps --services --status running)" || return 1
  set -f
  for service in $running; do
    case "$service" in
      [!a-zA-Z0-9]*|*[!a-zA-Z0-9_.-]*) echo "Invalid service name in security inventory" >&2; return 1 ;;
    esac
  done
  printf '%s\n' gateway ingress tor-a tor-b $running | LC_ALL=C sort -u
}
[ -f .env ] && [ ! -L .env ] || { echo "Copy .env.example to .env and set LAN_IP to this host's private IPv4 address." >&2; exit 1; }
case "${1:-}" in
  up)
    [ ! -e .arkpool-upgrade/active.json ] || { echo "A managed image pin exists; use upgrade, not up." >&2; exit 1; }
    compose config --quiet
    compose build --pull --no-cache --build-arg "SOURCE_VERSION=$(sed -n '1p' VERSION)" \
      --build-arg "SOURCE_REVISION=$(python3 -B ./deployment_version.py --build-revision)" gateway
    compose run --rm --no-deps gateway python3 /app/gateway.py check-config
    compose up -d --wait --wait-timeout 660
    if ! compose port ingress 3333 >/dev/null; then
      echo "LAN port was not published. If upgrading an older alpha, run 'docker compose down' (without -v) to recreate its network, then retry './gateway.sh up'." >&2
      exit 1
    fi
    echo "ArkPool Gateway ready. Point the miner at your configured LAN_IP:LAN_PORT, username=your complete Ark receive address, password=x."
    if python3 -c 'from pathlib import Path; from preflight import read_settings; raise SystemExit(read_settings(Path(".env"))["TLS_ENABLED"] != "1")'; then
      compose port ingress 3334 >/dev/null || { echo "TLS port was not published; check the TLS Compose overlay." >&2; exit 1; }
      echo "TLS is ready. Run './gateway.sh pairing' and import the file in the miner's Pool page."
    fi
    ;;
  status) compose ps ;;
  telemetry) compose exec -T gateway python3 /app/gateway.py telemetry ;;
  tls-status) compose exec -T ingress python3 /app/ingress.py tls-status ;;
  security-check)
    failed=0
    services="$(security_services)" || exit 1
    for service in $services; do
      echo "$service: checking known package-security minimums"
      # An old image's own checker may still accept superseded package floors.
      if ! compose exec -T "$service" python3 - < ./runtime_packages.py; then
        failed=1
      fi
    done
    exit "$failed"
    ;;
  security-audit)
    failed=0
    checked=''
    services="$(security_services)" || exit 1
    for service in $services; do
      image="$(compose images -q "$service")"
      [ -n "$image" ] || { echo "$service: image unavailable" >&2; failed=1; continue; }
      case " $checked " in *" $image "*) continue ;; esac
      checked="$checked $image"
      echo "$service: auditing disposable image copy against current package indexes"
      if report="$(docker --host unix:///var/run/docker.sock run --rm --interactive --pull never --user 0 \
          --network bridge --cap-drop ALL --security-opt no-new-privileges:true \
          --tmpfs /var/cache/apt:rw,noexec,nosuid,nodev,size=16m \
          --entrypoint sh "$image" -ec \
          'install -d -m 0755 /var/cache/apt/archives/partial && apt-get -o APT::Sandbox::User=root -o APT::Update::Error-Mode=any update >/dev/null && python3 - --check-upgradable' < ./runtime_packages.py)" \
          && printf '%s\n' "$report" | python3 ./runtime_packages.py --validate-report; then
        printf '%s\n' "$report"
      else
        echo "$service: current package status was not verified" >&2
        failed=1
      fi
    done
    exit "$failed"
    ;;
  logs) compose logs --no-color --tail 60 ;;
  stop) compose stop ;;
  restart) compose restart ;;
  *) echo "Usage: ./gateway.sh up|pairing|status|telemetry|tls-status|security-check|security-audit|logs|stop|restart|preflight [--json|--show-lan-cidr]|version|upgrade|rollback|upgrade-status" >&2; exit 2 ;;
esac

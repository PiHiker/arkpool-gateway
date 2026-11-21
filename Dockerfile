FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS tor-repository
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -o APT::Update::Error-Mode=any update && apt-get install -y --no-install-recommends python3 gpg ca-certificates
COPY --chmod=0444 tor_repository.py /prepare-tor-repository.py
RUN python3 /prepare-tor-repository.py /tor-repository

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime-base
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -o APT::Update::Error-Mode=any update && apt-get install -y --no-install-recommends ca-certificates
COPY --from=tor-repository /tor-repository/keyring.gpg /usr/share/keyrings/arkpool-tor-archive.gpg
COPY --from=tor-repository /tor-repository/tor.sources /etc/apt/sources.list.d/arkpool-tor.sources
COPY --from=tor-repository /tor-repository/tor.pref /etc/apt/preferences.d/arkpool-tor
COPY --chmod=0444 runtime_packages.py /app/
RUN apt-get -o APT::Update::Error-Mode=any update && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends tor python3 ca-certificates openssl libpcre2-8-0 && \
    apt-get purge -y mount && \
    test ! -e /usr/bin/mount && test ! -e /usr/bin/umount && \
    python3 /app/runtime_packages.py --check-upgradable && \
    rm -rf /var/lib/apt/lists/* && \
    install -d -o 10001 -g 10001 -m 0700 /var/lib/tor /run/tor-socks /run/arkpool /var/lib/arkpool-tls
WORKDIR /app
RUN python3 /app/runtime_packages.py
COPY --chmod=0444 gateway.py route_quality.py ingress.py tls_identity.py tor_health.py tor_supervisor.py torrc appliance_ui.py bounded_http.py /app/
COPY --chmod=0444 dual_gateway.py v2_config.py translator_runtime.py translator_observer.py dashboard_status.py dashboard.js native_status.py native_relay.py miner_status.py hashrate_history.py protocol.js /app/
RUN chmod 0555 /app && test "$(stat -c '%a' /app)" = 555
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ARG SOURCE_VERSION=unknown
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.version=$SOURCE_VERSION \
      org.opencontainers.image.revision=$SOURCE_REVISION

FROM runtime-base AS test
COPY --chmod=0444 tests.py tests_tls.py tests_dashboard.py tests_native_relay.py tests_native_status.py tests_miner_status.py tests_hashrate_history.py tests_translator.py tests_dual_gateway.py tests_v2_appliance.py /app/
CMD ["python3", "-m", "unittest", "tests", "tests_tls", "tests_dashboard", "tests_native_relay", "tests_native_status", "tests_miner_status", "tests_hashrate_history", "tests_translator", "tests_dual_gateway", "tests_v2_appliance"]

FROM runtime-base AS runtime
CMD ["python3", "/app/gateway.py"]

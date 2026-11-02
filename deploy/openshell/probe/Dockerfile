# The workload image for AEGIS's OpenShell sandboxes (ADR-0017). Built offline from the
# ubuntu:24.04 already present, pinned by digest: `make openshell-image` never pulls.
FROM ubuntu@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

# A dedicated non-root identity with no supplementary groups; the image's own `ubuntu` user
# belongs to sudo and adm.
RUN groupadd --gid 2000 probe \
    && useradd --uid 2000 --gid 2000 --no-create-home --home-dir /sandbox \
        --shell /usr/sbin/nologin probe \
    && printf 'aegis-openshell-probe 1\n' > /etc/aegis-probe-release

USER 2000:2000

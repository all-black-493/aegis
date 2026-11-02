# The workload image for AEGIS's OpenShell sandboxes (ADR-0017). Built offline from the
# ubuntu:24.04 already present, pinned by digest: `make openshell-image` never pulls.
FROM ubuntu@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

# A dedicated non-root identity with no supplementary groups; the image's own `ubuntu` user
# belongs to sudo and adm. The probe directories belong to that identity, so when a probe is
# refused there, Landlock refused it, not Unix permissions (ADR-0018).
RUN groupadd --gid 2000 probe \
    && useradd --uid 2000 --gid 2000 --no-create-home --home-dir /sandbox \
        --shell /usr/sbin/nologin probe \
    && mkdir -p /srv/aegis/readonly /srv/aegis/unlisted \
    && printf 'aegis read-only marker\n' > /srv/aegis/readonly/marker \
    && printf 'aegis unlisted file\n' > /srv/aegis/unlisted/private \
    && chown -R 2000:2000 /srv/aegis \
    && chmod 0700 /srv/aegis/unlisted \
    && printf 'aegis-openshell-probe 2\n' > /etc/aegis-probe-release

USER 2000:2000

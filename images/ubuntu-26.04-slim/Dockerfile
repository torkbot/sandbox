ARG SOURCE_IMAGE
FROM ${SOURCE_IMAGE}

RUN printf '%s\n' \
    'path-exclude=/usr/share/doc/*' \
    'path-include=/usr/share/doc/*/copyright' \
    'path-exclude=/usr/share/man/*' \
    'path-exclude=/usr/share/info/*' \
    'path-exclude=/usr/share/lintian/*' \
    'path-exclude=/usr/share/locale/*' \
    > /etc/dpkg/dpkg.cfg.d/01_sandbox_rootfs_excludes \
  && apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-install-suggests ca-certificates \
  && mkdir -p /dev /proc /run /sandbox /sys /tmp /usr/lib/sandbox /workspace \
  && chmod 1777 /tmp \
  && printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'certificate_path=$1' \
    'install -D -m 0644 "$certificate_path" /usr/local/share/ca-certificates/sandbox-http-interception-ca.crt' \
    'update-ca-certificates' \
    > /usr/lib/sandbox/install-http-ca \
  && chmod 755 /usr/lib/sandbox/install-http-ca \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /root/.cache /tmp/* /var/tmp/* /usr/share/doc /usr/share/man /usr/share/info /usr/share/lintian /usr/share/locale

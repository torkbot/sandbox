ARG SOURCE_IMAGE
FROM ${SOURCE_IMAGE}

RUN apk add --no-cache \
    bash \
    ca-certificates \
    coreutils \
    curl \
    exiftool \
    ffmpeg \
    file \
    findutils \
    git \
    imagemagick \
    jq \
    less \
    nodejs-current \
    npm \
    openssh-client \
    poppler-utils \
    py3-pip \
    python3 \
    ripgrep \
    tar \
    unzip \
    xz \
    zip \
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
  && rm -rf /var/cache/apk/* /etc/apk/cache/* /root/.cache /tmp/* /var/tmp/* /usr/share/doc /usr/share/man /usr/share/info

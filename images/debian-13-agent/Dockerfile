ARG SOURCE_IMAGE
FROM ${SOURCE_IMAGE}

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    coreutils \
    curl \
    ffmpeg \
    file \
    findutils \
    git \
    imagemagick \
    jq \
    less \
    libimage-exiftool-perl \
    nodejs \
    npm \
    openssh-client \
    poppler-utils \
    python3 \
    python3-pip \
    ripgrep \
    tar \
    unzip \
    xz-utils \
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
  && rm -rf /var/lib/apt/lists/* /root/.cache /tmp/* /var/tmp/* /usr/share/doc /usr/share/man /usr/share/info

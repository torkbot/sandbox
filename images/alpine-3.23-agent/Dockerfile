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
  && gh_arch="$(uname -m)" \
  && case "$gh_arch" in x86_64) gh_arch=amd64 ;; aarch64) gh_arch=arm64 ;; *) echo "unsupported gh architecture: $gh_arch" >&2; exit 1 ;; esac \
  && tmp="$(mktemp -d)" \
  && curl -fsSL "https://github.com/cli/cli/releases/download/v2.83.0/gh_2.83.0_linux_${gh_arch}.tar.gz" -o "$tmp/gh.tar.gz" \
  && tar -xzf "$tmp/gh.tar.gz" -C "$tmp" \
  && install -m 0755 "$tmp/gh_2.83.0_linux_${gh_arch}/bin/gh" /usr/local/bin/gh \
  && rm -rf "$tmp" \
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

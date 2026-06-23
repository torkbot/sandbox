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
  && rm -rf /var/lib/apt/lists/* /root/.cache /tmp/* /var/tmp/* /usr/share/doc /usr/share/man /usr/share/info

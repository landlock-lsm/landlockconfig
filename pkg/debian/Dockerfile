# See README.md

FROM debian:trixie

ARG UID=1000
ARG GID=1000

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cargo \
        cargo-c \
        debhelper \
        dpkg-dev \
        fakeroot \
        git \
        lintian \
        pkg-config \
        rustc \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g "${GID}" builder \
    && useradd -m -u "${UID}" -g "${GID}" builder \
    && echo "builder ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER builder
RUN mkdir -p ~/.cargo/registry
WORKDIR /landlockconfig
CMD ["make", "-C", "pkg/debian", "install"]

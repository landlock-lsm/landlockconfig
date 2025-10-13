# See docker-build.sh

FROM archlinux

ARG UID=1000
ARG GID=1000

RUN pacman -Syu --noconfirm \
        binutils \
        cargo-c \
        fakeroot \
        gcc \
        git \
        make \
        pkg-config \
        rust \
        sudo \
        && \
    pacman -Scc --noconfirm && \
    groupadd -g "${GID}" builder && \
    useradd -m -u "${UID}" -g "${GID}" builder && \
    echo "builder ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER builder
RUN mkdir -p ~/.cargo/registry
WORKDIR /landlockconfig
CMD ["make", "-C", "pkg/arch", "install"]

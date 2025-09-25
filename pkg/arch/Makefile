# SPDX-License-Identifier: Apache-2.0 OR MIT

.PHONY: build clean docker

# Build package directly (requires Arch Linux).
build:
	makepkg --force
	sed -i -e 's/^pkgver=.*/pkgver=0/' PKGBUILD

install: build
	sudo pacman -U --noconfirm -- "$$(ls -t landlockconfig-git-*.pkg.tar.zst | head -n 1)"

# Build package using Docker container
# Prerequisites: Install rustup and cargo-c (see .github/workflows/ci.yml)
docker:
	docker buildx build --file Dockerfile \
		--build-arg "UID=$(shell id -u)" \
		--build-arg "GID=$(shell id -g)" \
		--tag landlockconfig-archlinux \
		.
	docker run --rm \
		--volume "$(HOME)/.cargo/registry:/home/builder/.cargo/registry:ro" \
		--volume "$(CURDIR)/../..:/landlockconfig" \
		landlockconfig-archlinux

clean:
	rm landlockconfig-git-*.pkg.tar.zst || :

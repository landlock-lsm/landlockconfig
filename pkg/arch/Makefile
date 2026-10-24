# SPDX-License-Identifier: Apache-2.0 OR MIT

.PHONY: build clean docker

# Build package directly (requires Arch Linux).
build:
	makepkg --force
	sed -i -e 's/^pkgver=.*/pkgver=0/' PKGBUILD

install: build
	sudo pacman -U --noconfirm -- "$$(ls -1t landlock-policy-git-*.pkg.tar.zst | head -n 1)"

# Build package using Docker container
# Prerequisites: Install rustup and cargo-c (see .github/workflows/ci.yml)
docker:
	docker buildx build --file Dockerfile \
		--build-arg "UID=$(shell id -u)" \
		--build-arg "GID=$(shell id -g)" \
		--tag landlock-policy-archlinux \
		.
	# Preserve Git-less builds; mount existing worktree metadata read-only.
	if git_common_dir="$$(cd ../.. && \
		git_dir="$$(git rev-parse --git-common-dir)" && \
		cd "$$git_dir" && pwd)" 2>/dev/null; then \
		set -- --volume "$$git_common_dir:$$git_common_dir:ro"; \
	else \
		set --; \
	fi; \
	docker run --rm \
		--volume "$(HOME)/.cargo/registry:/home/builder/.cargo/registry:ro" \
		--volume "$(CURDIR)/../..:/landlock-policy" \
		"$$@" \
		landlock-policy-archlinux

clean:
	rm landlock-policy-git-*.pkg.tar.zst || :

# SPDX-License-Identifier: Apache-2.0 OR MIT

.PHONY: build install docker clean

# Build packages directly (requires Debian/Ubuntu with build tools).
build:
	dpkg-buildpackage -us -uc --check-command=lintian -b

install: build
	sudo dpkg -i \
		"$$(ls -1t ../liblandlockconfig0_*.deb | head -n 1)" \
		"$$(ls -1t ../liblandlockconfig-dev_*.deb | head -n 1)" \
		"$$(ls -1t ../llconfig_*.deb | head -n 1)"

# Build packages using a Docker container.
docker:
	docker build --file Dockerfile \
		--build-arg "UID=$(shell id -u)" \
		--build-arg "GID=$(shell id -g)" \
		--tag landlockconfig-debian \
		.
	docker run --rm \
		--volume "$(HOME)/.cargo/registry:/home/builder/.cargo/registry" \
		--volume "$(CURDIR)/../..:/landlockconfig" \
		landlockconfig-debian

clean:
	$(RM) -f ../liblandlockconfig0_*.deb ../liblandlockconfig-dev_*.deb \
		../llconfig_*.deb \
		../liblandlockconfig0-dbgsym_*.deb ../llconfig-dbgsym_*.deb \
		../landlockconfig_*.buildinfo ../landlockconfig_*.changes

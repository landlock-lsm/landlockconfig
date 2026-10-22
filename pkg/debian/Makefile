# SPDX-License-Identifier: Apache-2.0 OR MIT

.PHONY: build install docker clean

# Build packages directly (requires Debian/Ubuntu with build tools).
build:
	dpkg-buildpackage -us -uc --check-command=lintian -b

install: build
	sudo dpkg -i \
		"$$(ls -1t ../liblandlock-policy0_*.deb | head -n 1)" \
		"$$(ls -1t ../liblandlock-policy-dev_*.deb | head -n 1)" \
		"$$(ls -1t ../landlock-exec_*.deb | head -n 1)" \
		"$$(ls -1t ../landlock-policy_*.deb | head -n 1)"

# Build packages using a Docker container.
docker:
	docker build --file Dockerfile \
		--build-arg "UID=$(shell id -u)" \
		--build-arg "GID=$(shell id -g)" \
		--tag landlockconfig-debian \
		.
	docker run --rm \
		--volume "$(HOME)/.cargo/registry:/home/builder/.cargo/registry:ro" \
		--volume "$(CURDIR)/../..:/landlockconfig" \
		landlockconfig-debian

clean:
	$(RM) -f ../liblandlock-policy0_*.deb ../liblandlock-policy-dev_*.deb \
		../landlock-exec_*.deb ../landlock-policy_*.deb \
		../liblandlock-policy0-dbgsym_*.deb ../landlock-exec-dbgsym_*.deb \
		../landlock-policy-dbgsym_*.deb ../landlockconfig_*.buildinfo \
		../landlockconfig_*.changes

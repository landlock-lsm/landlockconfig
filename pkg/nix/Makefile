NIX_BUILD = nix-build

.PHONY: landlockconfig llconfig

all: landlockconfig llconfig

landlockconfig:
	$(NIX_BUILD) --attr landlockconfig --out-link $@

llconfig:
	$(NIX_BUILD) --attr llconfig --out-link $@

test:
	$(NIX_BUILD) --no-out-link --attr landlockconfig.tests --attr llconfig.tests

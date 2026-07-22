# SPDX-License-Identifier: Apache-2.0 OR MIT
{
  lib,
  buildFHSEnv,
  llconfig,
  pkgsStatic,
  runCommand,
}:
let
  fhs = buildFHSEnv {
    name = "landlockconfig-test-composition-fhs";
    targetPkgs = _: [ llconfig ];
    runScript = "llconfig run \"$@\" --debug true";
    extraBuildCommands = ''
      mkdir -p $out/var/tmp
      rm -f $out/usr/bin/true
      cp ${pkgsStatic.busybox}/bin/busybox $out/usr/bin/true
    '';
  };
in
runCommand "landlockconfig-test-composition" { } ''
  set -euo pipefail

  composition="${../../tests/composition}"
  cp -r "$composition" ./composition
  chmod -R u+w ./composition

  check() {
    diff -u "$composition/golden-debug.txt" <(${lib.getExe fhs} "$@" 2>&1)
  }

  check --toml composition/source/s1.toml --toml composition/source/s2.toml
  check --toml composition/s.toml
  check --json composition/s.json
  check --toml composition/source/
  check --json composition/source/s1.json --toml composition/source/s2.toml

  touch $out
''

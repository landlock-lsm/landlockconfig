# SPDX-License-Identifier: Apache-2.0 OR MIT
{
  lib,
  rustPlatform,
  versionCheckHook,
  callPackage,
}:
let
  gitInfo = builtins.fetchGit ../..;

  # git log --max-count=1 --format=%cs
  GIT_DATE =
    let
      year = builtins.substring 0 4 gitInfo.lastModifiedDate;
      month = builtins.substring 4 2 gitInfo.lastModifiedDate;
      day = builtins.substring 6 2 gitInfo.lastModifiedDate;
    in
    "${year}-${month}-${day}";

  # git describe --always --abbrev=12 --exclude=* --dirty
  GIT_COMMIT =
    if gitInfo ? dirtyRev then
      builtins.substring 0 12 gitInfo.dirtyRev + "-dirty"
    else
      builtins.substring 0 12 gitInfo.rev;
in
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "llconfig";
  version = "0.0.0";

  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.difference (lib.fileset.gitTracked ../..) ../../pkg;
  };

  cargoLock.lockFile = ../../Cargo.lock;

  nativeInstallCheckInputs = [ versionCheckHook ];
  doInstallCheck = true;

  cargoBuildFlags = [
    "--package=llconfig"
  ];

  env = { inherit GIT_COMMIT GIT_DATE; };

  passthru.tests.composition = callPackage ./composition.nix {
    llconfig = finalAttrs.finalPackage;
  };

  meta = {
    description = "Command-line tool for the Landlock Config format";
    homepage = "https://landlock.io/";
    license = lib.licenses.OR [
      lib.licenses.mit
      lib.licenses.asl20
    ];
    mainProgram = "llconfig";
    platforms = lib.platforms.linux;
  };
})

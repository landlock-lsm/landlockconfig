# SPDX-License-Identifier: Apache-2.0 OR MIT
{
  lib,
  cargo-c,
  validatePkgConfig,
  buildPackages,
  stdenv,
  testers,
  rustPlatform,
}:
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "landlockconfig";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.difference (lib.fileset.gitTracked ../..) ../../pkg;
  };

  cargoLock.lockFile = ../../Cargo.lock;

  nativeBuildInputs = [
    cargo-c
    validatePkgConfig
  ];

  postInstall = ''
    cbuildFlags=(
      --release
      --frozen
      --package landlockconfig_ffi
      --prefix $out
      --target ${stdenv.hostPlatform.rust.rustcTarget}
    )

    ${buildPackages.rust.envVars.setEnv} cargo cbuild "''${cbuildFlags[@]}"
    ${buildPackages.rust.envVars.setEnv} cargo cinstall "''${cbuildFlags[@]}"
  '';

  passthru.tests.pkg-config = testers.hasPkgConfigModules {
    package = finalAttrs.finalPackage;
    versionCheck = true;
  };

  meta = {
    description = "Landlock configuration library";
    homepage = "https://landlock.io/";
    license = lib.licenses.OR [
      lib.licenses.mit
      lib.licenses.asl20
    ];
    pkgConfigModules = [ "landlockconfig" ];
    platforms = lib.platforms.linux;
  };
})

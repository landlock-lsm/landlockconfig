package main

// #cgo CFLAGS: -Wall -Werror -g -I../include
// #cgo LDFLAGS: -L../target/debug -llandlockconfig
// #include "landlockconfig.h"
import "C"

import (
	"log"
	"os"
	"syscall"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

type LandlockConfig struct {
	s *C.struct_landlockconfig
}

func LandlockConfigParseJson(f *os.File) *LandlockConfig {
	return &LandlockConfig{
		C.landlockconfig_parse_json(C.int(f.Fd())),
	}
}

func LandlockConfigParseToml(f *os.File) *LandlockConfig {
	return &LandlockConfig{
		C.landlockconfig_parse_toml(C.int(f.Fd())),
	}
}

func LandlockConfigParseFree(s *LandlockConfig) {
	C.landlockconfig_free(s.s)
}

func LandlockConfigBuildRulseset(s *LandlockConfig) int {
	return int(C.landlockconfig_build_ruleset(s.s))
}

func main() {
	f, err := os.Open("config.toml")
	if err != nil {
		log.Fatalf("failed reading file")
	}
	s := LandlockConfigParseToml(f)
	n := LandlockConfigBuildRulseset(s)
	if err := ll.AllThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		log.Fatal(err)
	}
	if err := ll.AllThreadsLandlockRestrictSelf(n, 0); err != nil {
		log.Fatal(err)
	}
	err = syscall.Exec("/bin/bash", []string{"-i"}, os.Environ())
	if err != nil {
		log.Fatalf("could not execve ct, error: %v", err)
	}
}

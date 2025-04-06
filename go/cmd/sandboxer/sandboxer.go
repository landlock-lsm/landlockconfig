package main

import (
	"log"
	"os"
	"syscall"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"github.com/landlock-lsm/landlockconfig"
	"golang.org/x/sys/unix"
)

func main() {
	// f, err := os.Open("config.toml")
	// if err != nil {
	// 	log.Fatalf("failed reading file")
	// }

	b, err := os.ReadFile("config.toml")
	if err != nil {
		log.Fatalf("failed reading file")
	}
	// s := LandlockConfigParseToml(f)
	s := landlockconfig.LandlockconfigParseTomlBuffer(b)
	n := landlockconfig.LandlockConfigBuildRulseset(s)
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

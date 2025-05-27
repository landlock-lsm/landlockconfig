package landlockconfig

// #cgo CFLAGS: -Wall -Werror -g -I../include
// #cgo LDFLAGS: -L../target/release -llandlockconfig
// #include "landlockconfig.h"
import "C"

import (
	"os"
	"unsafe"
)

type LandlockConfig struct {
	s *C.struct_landlockconfig
}

func LandlockConfigParseJson(f *os.File) *LandlockConfig {
	return &LandlockConfig{
		C.landlockconfig_parse_json_file(C.int(f.Fd()), 0),
	}
}

func LandlockConfigParseToml(f *os.File) *LandlockConfig {
	return &LandlockConfig{
		C.landlockconfig_parse_toml_file(C.int(f.Fd()), 0),
	}
}

func LandlockConfigParseFree(s *LandlockConfig) {
	C.landlockconfig_free(s.s)
}

func LandlockConfigBuildRulseset(s *LandlockConfig) int {
	return int(C.landlockconfig_build_ruleset(s.s, 0))
}

func LandlockconfigParseTomlBuffer(b []byte) *LandlockConfig {
	return &LandlockConfig{C.landlockconfig_parse_toml_buffer((*C.uint8_t)(unsafe.Pointer(&b[0])), C.uintptr_t(len(b)), 0)}
}

func LandlockconfigParseJsonBuffer(b []byte) *LandlockConfig {
	return &LandlockConfig{C.landlockconfig_parse_json_buffer((*C.uint8_t)(unsafe.Pointer(&b[0])), C.uintptr_t(len(b)), 0)}
}
